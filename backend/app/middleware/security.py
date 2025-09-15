"""
Security Middleware
Token theft protection and security headers implementation
"""
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import logging
from typing import Callable, Dict, Any
import time
import hashlib
import secrets

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Security Headers Middleware
    Implements comprehensive security headers including CSP for token theft protection
    """
    
    def __init__(self, app, config: Dict[str, Any] = None):
        super().__init__(app)
        self.config = config or {}
        self.nonce_cache = {}  # In production, use Redis
        
        # Default CSP policy for token theft protection
        self.default_csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self' ws://localhost:3000 wss://localhost:3000 "
            "https://api.temporal.io https://temporal.io; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "upgrade-insecure-requests;"
        )
        
        # Production CSP (stricter)
        self.production_csp = (
            "default-src 'self'; "
            "script-src 'self' 'nonce-{nonce}'; "
            "style-src 'self' 'nonce-{nonce}'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self' https://api.yourdomain.com; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'; "
            "upgrade-insecure-requests; "
            "report-uri /api/csp-report;"
        )

    async def dispatch(self, request: Request, call_next: Callable):
        """Apply security headers to all responses"""
        
        # Generate nonce for this request
        nonce = self._generate_nonce()
        request.state.csp_nonce = nonce
        
        # Process request
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # Apply security headers
        self._apply_security_headers(response, nonce, request)
        
        # Add performance header
        response.headers["X-Process-Time"] = str(process_time)
        
        # Log security-sensitive requests
        if self._is_auth_request(request):
            logger.info(
                f"Auth request: {request.method} {request.url.path} - "
                f"Status: {response.status_code} - Time: {process_time:.3f}s"
            )
        
        return response

    def _apply_security_headers(self, response: Response, nonce: str, request: Request):
        """Apply comprehensive security headers"""
        
        # Content Security Policy - Primary token theft protection
        csp_policy = self._get_csp_policy(nonce, request)
        response.headers["Content-Security-Policy"] = csp_policy
        
        # Additional security headers
        security_headers = {
            # Prevent MIME type sniffing
            "X-Content-Type-Options": "nosniff",
            
            # XSS Protection
            "X-XSS-Protection": "1; mode=block",
            
            # Frame protection
            "X-Frame-Options": "DENY",
            
            # Referrer policy
            "Referrer-Policy": "strict-origin-when-cross-origin",
            
            # HSTS (HTTPS only)
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            
            # Feature Policy / Permissions Policy
            "Permissions-Policy": (
                "geolocation=(), microphone=(), camera=(), "
                "payment=(), usb=(), magnetometer=(), gyroscope=()"
            ),
            
            # Cache control for sensitive endpoints
            "Cache-Control": "no-store, no-cache, must-revalidate, private" 
            if self._is_auth_request(request) else "public, max-age=300",
            
            # Custom security headers
            "X-Security-Policy": "token-theft-protection-enabled",
            "X-Auth-Method": "pkce-oauth2.1"
        }
        
        # Apply headers
        for header, value in security_headers.items():
            response.headers[header] = value

    def _get_csp_policy(self, nonce: str, request: Request) -> str:
        """Get appropriate CSP policy based on environment and request"""
        
        # Check if production environment
        is_production = self.config.get("environment") == "production"
        
        # Use stricter policy for auth endpoints
        if self._is_auth_request(request):
            if is_production:
                return self.production_csp.format(nonce=nonce)
            else:
                # Development policy with nonce for auth endpoints
                return (
                    "default-src 'self'; "
                    f"script-src 'self' 'nonce-{nonce}' 'unsafe-eval'; "
                    f"style-src 'self' 'nonce-{nonce}' 'unsafe-inline'; "
                    "img-src 'self' data: https:; "
                    "connect-src 'self' ws://localhost:* wss://localhost:* "
                    "https://api.temporal.io; "
                    "form-action 'self'; "
                    "base-uri 'self'; "
                    "object-src 'none'; "
                    "frame-ancestors 'none';"
                )
        
        return self.default_csp

    def _generate_nonce(self) -> str:
        """Generate cryptographically secure nonce for CSP"""
        nonce = secrets.token_urlsafe(16)
        
        # Store nonce with timestamp for cleanup
        self.nonce_cache[nonce] = time.time()
        
        # Clean old nonces (keep last 100)
        if len(self.nonce_cache) > 100:
            sorted_nonces = sorted(self.nonce_cache.items(), key=lambda x: x[1])
            for old_nonce, _ in sorted_nonces[:-50]:
                del self.nonce_cache[old_nonce]
        
        return nonce

    def _is_auth_request(self, request: Request) -> bool:
        """Check if request is authentication-related"""
        auth_paths = [
            "/auth/", "/oauth/", "/oauth2/", "/pkce/", "/token", "/login", "/logout"
        ]
        return any(path in str(request.url.path) for path in auth_paths)


class TokenTheftProtectionMiddleware(BaseHTTPMiddleware):
    """
    Token Theft Protection Middleware
    Implements advanced token security measures
    """
    
    def __init__(self, app, config: Dict[str, Any] = None):
        super().__init__(app)
        self.config = config or {}
        self.suspicious_requests = {}  # In production, use Redis

    async def dispatch(self, request: Request, call_next: Callable):
        """Monitor and protect against token theft attempts"""
        
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")
        
        # Check for suspicious patterns
        if self._detect_suspicious_request(request, client_ip, user_agent):
            logger.warning(
                f"Suspicious token request detected from {client_ip}: "
                f"{request.method} {request.url.path}"
            )
            
            # Return security error for suspicious requests
            return JSONResponse(
                status_code=429,
                content={
                    "error": "security_violation",
                    "error_description": "Suspicious request pattern detected"
                },
                headers={
                    "Retry-After": "300",
                    "X-Security-Block": "suspicious-pattern"
                }
            )
        
        # Process request normally
        response = await call_next(request)
        
        # Add token security headers for token endpoints
        if self._is_token_endpoint(request):
            self._add_token_security_headers(response)
        
        return response

    def _detect_suspicious_request(self, request: Request, client_ip: str, user_agent: str) -> bool:
        """Detect suspicious token theft patterns"""
        
        current_time = time.time()
        request_key = f"{client_ip}:{user_agent}"
        
        # Rate limiting for token endpoints
        if self._is_token_endpoint(request):
            if request_key not in self.suspicious_requests:
                self.suspicious_requests[request_key] = []
            
            # Add current request timestamp
            self.suspicious_requests[request_key].append(current_time)
            
            # Keep only requests from last 5 minutes
            recent_requests = [
                t for t in self.suspicious_requests[request_key] 
                if current_time - t < 300
            ]
            self.suspicious_requests[request_key] = recent_requests
            
            # Flag if more than 10 token requests in 5 minutes
            if len(recent_requests) > 10:
                return True
        
        # Check for suspicious headers
        suspicious_headers = [
            "x-forwarded-for", "x-real-ip", "x-client-ip"
        ]
        
        for header in suspicious_headers:
            if header in request.headers:
                # Log potential proxy/forwarding manipulation
                logger.info(f"Forwarded request detected: {header}={request.headers[header]}")
        
        # Check for automation patterns
        automation_patterns = [
            "curl/", "wget/", "python-requests/", "postman", "insomnia"
        ]
        
        if any(pattern in user_agent.lower() for pattern in automation_patterns):
            # Not necessarily suspicious, but worth monitoring
            logger.info(f"API client detected: {user_agent}")
        
        return False

    def _add_token_security_headers(self, response: Response):
        """Add additional security headers for token endpoints"""
        
        token_security_headers = {
            "X-Token-Security": "theft-protection-active",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store, no-cache, must-revalidate, private, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        }
        
        for header, value in token_security_headers.items():
            response.headers[header] = value

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address considering proxies"""
        
        # Check for forwarded headers (in order of preference)
        forwarded_headers = [
            "x-forwarded-for",
            "x-real-ip", 
            "x-client-ip"
        ]
        
        for header in forwarded_headers:
            if header in request.headers:
                # Take first IP if comma-separated
                ip = request.headers[header].split(",")[0].strip()
                if ip:
                    return ip
        
        # Fallback to direct client IP
        return getattr(request.client, "host", "unknown")

    def _is_token_endpoint(self, request: Request) -> bool:
        """Check if request is to a token endpoint"""
        token_paths = ["/token", "/oauth/token", "/oauth2/token", "/pkce/token"]
        return any(path in str(request.url.path) for path in token_paths)


class CSPReportMiddleware(BaseHTTPMiddleware):
    """
    CSP Violation Reporting Middleware
    Collects and logs CSP violations for security monitoring
    """
    
    async def dispatch(self, request: Request, call_next: Callable):
        """Handle CSP violation reports"""
        
        if request.url.path == "/api/csp-report" and request.method == "POST":
            return await self._handle_csp_report(request)
        
        return await call_next(request)

    async def _handle_csp_report(self, request: Request) -> JSONResponse:
        """Process CSP violation report"""
        
        try:
            body = await request.body()
            report_data = body.decode("utf-8")
            
            client_ip = self._get_client_ip(request)
            
            logger.warning(
                f"CSP violation reported from {client_ip}: {report_data}"
            )
            
            # In production, store in security monitoring system
            # This could indicate token theft attempts
            
            return JSONResponse(
                status_code=204,
                content=None
            )
            
        except Exception as e:
            logger.error(f"CSP report processing error: {str(e)}")
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid report"}
            )

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP for CSP reporting"""
        return getattr(request.client, "host", "unknown")