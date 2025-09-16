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
import asyncio
from datetime import datetime, timedelta

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


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """
    Rate Limiting Middleware
    Integrates with Temporal-based rate limiting system to protect all API endpoints
    """

    def __init__(self, app, config: Dict[str, Any] = None):
        super().__init__(app)
        self.config = config or {}
        self.bypass_paths = {
            "/health", "/docs", "/openapi.json", "/redoc",
            "/temporal-status", "/temporal-ping",
            "/rate-limiting/health"  # Don't rate limit the rate limiting health check
        }

    async def dispatch(self, request: Request, call_next: Callable):
        """Apply rate limiting to incoming requests"""

        # Skip rate limiting for bypass paths
        if request.url.path in self.bypass_paths:
            return await call_next(request)

        # Skip rate limiting for static files
        if any(request.url.path.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.ico']):
            return await call_next(request)

        try:
            # Determine rate limit type based on endpoint
            limit_type = self._determine_limit_type(request)

            # Get client identifier
            client_id = self._get_client_identifier(request)

            # Check rate limit using Temporal workflow
            is_allowed = await self._check_rate_limit(
                request, client_id, limit_type
            )

            if not is_allowed['allowed']:
                # Return rate limit exceeded response
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "rate_limit_exceeded",
                        "error_description": is_allowed.get('blocked_reason', 'Too many requests'),
                        "retry_after": is_allowed.get('retry_after', 60),
                        "limit": is_allowed.get('limit', 0),
                        "remaining": 0,
                        "reset_time": is_allowed.get('reset_time')
                    },
                    headers={
                        "Retry-After": str(is_allowed.get('retry_after', 60)),
                        "X-RateLimit-Limit": str(is_allowed.get('limit', 0)),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": is_allowed.get('reset_time', ''),
                        "X-Rate-Limit-Type": limit_type
                    }
                )

            # Process request normally
            response = await call_next(request)

            # Add rate limit headers to successful responses
            if is_allowed.get('remaining') is not None:
                response.headers["X-RateLimit-Limit"] = str(is_allowed.get('limit', 0))
                response.headers["X-RateLimit-Remaining"] = str(is_allowed.get('remaining', 0))
                response.headers["X-RateLimit-Reset"] = is_allowed.get('reset_time', '')
                response.headers["X-Rate-Limit-Type"] = limit_type

            return response

        except Exception as e:
            logger.error(f"Rate limiting middleware error: {e}")
            # On error, allow request to proceed (fail open)
            return await call_next(request)

    def _determine_limit_type(self, request: Request) -> str:
        """Determine the appropriate rate limit type based on the request"""

        path = request.url.path.lower()
        method = request.method.upper()

        # Authentication endpoints - stricter limits
        if any(auth_path in path for auth_path in ['/auth/', '/oauth/', '/pkce/', '/login', '/token']):
            if 'login' in path or method == 'POST':
                return 'login'
            else:
                return 'api'

        # Registration endpoints - very strict limits
        if any(reg_path in path for reg_path in ['/register', '/signup', '/user/create']):
            return 'registration'

        # MFA endpoints - strict limits
        if any(mfa_path in path for mfa_path in ['/mfa', '/2fa', '/verify']):
            return 'mfa'

        # Admin endpoints - moderate limits but important to protect
        if any(admin_path in path for admin_path in ['/admin', '/dashboard']):
            return 'api'

        # Default to general API limits
        return 'api'

    def _get_client_identifier(self, request: Request) -> str:
        """Get client identifier for rate limiting"""

        # Try to get user ID from token if available
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            try:
                # In a real implementation, decode JWT to get user_id
                # For now, use a simple approach
                token = auth_header.split(' ')[1]
                if len(token) > 10:  # Basic token validation
                    # Use hash of token as identifier to maintain some privacy
                    user_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
                    return f"user_{user_hash}"
            except Exception:
                pass

        # Fall back to IP address
        client_ip = self._get_client_ip(request)
        return f"ip_{client_ip}"

    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address considering proxies"""

        # Check for forwarded headers
        forwarded_headers = ["x-forwarded-for", "x-real-ip", "x-client-ip"]

        for header in forwarded_headers:
            if header in request.headers:
                ip = request.headers[header].split(",")[0].strip()
                if ip:
                    return ip

        # Fallback to direct client IP
        return getattr(request.client, "host", "unknown")

    async def _check_rate_limit(self, request: Request, client_id: str, limit_type: str) -> Dict[str, Any]:
        """Check rate limit using Temporal workflow"""

        try:
            from app.temporal.client import get_temporal_client
            from app.temporal.workflows.rate_limiting_workflow import (
                RateLimitingWorkflow, RateLimitRequest
            )

            # Create rate limit request
            rate_limit_key = f"{limit_type}:{client_id}"

            temporal_request = RateLimitRequest(
                key=rate_limit_key,
                limit_type=limit_type,
                identifier=client_id,
                action=f"{request.method}_{request.url.path}",
                metadata={
                    'user_agent': request.headers.get('user-agent', ''),
                    'referer': request.headers.get('referer', ''),
                    'request_time': datetime.now().isoformat()
                }
            )

            # Execute rate limiting workflow
            client = await get_temporal_client()

            # Use start_workflow instead of execute_workflow for async processing
            workflow_handle = await client.start_workflow(
                RateLimitingWorkflow.run,
                temporal_request,
                id=f"rate_limit_{rate_limit_key}_{int(time.time())}",
                task_queue="guardflow"
            )

            # Wait for result with timeout
            try:
                result = await asyncio.wait_for(workflow_handle.result(), timeout=5.0)
                return result.__dict__ if hasattr(result, '__dict__') else result
            except asyncio.TimeoutError:
                logger.warning(f"Rate limit check timeout for {client_id}")
                # On timeout, allow request (fail open)
                return {
                    'allowed': True,
                    'remaining': 100,
                    'reset_time': (datetime.now() + timedelta(hours=1)).isoformat(),
                    'current_count': 0,
                    'limit': 100,
                    'blocked_reason': 'Rate limiting service timeout - request allowed'
                }

        except Exception as e:
            logger.error(f"Rate limiting check failed: {e}")
            # On error, allow request (fail open policy)
            return {
                'allowed': True,
                'remaining': 100,
                'reset_time': (datetime.now() + timedelta(hours=1)).isoformat(),
                'current_count': 0,
                'limit': 100,
                'blocked_reason': 'Rate limiting service error - request allowed'
            }