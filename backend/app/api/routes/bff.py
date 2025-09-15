"""
Backend for Frontend (BFF) Pattern
Token-mediating backend to prevent token theft in SPAs
"""
from fastapi import APIRouter, HTTPException, Depends, Request, Response, Cookie
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
import httpx
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import secrets
import json
from urllib.parse import urlencode

from app.models.user import User
from app.services.auth_service import get_current_user
from app.models.pkce import PKCEUtils

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/bff", tags=["Backend for Frontend"])

# In production, use Redis for session storage
session_store = {}


class BFFSession:
    """BFF Session management for secure token handling"""
    
    @staticmethod
    def create_session(user_id: str, access_token: str, refresh_token: Optional[str] = None) -> str:
        """Create secure session with tokens stored server-side"""
        
        session_id = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(hours=24)
        
        session_data = {
            "session_id": session_id,
            "user_id": user_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": expires_at.isoformat(),
            "last_activity": datetime.utcnow().isoformat()
        }
        
        session_store[session_id] = session_data
        
        logger.info(f"BFF session created for user {user_id}: {session_id[:8]}...")
        return session_id
    
    @staticmethod
    def get_session(session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve session data"""
        
        if session_id not in session_store:
            return None
        
        session_data = session_store[session_id]
        
        # Check expiration
        expires_at = datetime.fromisoformat(session_data["expires_at"])
        if datetime.utcnow() > expires_at:
            BFFSession.destroy_session(session_id)
            return None
        
        # Update last activity
        session_data["last_activity"] = datetime.utcnow().isoformat()
        
        return session_data
    
    @staticmethod
    def update_tokens(session_id: str, access_token: str, refresh_token: Optional[str] = None) -> bool:
        """Update tokens in session"""
        
        if session_id not in session_store:
            return False
        
        session_store[session_id]["access_token"] = access_token
        if refresh_token:
            session_store[session_id]["refresh_token"] = refresh_token
        
        session_store[session_id]["last_activity"] = datetime.utcnow().isoformat()
        
        logger.info(f"BFF session tokens updated: {session_id[:8]}...")
        return True
    
    @staticmethod
    def destroy_session(session_id: str) -> bool:
        """Destroy session and clear tokens"""
        
        if session_id in session_store:
            user_id = session_store[session_id].get("user_id", "unknown")
            del session_store[session_id]
            logger.info(f"BFF session destroyed for user {user_id}: {session_id[:8]}...")
            return True
        
        return False


def get_bff_session(request: Request) -> Optional[Dict[str, Any]]:
    """Get current BFF session from HTTP-only cookie"""
    
    session_id = request.cookies.get("bff_session")
    if not session_id:
        return None
    
    return BFFSession.get_session(session_id)


def require_bff_session(request: Request) -> Dict[str, Any]:
    """Require valid BFF session"""
    
    session = get_bff_session(request)
    if not session:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "unauthorized", 
                "error_description": "Valid session required"
            }
        )
    
    return session


@router.post("/login")
async def bff_login(
    request: Request,
    response: Response,
    email: str,
    password: str
):
    """
    BFF Login - Initiate PKCE flow and establish secure session
    Frontend never sees tokens directly
    """
    try:
        # Generate PKCE parameters
        code_verifier = PKCEUtils.generate_code_verifier()
        code_challenge = PKCEUtils.generate_code_challenge(code_verifier)
        
        # Store PKCE parameters in temporary storage
        temp_id = secrets.token_urlsafe(16)
        session_store[f"pkce_{temp_id}"] = {
            "code_verifier": code_verifier,
            "email": email,
            "password": password,
            "expires_at": (datetime.utcnow() + timedelta(minutes=10)).isoformat()
        }
        
        # Return authorization URL for frontend to redirect to
        auth_params = {
            "response_type": "code",
            "client_id": "demo-client",
            "redirect_uri": "http://localhost:3000/bff-callback",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "scope": "read write",
            "state": temp_id
        }
        
        auth_url = f"/oauth2/pkce/authorize?{urlencode(auth_params)}"
        
        return {
            "success": True,
            "authorization_url": auth_url,
            "temp_id": temp_id,
            "method": "bff_pkce_flow"
        }
        
    except Exception as e:
        logger.error(f"BFF login error: {str(e)}")
        raise HTTPException(
            status_code=400,
            detail={
                "error": "login_failed",
                "error_description": "Authentication initiation failed"
            }
        )


@router.post("/callback")
async def bff_callback(
    request: Request,
    response: Response,
    code: str,
    state: str
):
    """
    BFF Callback - Complete PKCE flow and establish session
    Exchanges authorization code for tokens and stores them securely
    """
    try:
        # Retrieve PKCE parameters
        pkce_key = f"pkce_{state}"
        if pkce_key not in session_store:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_state",
                    "error_description": "Invalid or expired state parameter"
                }
            )
        
        pkce_data = session_store[pkce_key]
        code_verifier = pkce_data["code_verifier"]
        
        # Exchange authorization code for tokens using internal API
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                "http://localhost:8000/oauth2/pkce/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": "http://localhost:3000/bff-callback",
                    "client_id": "demo-client",
                    "code_verifier": code_verifier
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
        
        if token_response.status_code != 200:
            logger.error(f"Token exchange failed: {token_response.text}")
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "token_exchange_failed",
                    "error_description": "Failed to obtain tokens"
                }
            )
        
        token_data = token_response.json()
        access_token = token_data["access_token"]
        refresh_token = token_data.get("refresh_token")
        
        # Get user information using access token
        user_response = await client.get(
            "http://localhost:8000/users/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        if user_response.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "user_info_failed",
                    "error_description": "Failed to retrieve user information"
                }
            )
        
        user_data = user_response.json()
        user_id = user_data["id"]
        
        # Create secure BFF session
        session_id = BFFSession.create_session(user_id, access_token, refresh_token)
        
        # Set HTTP-only secure cookie
        response.set_cookie(
            key="bff_session",
            value=session_id,
            httponly=True,
            secure=True,  # HTTPS only in production
            samesite="strict",
            max_age=86400  # 24 hours
        )
        
        # Generate CSRF token
        csrf_token = secrets.token_urlsafe(32)
        response.set_cookie(
            key="csrf_token",
            value=csrf_token,
            httponly=False,  # Accessible to JavaScript for headers
            secure=True,
            samesite="strict",
            max_age=86400
        )
        
        # Clean up PKCE data
        del session_store[pkce_key]
        
        logger.info(f"BFF session established for user {user_id}")
        
        return {
            "success": True,
            "user": {
                "id": user_data["id"],
                "email": user_data["email"],
                "first_name": user_data.get("first_name"),
                "last_name": user_data.get("last_name")
            },
            "csrf_token": csrf_token,
            "method": "bff_session"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"BFF callback error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "callback_failed",
                "error_description": "Authentication callback failed"
            }
        )


@router.get("/me")
async def bff_get_user(request: Request):
    """Get current user information through BFF"""
    
    session = require_bff_session(request)
    
    try:
        # Use stored access token to get user info
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "http://localhost:8000/users/me",
                headers={"Authorization": f"Bearer {session['access_token']}"}
            )
        
        if response.status_code == 200:
            return response.json()
        
        # Token might be expired, try refresh
        if response.status_code == 401 and session.get("refresh_token"):
            refreshed = await _refresh_tokens(session)
            if refreshed:
                # Retry with new token
                response = await client.get(
                    "http://localhost:8000/users/me",
                    headers={"Authorization": f"Bearer {session['access_token']}"}
                )
                if response.status_code == 200:
                    return response.json()
        
        raise HTTPException(
            status_code=401,
            detail={
                "error": "unauthorized",
                "error_description": "Session expired or invalid"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"BFF get user error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "user_fetch_failed",
                "error_description": "Failed to retrieve user information"
            }
        )


@router.post("/api-proxy")
async def bff_api_proxy(
    request: Request,
    target_path: str,
    method: str = "GET"
):
    """
    BFF API Proxy - Proxy API calls with automatic token handling
    Frontend makes requests to BFF, BFF adds tokens automatically
    """
    
    session = require_bff_session(request)
    csrf_token = request.headers.get("X-CSRF-Token")
    expected_csrf = request.cookies.get("csrf_token")
    
    # CSRF protection
    if not csrf_token or csrf_token != expected_csrf:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "csrf_error",
                "error_description": "Invalid CSRF token"
            }
        )
    
    try:
        # Get request body for POST/PUT requests
        body = None
        if method.upper() in ["POST", "PUT", "PATCH"]:
            body = await request.body()
        
        # Proxy request with stored access token
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=method.upper(),
                url=f"http://localhost:8000{target_path}",
                headers={
                    "Authorization": f"Bearer {session['access_token']}",
                    "Content-Type": request.headers.get("content-type", "application/json")
                },
                content=body
            )
        
        # Handle token refresh if needed
        if response.status_code == 401 and session.get("refresh_token"):
            refreshed = await _refresh_tokens(session)
            if refreshed:
                # Retry with new token
                response = await client.request(
                    method=method.upper(),
                    url=f"http://localhost:8000{target_path}",
                    headers={
                        "Authorization": f"Bearer {session['access_token']}",
                        "Content-Type": request.headers.get("content-type", "application/json")
                    },
                    content=body
                )
        
        # Return proxied response
        return JSONResponse(
            status_code=response.status_code,
            content=response.json() if response.status_code != 204 else None,
            headers=dict(response.headers)
        )
        
    except Exception as e:
        logger.error(f"BFF API proxy error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "proxy_failed",
                "error_description": "API request failed"
            }
        )


@router.post("/logout")
async def bff_logout(request: Request, response: Response):
    """BFF Logout - Destroy session and clear cookies"""
    
    session = get_bff_session(request)
    
    if session:
        # Revoke tokens if possible
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    "http://localhost:8000/auth/logout",
                    headers={"Authorization": f"Bearer {session['access_token']}"}
                )
        except Exception as e:
            logger.warning(f"Token revocation failed: {str(e)}")
        
        # Destroy BFF session
        BFFSession.destroy_session(session["session_id"])
    
    # Clear cookies
    response.delete_cookie("bff_session")
    response.delete_cookie("csrf_token")
    
    return {
        "success": True,
        "message": "Logged out successfully",
        "method": "bff_logout"
    }


@router.get("/session-status")
async def bff_session_status(request: Request):
    """Check BFF session status"""
    
    session = get_bff_session(request)
    
    if not session:
        return {
            "authenticated": False,
            "method": "bff_session_check"
        }
    
    return {
        "authenticated": True,
        "user_id": session["user_id"],
        "created_at": session["created_at"],
        "last_activity": session["last_activity"],
        "method": "bff_session_check"
    }


async def _refresh_tokens(session: Dict[str, Any]) -> bool:
    """Internal function to refresh access tokens"""
    
    if not session.get("refresh_token"):
        return False
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://localhost:8000/auth/refresh",
                headers={"Authorization": f"Bearer {session['refresh_token']}"}
            )
        
        if response.status_code == 200:
            token_data = response.json()
            new_access_token = token_data["access_token"]
            new_refresh_token = token_data.get("refresh_token")
            
            # Update session with new tokens
            BFFSession.update_tokens(
                session["session_id"], 
                new_access_token, 
                new_refresh_token or session["refresh_token"]
            )
            
            # Update local session data
            session["access_token"] = new_access_token
            if new_refresh_token:
                session["refresh_token"] = new_refresh_token
            
            logger.info(f"Tokens refreshed for session {session['session_id'][:8]}...")
            return True
        
        return False
        
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        return False