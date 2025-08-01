from fastapi import APIRouter, Depends, HTTPException, status, Query, Form
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from typing import Optional
from urllib.parse import urlencode
from datetime import datetime
import logging

from app.database.connection import get_db
from app.models.user import User
from app.models.oauth import OAuth2Client, OAuth2AuthorizationCode, OAuth2AccessToken
from app.utils.security import verify_password, verify_token, generate_state
from app.temporal.client import get_temporal_client
from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()

# Add missing oauth2_scheme
oauth2_scheme = HTTPBearer()

class AuthorizeRequest(BaseModel):
    response_type: str = "code"
    client_id: str
    redirect_uri: str
    scope: Optional[str] = "read"
    state: Optional[str] = None

class TokenRequest(BaseModel):
    grant_type: str = "authorization_code"
    code: str
    client_id: str
    client_secret: str
    redirect_uri: str

@router.get("/authorize")
async def authorize(
    response_type: str = Query(...),
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    scope: str = Query("read"),
    state: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db)
):
    """OAuth2 authorization endpoint"""
    try:
        # Validate response_type
        if response_type != "code":
            error_params = {
                "error": "unsupported_response_type",
                "error_description": "Only authorization code flow is supported"
            }
            if state:
                error_params["state"] = state
            return RedirectResponse(
                url=f"{redirect_uri}?{urlencode(error_params)}",
                status_code=302
            )
        
        # Validate client
        result = await db.execute(
            select(OAuth2Client).where(
                OAuth2Client.client_id == client_id,
                OAuth2Client.is_active == True
            )
        )
        client = result.scalar_one_or_none()
        
        if not client:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid client_id"
            )
        
        # Validate redirect_uri
        if redirect_uri not in client.redirect_uris:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid redirect_uri"
            )
        
        # Redirect to login page with authorization parameters
        auth_params = {
            "response_type": response_type,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state or generate_state()
        }
        
        login_url = f"{settings.FRONTEND_URL}/oauth/login?{urlencode(auth_params)}"
        return RedirectResponse(url=login_url, status_code=302)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authorization failed: {e}")
        error_params = {
            "error": "server_error",
            "error_description": "Authorization failed"
        }
        if state:
            error_params["state"] = state
        return RedirectResponse(
            url=f"{redirect_uri}?{urlencode(error_params)}",
            status_code=302
        )

@router.post("/authorize")
async def authorize_post(
    response_type: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form("read"),
    state: Optional[str] = Form(None),
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    """Handle OAuth2 authorization with user credentials"""
    try:
        # Validate client
        result = await db.execute(
            select(OAuth2Client).where(
                OAuth2Client.client_id == client_id,
                OAuth2Client.is_active == True
            )
        )
        client = result.scalar_one_or_none()
        
        if not client:
            error_params = {
                "error": "invalid_client",
                "error_description": "Invalid client"
            }
            if state:
                error_params["state"] = state
            return RedirectResponse(
                url=f"{redirect_uri}?{urlencode(error_params)}",
                status_code=302
            )
        
        # Authenticate user
        user_result = await db.execute(select(User).where(User.email == email))
        user = user_result.scalar_one_or_none()
        
        if not user or not verify_password(password, user.hashed_password):
            error_params = {
                "error": "access_denied",
                "error_description": "Invalid credentials"
            }
            if state:
                error_params["state"] = state
            return RedirectResponse(
                url=f"{redirect_uri}?{urlencode(error_params)}",
                status_code=302
            )
        
        if not user.is_active or not user.is_verified:
            error_params = {
                "error": "access_denied",
                "error_description": "Account not active or verified"
            }
            if state:
                error_params["state"] = state
            return RedirectResponse(
                url=f"{redirect_uri}?{urlencode(error_params)}",
                status_code=302
            )
        
        # Generate authorization code using Temporal
        temporal_client = await get_temporal_client()
        
        code_result = await temporal_client.execute_activity(
            "generate_oauth_authorization_code",
            client_id,
            user.id,
            redirect_uri,
            scope,
            state,
            task_queue="oauth2-task-queue"
        )
        
        # Redirect with authorization code
        success_params = {
            "code": code_result["code"]
        }
        if state:
            success_params["state"] = state
            
        return RedirectResponse(
            url=f"{redirect_uri}?{urlencode(success_params)}",
            status_code=302
        )
        
    except Exception as e:
        logger.error(f"Authorization failed: {e}")
        error_params = {
            "error": "server_error",
            "error_description": "Authorization failed"
        }
        if state:
            error_params["state"] = state
        return RedirectResponse(
            url=f"{redirect_uri}?{urlencode(error_params)}",
            status_code=302
        )

@router.post("/token")
async def token(
    grant_type: str = Form(...),
    code: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    redirect_uri: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    """OAuth2 token endpoint"""
    try:
        # Validate grant_type
        if grant_type != "authorization_code":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "unsupported_grant_type",
                    "error_description": "Only authorization code grant is supported"
                }
            )
        
        # Validate client
        result = await db.execute(
            select(OAuth2Client).where(
                OAuth2Client.client_id == client_id,
                OAuth2Client.is_active == True
            )
        )
        client = result.scalar_one_or_none()
        
        if not client or not verify_password(client_secret, client.client_secret):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "invalid_client",
                    "error_description": "Invalid client credentials"
                }
            )
        
        # Exchange authorization code for tokens using Temporal
        temporal_client = await get_temporal_client()
        
        token_result = await temporal_client.execute_activity(
            "exchange_authorization_code",
            code,
            client_id,
            redirect_uri,
            task_queue="oauth2-task-queue"
        )
        
        return token_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token exchange failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "server_error",
                "error_description": "Token exchange failed"
            }
        )

@router.post("/revoke")
async def revoke_token(
    token: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    """OAuth2 token revocation endpoint"""
    try:
        # Validate client
        result = await db.execute(
            select(OAuth2Client).where(
                OAuth2Client.client_id == client_id,
                OAuth2Client.is_active == True
            )
        )
        client = result.scalar_one_or_none()
        
        if not client or not verify_password(client_secret, client.client_secret):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "invalid_client",
                    "error_description": "Invalid client credentials"
                }
            )
        
        # Revoke token using Temporal
        temporal_client = await get_temporal_client()
        
        revoke_result = await temporal_client.execute_activity(
            "revoke_access_token",
            token,
            task_queue="oauth2-task-queue"
        )
        
        return {"message": "Token revoked successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token revocation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "server_error", 
                "error_description": "Token revocation failed"
            }
        )

@router.get("/userinfo")
async def userinfo(
    authorization: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
):
    """OAuth2 userinfo endpoint"""
    try:
        # Extract token from Authorization header
        token = authorization.credentials
        
        # Verify access token
        result = await db.execute(
            select(OAuth2AccessToken).where(
                OAuth2AccessToken.access_token == token,
                OAuth2AccessToken.is_revoked == False
            )
        )
        oauth_token = result.scalar_one_or_none()
        
        if not oauth_token or oauth_token.expires_at < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired access token"
            )
        
        # Get user info
        user = await db.get(User, oauth_token.user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Return user info based on scope
        user_info = {
            "sub": user.id,
            "email": user.email,
            "email_verified": user.is_verified
        }
        
        if "profile" in (oauth_token.scope or ""):
            user_info.update({
                "name": f"{user.first_name or ''} {user.last_name or ''}".strip(),
                "given_name": user.first_name,
                "family_name": user.last_name,
                "preferred_username": user.username,
                "picture": user.profile_picture
            })
        
        return user_info
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Userinfo failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user info"
        )