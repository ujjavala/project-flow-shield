"""
PKCE OAuth2 Endpoints
OAuth 2.1 compliant PKCE implementation with Temporal workflows
"""
from fastapi import APIRouter, HTTPException, Depends, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_500_INTERNAL_SERVER_ERROR
import temporalio.client as temporal_client
from temporalio.common import RetryPolicy
from datetime import timedelta
import logging
from typing import Dict, Any, Optional
from urllib.parse import urlencode, urlparse

from app.models.pkce import (
    PKCERequest, 
    PKCETokenRequest, 
    PKCEResponse, 
    PKCETokenResponse,
    PKCEError,
    PKCEErrorTypes,
    PKCEUtils
)
from app.temporal.client import get_temporal_client
from app.services.auth_service import get_current_user
from app.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/oauth2/pkce", tags=["PKCE OAuth2"])
security = HTTPBearer(auto_error=False)


@router.get("/authorize", response_model=None)
async def pkce_authorize_get(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str = "S256",
    scope: Optional[str] = "read write",
    state: Optional[str] = None
):
    """
    PKCE Authorization Endpoint (GET)
    OAuth 2.1 compliant authorization endpoint with PKCE support
    """
    try:
        # Validate required parameters
        if response_type != "code":
            error_params = {
                "error": PKCEErrorTypes.UNSUPPORTED_GRANT_TYPE,
                "error_description": "Only 'code' response type is supported",
                "state": state
            }
            return RedirectResponse(
                url=f"{redirect_uri}?{urlencode(error_params)}",
                status_code=302
            )
        
        # Create PKCE request model
        pkce_request = PKCERequest(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            response_type=response_type
        )
        
        # Check if user is authenticated
        authorization = request.headers.get("Authorization")
        if not authorization:
            # Redirect to login with return URL
            login_url = f"/login?return_to={request.url}"
            return RedirectResponse(url=login_url, status_code=302)
        
        # For demo, we'll assume user is authenticated
        # In production, validate the authorization header
        current_user = await get_current_user(authorization.replace("Bearer ", ""))
        if not current_user:
            login_url = f"/login?return_to={request.url}"
            return RedirectResponse(url=login_url, status_code=302)
        
        # Execute PKCE authorization workflow
        client = await get_temporal_client()
        
        workflow_id = f"pkce-auth-{client_id}-{current_user.id}-{temporal_client.uuid4()}"
        
        try:
            result = await client.execute_workflow(
                "PKCEAuthorizationWorkflow",
                args=[pkce_request.dict(), current_user.id],
                id=workflow_id,
                task_queue="oauth2-task-queue",
                execution_timeout=timedelta(minutes=5),
                retry_policy=RetryPolicy(maximum_attempts=2)
            )
            
            if result.get("success"):
                # Successful authorization - redirect with code
                response_params = {
                    "code": result["code"],
                    "state": state
                } if state else {"code": result["code"]}
                
                return RedirectResponse(
                    url=f"{redirect_uri}?{urlencode(response_params)}",
                    status_code=302
                )
            else:
                # Authorization failed - redirect with error
                error_params = {
                    "error": result.get("error", PKCEErrorTypes.INVALID_REQUEST),
                    "error_description": result.get("error_description", "Authorization failed"),
                    "state": state
                }
                return RedirectResponse(
                    url=f"{redirect_uri}?{urlencode(error_params)}",
                    status_code=302
                )
                
        except Exception as temporal_error:
            logger.error(f"Temporal PKCE authorization failed: {str(temporal_error)}")
            # Fallback error response
            error_params = {
                "error": PKCEErrorTypes.INVALID_REQUEST,
                "error_description": "Authorization service temporarily unavailable",
                "state": state
            }
            return RedirectResponse(
                url=f"{redirect_uri}?{urlencode(error_params)}",
                status_code=302
            )
            
    except Exception as e:
        logger.error(f"PKCE authorize endpoint error: {str(e)}")
        error_params = {
            "error": PKCEErrorTypes.INVALID_REQUEST,
            "error_description": "Invalid authorization request",
            "state": state
        }
        return RedirectResponse(
            url=f"{redirect_uri}?{urlencode(error_params)}",
            status_code=302
        )


@router.post("/authorize")
async def pkce_authorize_post(
    pkce_request: PKCERequest,
    current_user: User = Depends(get_current_user)
):
    """
    PKCE Authorization Endpoint (POST)
    Programmatic PKCE authorization for API clients
    """
    try:
        logger.info(f"PKCE authorization request for client {pkce_request.client_id} by user {current_user.id}")
        
        # Execute PKCE authorization workflow
        client = await get_temporal_client()
        
        workflow_id = f"pkce-auth-{pkce_request.client_id}-{current_user.id}-{temporal_client.uuid4()}"
        
        try:
            result = await client.execute_workflow(
                "PKCEAuthorizationWorkflow",
                args=[pkce_request.dict(), current_user.id],
                id=workflow_id,
                task_queue="oauth2-task-queue",
                execution_timeout=timedelta(minutes=5),
                retry_policy=RetryPolicy(maximum_attempts=2)
            )
            
            if result.get("success"):
                return PKCEResponse(
                    code=result["code"],
                    state=pkce_request.state,
                    expires_in=result.get("expires_in", 600)
                )
            else:
                raise HTTPException(
                    status_code=HTTP_400_BAD_REQUEST,
                    detail={
                        "error": result.get("error", PKCEErrorTypes.INVALID_REQUEST),
                        "error_description": result.get("error_description", "Authorization failed")
                    }
                )
                
        except Exception as temporal_error:
            logger.error(f"Temporal PKCE authorization failed: {str(temporal_error)}")
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": PKCEErrorTypes.INVALID_REQUEST,
                    "error_description": "Authorization service temporarily unavailable"
                }
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"PKCE authorize POST endpoint error: {str(e)}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail={
                "error": PKCEErrorTypes.INVALID_REQUEST,
                "error_description": "Invalid authorization request"
            }
        )


@router.post("/token")
async def pkce_token_exchange(token_request: PKCETokenRequest):
    """
    PKCE Token Exchange Endpoint
    Exchange authorization code + code verifier for access tokens
    """
    try:
        logger.info(f"PKCE token exchange request for client {token_request.client_id}")
        
        # Execute PKCE token exchange workflow
        client = await get_temporal_client()
        
        workflow_id = f"pkce-token-{token_request.client_id}-{temporal_client.uuid4()}"
        
        try:
            result = await client.execute_workflow(
                "PKCETokenExchangeWorkflow",
                args=[token_request.dict()],
                id=workflow_id,
                task_queue="oauth2-task-queue",
                execution_timeout=timedelta(minutes=5),
                retry_policy=RetryPolicy(maximum_attempts=2)
            )
            
            if result.get("success"):
                return PKCETokenResponse(
                    access_token=result["access_token"],
                    token_type=result.get("token_type", "Bearer"),
                    expires_in=result.get("expires_in", 1800),
                    refresh_token=result.get("refresh_token"),
                    scope=result.get("scope")
                )
            else:
                raise HTTPException(
                    status_code=HTTP_400_BAD_REQUEST,
                    detail={
                        "error": result.get("error", PKCEErrorTypes.INVALID_GRANT),
                        "error_description": result.get("error_description", "Token exchange failed")
                    }
                )
                
        except Exception as temporal_error:
            logger.error(f"Temporal PKCE token exchange failed: {str(temporal_error)}")
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "error": PKCEErrorTypes.INVALID_REQUEST,
                    "error_description": "Token service temporarily unavailable"
                }
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"PKCE token exchange endpoint error: {str(e)}")
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail={
                "error": PKCEErrorTypes.INVALID_REQUEST,
                "error_description": "Invalid token request"
            }
        )


@router.get("/client-config")
async def get_pkce_client_config(client_id: str):
    """
    Get PKCE client configuration
    Helps clients understand supported features
    """
    try:
        # Demo client configurations
        demo_configs = {
            "demo-client": {
                "client_id": "demo-client",
                "pkce_methods": ["S256", "plain"],
                "recommended_method": "S256",
                "token_endpoint_auth_methods": ["none"],  # Public client
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "redirect_uris": [
                    "http://localhost:3000/callback",
                    "https://yourdomain.com/callback"
                ]
            },
            "mobile-app": {
                "client_id": "mobile-app",
                "pkce_methods": ["S256"],
                "recommended_method": "S256",
                "token_endpoint_auth_methods": ["none"],  # Public client
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "redirect_uris": [
                    "com.yourapp.oauth://callback"
                ]
            }
        }
        
        if client_id not in demo_configs:
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST,
                detail={
                    "error": PKCEErrorTypes.INVALID_CLIENT,
                    "error_description": "Unknown client_id"
                }
            )
        
        return demo_configs[client_id]
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get PKCE client config error: {str(e)}")
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": PKCEErrorTypes.INVALID_REQUEST,
                "error_description": "Configuration service error"
            }
        )


@router.post("/generate-challenge")
async def generate_pkce_challenge(method: str = "S256"):
    """
    Helper endpoint to generate PKCE challenge for testing
    In production, clients should generate this themselves
    """
    try:
        if method not in ["S256", "plain"]:
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST,
                detail={
                    "error": "invalid_request",
                    "error_description": "Code challenge method must be S256 or plain"
                }
            )
        
        code_verifier = PKCEUtils.generate_code_verifier()
        code_challenge = PKCEUtils.generate_code_challenge(code_verifier, method)
        
        return {
            "code_verifier": code_verifier,
            "code_challenge": code_challenge,
            "code_challenge_method": method,
            "note": "Store code_verifier securely - it's needed for token exchange"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Generate PKCE challenge error: {str(e)}")
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "server_error",
                "error_description": "Challenge generation failed"
            }
        )