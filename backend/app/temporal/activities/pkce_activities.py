"""
PKCE Activities
OAuth 2.1 PKCE implementation activities for Temporal workflows
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import temporalio.activity as activity

from app.models.pkce import PKCERequest, PKCEUtils, PKCEAuthorizationCode
from app.database.connection import AsyncSessionLocal
from app.services.jwt_service import create_access_token, create_refresh_token

logger = logging.getLogger(__name__)


@activity.defn(name="validate_pkce_request")
async def validate_pkce_request(pkce_request: PKCERequest) -> Dict[str, Any]:
    """
    Validate PKCE authorization request
    Ensures compliance with RFC 7636 specifications
    """
    try:
        # Validate code challenge format
        if len(pkce_request.code_challenge) < 43 or len(pkce_request.code_challenge) > 128:
            return {
                "valid": False,
                "error_description": "Code challenge must be 43-128 characters"
            }
        
        # Validate code challenge method
        if pkce_request.code_challenge_method not in ["S256", "plain"]:
            return {
                "valid": False,
                "error_description": "Code challenge method must be S256 or plain"
            }
        
        # Recommend S256 over plain for security
        if pkce_request.code_challenge_method == "plain":
            logger.warning(
                f"Client {pkce_request.client_id} using plain code challenge method (not recommended)"
            )
        
        # Validate client_id exists (simplified for demo)
        # In production, check against registered clients
        if not pkce_request.client_id or len(pkce_request.client_id) < 3:
            return {
                "valid": False,
                "error_description": "Invalid client_id"
            }
        
        # Validate redirect URI format
        if not pkce_request.redirect_uri or not (
            pkce_request.redirect_uri.startswith("https://") or 
            pkce_request.redirect_uri.startswith("http://localhost")
        ):
            return {
                "valid": False,
                "error_description": "Invalid redirect_uri format"
            }
        
        # Validate scope (optional)
        if pkce_request.scope:
            valid_scopes = ["read", "write", "admin"]
            requested_scopes = pkce_request.scope.split()
            if not all(scope in valid_scopes for scope in requested_scopes):
                return {
                    "valid": False,
                    "error_description": "Invalid scope requested"
                }
        
        logger.info(
            f"PKCE request validation passed for client {pkce_request.client_id}"
        )
        
        return {"valid": True}
        
    except Exception as e:
        logger.error(f"PKCE request validation error: {str(e)}")
        return {
            "valid": False,
            "error_description": "Request validation failed"
        }


@activity.defn(name="store_pkce_authorization_code")
async def store_pkce_authorization_code(auth_code_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Store PKCE authorization code with challenge parameters
    Includes secure storage with expiration
    """
    try:
        async with AsyncSessionLocal() as db:
            # In production, store in dedicated PKCE table
            # For demo, we'll simulate storage
            stored_codes = getattr(store_pkce_authorization_code, '_codes', {})
            
            code = auth_code_data["code"]
            stored_codes[code] = {
                **auth_code_data,
                "stored_at": datetime.utcnow().isoformat()
            }
            
            # Store in activity function for demo (use Redis/DB in production)
            store_pkce_authorization_code._codes = stored_codes
            
            logger.info(
                f"PKCE authorization code stored: {code[:8]}... for client {auth_code_data['client_id']}"
            )
            
            return {"success": True}
            
    except Exception as e:
        logger.error(f"Failed to store PKCE authorization code: {str(e)}")
        return {
            "success": False,
            "error": str(e)
        }


@activity.defn(name="retrieve_pkce_authorization_code")
async def retrieve_pkce_authorization_code(code: str) -> Dict[str, Any]:
    """
    Retrieve PKCE authorization code with validation
    Checks expiration and usage status
    """
    try:
        stored_codes = getattr(store_pkce_authorization_code, '_codes', {})
        
        if code not in stored_codes:
            logger.warning(f"PKCE authorization code not found: {code[:8]}...")
            return {"found": False}
        
        auth_code_data = stored_codes[code]
        
        # Check expiration
        expires_at = datetime.fromisoformat(auth_code_data["expires_at"])
        if datetime.utcnow() > expires_at:
            logger.warning(f"PKCE authorization code expired: {code[:8]}...")
            # Clean up expired code
            del stored_codes[code]
            return {"found": False}
        
        # Check if already used
        if auth_code_data.get("is_used", False):
            logger.warning(f"PKCE authorization code already used: {code[:8]}...")
            return {"found": False}
        
        logger.info(f"PKCE authorization code retrieved: {code[:8]}...")
        
        return {
            "found": True,
            "auth_code": auth_code_data
        }
        
    except Exception as e:
        logger.error(f"Failed to retrieve PKCE authorization code: {str(e)}")
        return {"found": False, "error": str(e)}


@activity.defn(name="mark_authorization_code_used")
async def mark_authorization_code_used(code: str) -> Dict[str, Any]:
    """
    Mark authorization code as used to prevent replay attacks
    Critical security measure for PKCE flow
    """
    try:
        stored_codes = getattr(store_pkce_authorization_code, '_codes', {})
        
        if code in stored_codes:
            stored_codes[code]["is_used"] = True
            stored_codes[code]["used_at"] = datetime.utcnow().isoformat()
            
            logger.info(f"PKCE authorization code marked as used: {code[:8]}...")
            return {"success": True}
        
        return {"success": False, "error": "Code not found"}
        
    except Exception as e:
        logger.error(f"Failed to mark authorization code as used: {str(e)}")
        return {"success": False, "error": str(e)}


@activity.defn(name="generate_pkce_tokens")
async def generate_pkce_tokens(token_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate access and refresh tokens for PKCE flow
    Includes enhanced security features
    """
    try:
        user_id = token_data["user_id"]
        client_id = token_data["client_id"]
        scope = token_data.get("scope", "read write")
        
        # Generate access token with PKCE context
        access_token_data = {
            "sub": user_id,
            "client_id": client_id,
            "scope": scope,
            "auth_method": "pkce",
            "iat": datetime.utcnow(),
            "jti": PKCEUtils.generate_authorization_code()  # Unique token ID
        }
        
        access_token = create_access_token(access_token_data)
        
        # Generate refresh token
        refresh_token_data = {
            "sub": user_id,
            "client_id": client_id,
            "scope": scope,
            "token_type": "refresh"
        }
        
        refresh_token = create_refresh_token(refresh_token_data)
        
        logger.info(
            f"PKCE tokens generated for user {user_id} and client {client_id}"
        )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": 1800,  # 30 minutes
            "scope": scope
        }
        
    except Exception as e:
        logger.error(f"Failed to generate PKCE tokens: {str(e)}")
        raise


@activity.defn(name="log_security_event")
async def log_security_event(event_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Log security events for PKCE flows
    Important for monitoring and audit trails
    """
    try:
        event_type = event_data.get("event_type", "unknown")
        user_id = event_data.get("user_id", "unknown")
        client_id = event_data.get("client_id", "unknown")
        timestamp = event_data.get("timestamp", datetime.utcnow().isoformat())
        
        # In production, store in dedicated security log table/service
        security_log = {
            "event_type": event_type,
            "user_id": user_id,
            "client_id": client_id,
            "timestamp": timestamp,
            "details": event_data
        }
        
        logger.info(
            f"Security event logged: {event_type} for user {user_id} and client {client_id}"
        )
        
        # Simulate async logging
        await asyncio.sleep(0.1)
        
        return {"logged": True}
        
    except Exception as e:
        logger.error(f"Failed to log security event: {str(e)}")
        return {"logged": False, "error": str(e)}


@activity.defn(name="validate_pkce_client")
async def validate_pkce_client(client_id: str, redirect_uri: str) -> Dict[str, Any]:
    """
    Validate OAuth2 client for PKCE flow
    In production, check against registered client database
    """
    try:
        # Demo client validation - replace with database lookup
        demo_clients = {
            "demo-client": {
                "redirect_uris": [
                    "http://localhost:3000/callback",
                    "https://yourdomain.com/callback"
                ],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "pkce_required": True
            },
            "mobile-app": {
                "redirect_uris": [
                    "com.yourapp.oauth://callback"
                ],
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "pkce_required": True
            }
        }
        
        if client_id not in demo_clients:
            return {
                "valid": False,
                "error": "Unknown client_id"
            }
        
        client_config = demo_clients[client_id]
        
        if redirect_uri not in client_config["redirect_uris"]:
            return {
                "valid": False,
                "error": "Invalid redirect_uri for client"
            }
        
        if "authorization_code" not in client_config["grant_types"]:
            return {
                "valid": False,
                "error": "Authorization code flow not allowed for client"
            }
        
        logger.info(f"PKCE client validation passed for {client_id}")
        
        return {
            "valid": True,
            "client_config": client_config
        }
        
    except Exception as e:
        logger.error(f"PKCE client validation error: {str(e)}")
        return {
            "valid": False,
            "error": "Client validation failed"
        }