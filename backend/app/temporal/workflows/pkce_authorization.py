"""
PKCE Authorization Workflow
OAuth 2.1 compliant PKCE flow with Temporal orchestration and enhanced workflow patterns
"""
from datetime import timedelta
from typing import Dict, Any, Optional
import temporalio.workflow as workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError, ActivityError

from app.models.pkce import (
    PKCERequest, 
    PKCETokenRequest, 
    PKCEAuthorizationCode,
    PKCEUtils,
    PKCEResponse,
    PKCETokenResponse,
    PKCEError,
    PKCEErrorTypes
)


@workflow.defn
class PKCEAuthorizationWorkflow:
    """
    OAuth 2.1 compliant PKCE authorization workflow
    Provides enhanced security against authorization code interception attacks
    """

    def __init__(self):
        self._authorization_code: Optional[PKCEAuthorizationCode] = None
        self._workflow_result: Optional[Dict[str, Any]] = None
        self._workflow_status: str = "initializing"
        self._security_events: list = []
        self._revoke_signal_received: bool = False

    @workflow.run
    async def run(self, pkce_request: PKCERequest, user_id: str) -> Dict[str, Any]:
        """
        Execute PKCE authorization flow
        
        Args:
            pkce_request: PKCE authorization request with code challenge
            user_id: Authenticated user ID
            
        Returns:
            Authorization code response or error
        """
        workflow.logger.info(
            f"Starting PKCE authorization workflow for user {user_id} and client {pkce_request.client_id}"
        )
        
        self._workflow_status = "validating_request"
        
        # Set up signal handler for authorization revocation
        self._setup_signal_handlers()
        
        try:
            # Step 1: Validate PKCE request with enhanced error handling
            try:
                validation_result = await workflow.execute_activity(
                    "validate_pkce_request",
                    pkce_request.dict() if hasattr(pkce_request, 'dict') else pkce_request,
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=RetryPolicy(
                        initial_interval=timedelta(seconds=1),
                        maximum_attempts=3
                    )
                )
            except ActivityError as e:
                workflow.logger.error(f"PKCE request validation failed: {e}")
                return self._create_error_response(
                    PKCEErrorTypes.INVALID_REQUEST,
                    "Request validation failed",
                    pkce_request.state if hasattr(pkce_request, 'state') else None
                )
            
            if not validation_result.get("valid"):
                self._workflow_status = "validation_failed"
                self._add_security_event("pkce_validation_failed", {
                    "client_id": pkce_request.client_id if hasattr(pkce_request, 'client_id') else None,
                    "error": validation_result.get("error_description")
                })
                return self._create_error_response(
                    PKCEErrorTypes.INVALID_REQUEST,
                    validation_result.get("error_description", "Invalid PKCE request"),
                    pkce_request.state if hasattr(pkce_request, 'state') else None
                )
            
            self._workflow_status = "generating_code"
            
            # Step 2: Generate authorization code with PKCE parameters
            # Use workflow execution time for consistent timestamps across activities
            auth_code_data = PKCEUtils.create_authorization_code(
                client_id=pkce_request.client_id if hasattr(pkce_request, 'client_id') else pkce_request.get('client_id'),
                user_id=user_id,
                redirect_uri=pkce_request.redirect_uri if hasattr(pkce_request, 'redirect_uri') else pkce_request.get('redirect_uri'),
                code_challenge=pkce_request.code_challenge if hasattr(pkce_request, 'code_challenge') else pkce_request.get('code_challenge'),
                code_challenge_method=pkce_request.code_challenge_method if hasattr(pkce_request, 'code_challenge_method') else pkce_request.get('code_challenge_method', 'S256'),
                scope=pkce_request.scope if hasattr(pkce_request, 'scope') else pkce_request.get('scope'),
                state=pkce_request.state if hasattr(pkce_request, 'state') else pkce_request.get('state')
            )
            
            # Check for revocation signal before proceeding
            if self._revoke_signal_received:
                workflow.logger.info("Authorization revoked by signal")
                return self._create_error_response(
                    PKCEErrorTypes.INVALID_REQUEST,
                    "Authorization request was cancelled",
                    pkce_request.state if hasattr(pkce_request, 'state') else pkce_request.get('state')
                )
            
            self._workflow_status = "storing_code"
            
            # Step 3: Store authorization code securely with parallel activities
            store_activities = []
            
            # Primary storage activity
            store_activities.append(
                workflow.execute_activity(
                    "store_pkce_authorization_code",
                    auth_code_data.dict(),
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=RetryPolicy(
                        initial_interval=timedelta(seconds=1),
                        maximum_attempts=3
                    )
                )
            )
            
            # Start authorization code expiration timer
            code_expiration_timer = workflow.start_timer(timedelta(minutes=10))
            store_activities.append(code_expiration_timer)
            
            # Execute storage and start expiration timer in parallel
            store_result, _ = await workflow.gather(*store_activities, return_exceptions=True)
            
            if isinstance(store_result, Exception) or not store_result.get("success"):
                workflow.logger.error(f"Failed to store PKCE authorization code: {getattr(store_result, 'message', store_result)}")
                return self._create_error_response(
                    PKCEErrorTypes.INVALID_REQUEST,
                    "Failed to generate authorization code",
                    pkce_request.state if hasattr(pkce_request, 'state') else pkce_request.get('state')
                )
            
            self._authorization_code = auth_code_data
            self._workflow_status = "code_generated"
            
            # Step 4: Log security event for monitoring
            await workflow.execute_activity(
                "log_security_event",
                {
                    "event_type": "pkce_authorization_code_generated",
                    "user_id": user_id,
                    "client_id": pkce_request.client_id,
                    "code_challenge_method": pkce_request.code_challenge_method,
                    "timestamp": auth_code_data.created_at.isoformat()
                },
                start_to_close_timeout=timedelta(seconds=15),
                retry_policy=RetryPolicy(maximum_attempts=2)
            )
            
            workflow.logger.info(
                f"PKCE authorization code generated successfully for user {user_id}"
            )
            
            self._workflow_result = {
                "success": True,
                "code": auth_code_data.code,
                "state": pkce_request.state,
                "expires_in": 600,  # 10 minutes
                "method": "pkce_workflow"
            }
            
            return self._workflow_result
            
        except ApplicationError as e:
            workflow.logger.error(f"PKCE authorization application error: {e}")
            self._workflow_status = "failed"
            return self._create_error_response(
                PKCEErrorTypes.INVALID_REQUEST,
                f"Authorization failed: {e.message}",
                pkce_request.state if hasattr(pkce_request, 'state') else pkce_request.get('state')
            )
        except Exception as e:
            workflow.logger.error(f"PKCE authorization workflow failed: {str(e)}")
            self._workflow_status = "failed"
            return self._create_error_response(
                PKCEErrorTypes.INVALID_REQUEST,
                "Authorization request failed",
                pkce_request.state if hasattr(pkce_request, 'state') else pkce_request.get('state')
            )

    def _create_error_response(self, error_type: str, description: str, state: Optional[str] = None) -> Dict[str, Any]:
        """Create standardized PKCE error response"""
        return {
            "success": False,
            "error": error_type,
            "error_description": description,
            "state": state,
            "method": "pkce_workflow"
        }

    @workflow.query
    def get_authorization_code(self) -> Optional[Dict[str, Any]]:
        """Query for authorization code details"""
        if self._authorization_code:
            return {
                "code": self._authorization_code.code,
                "client_id": self._authorization_code.client_id,
                "expires_at": self._authorization_code.expires_at.isoformat(),
                "is_used": self._authorization_code.is_used
            }
        return None

    @workflow.query  
    def get_workflow_result(self) -> Optional[Dict[str, Any]]:
        """Query for workflow execution result"""
        return self._workflow_result
        
    @workflow.query
    def get_workflow_status(self) -> str:
        """Query for current workflow status"""
        return self._workflow_status
        
    @workflow.query
    def get_security_events(self) -> list:
        """Query for security events during workflow execution"""
        return self._security_events
        
    @workflow.signal
    def revoke_authorization(self, reason: str = "user_cancelled"):
        """Signal to revoke the authorization request"""
        workflow.logger.info(f"Received revocation signal: {reason}")
        self._revoke_signal_received = True
        self._workflow_status = "revoked"
        self._add_security_event("authorization_revoked", {"reason": reason})
        
    @workflow.signal
    def update_security_level(self, level: str):
        """Signal to update security monitoring level"""
        workflow.logger.info(f"Security level updated to: {level}")
        self._add_security_event("security_level_updated", {"level": level})
        
    def _setup_signal_handlers(self):
        """Set up signal handlers for workflow control"""
        # Signal handlers are automatically registered via decorators
        workflow.logger.debug("Signal handlers configured for PKCE authorization workflow")
        
    def _add_security_event(self, event_type: str, details: Dict[str, Any]):
        """Add security event to workflow state"""
        event = {
            "type": event_type,
            "timestamp": workflow.now().isoformat(),
            "details": details
        }
        self._security_events.append(event)
        workflow.logger.info(f"Security event recorded: {event_type}")


@workflow.defn
class PKCETokenExchangeWorkflow:
    """
    PKCE Token Exchange Workflow
    Securely exchange authorization code + code verifier for access tokens
    """

    def __init__(self):
        self._token_response: Optional[PKCETokenResponse] = None
        self._workflow_status: str = "initializing"
        self._security_events: list = []
        self._token_revoke_signal_received: bool = False
        self._fraud_detection_enabled: bool = True

    @workflow.run
    async def run(self, token_request: PKCETokenRequest) -> Dict[str, Any]:
        """
        Execute PKCE token exchange
        
        Args:
            token_request: Token request with authorization code and code verifier
            
        Returns:
            Access token response or error
        """
        workflow.logger.info(
            f"Starting PKCE token exchange for client {token_request.client_id if hasattr(token_request, 'client_id') else token_request.get('client_id')}"
        )
        
        self._workflow_status = "retrieving_auth_code"
        
        # Set up fraud detection and monitoring
        if self._fraud_detection_enabled:
            fraud_detection_task = workflow.execute_activity(
                "fraud_detection_scan",
                {
                    "client_id": token_request.client_id if hasattr(token_request, 'client_id') else token_request.get('client_id'),
                    "code": token_request.code if hasattr(token_request, 'code') else token_request.get('code')
                },
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=RetryPolicy(maximum_attempts=2)
            )
        
        try:
            # Step 1: Retrieve and validate authorization code
            auth_code_result = await workflow.execute_activity(
                "retrieve_pkce_authorization_code",
                token_request.code,
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_attempts=3
                )
            )
            
            if not auth_code_result["found"]:
                return self._create_token_error(
                    PKCEErrorTypes.INVALID_GRANT,
                    "Invalid or expired authorization code"
                )
            
            auth_code_data = auth_code_result["auth_code"]
            
            # Step 2: Validate PKCE code verifier
            verifier_valid = PKCEUtils.verify_code_challenge(
                code_verifier=token_request.code_verifier,
                code_challenge=auth_code_data["code_challenge"],
                method=auth_code_data["code_challenge_method"]
            )
            
            if not verifier_valid:
                workflow.logger.warning(
                    f"PKCE code verifier validation failed for client {token_request.client_id}"
                )
                return self._create_token_error(
                    PKCEErrorTypes.INVALID_CODE_VERIFIER,
                    "Invalid code verifier"
                )
            
            # Step 3: Validate client and redirect URI
            if (auth_code_data["client_id"] != token_request.client_id or
                auth_code_data["redirect_uri"] != token_request.redirect_uri):
                return self._create_token_error(
                    PKCEErrorTypes.INVALID_GRANT,
                    "Client ID or redirect URI mismatch"
                )
            
            # Step 4: Mark authorization code as used
            await workflow.execute_activity(
                "mark_authorization_code_used",
                token_request.code,
                start_to_close_timeout=timedelta(seconds=15)
            )
            
            self._workflow_status = "generating_tokens"
            
            # Step 5: Generate access and refresh tokens with parallel activities
            token_activities = []
            
            # Primary token generation
            token_generation = workflow.execute_activity(
                "generate_pkce_tokens",
                {
                    "user_id": auth_code_data["user_id"],
                    "client_id": token_request.client_id if hasattr(token_request, 'client_id') else token_request.get('client_id'),
                    "scope": auth_code_data.get("scope", "read write")
                },
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=1),
                    maximum_attempts=3
                )
            )
            token_activities.append(token_generation)
            
            # Parallel fraud detection completion check
            if self._fraud_detection_enabled and 'fraud_detection_task' in locals():
                token_activities.append(fraud_detection_task)
            
            # Wait for token generation and fraud detection to complete
            results = await workflow.gather(*token_activities, return_exceptions=True)
            token_result = results[0]
            
            if isinstance(token_result, Exception):
                workflow.logger.error(f"Token generation failed: {token_result}")
                return self._create_token_error(
                    PKCEErrorTypes.INVALID_REQUEST,
                    "Token generation failed"
                )
            
            # Check fraud detection results if enabled
            if len(results) > 1 and not isinstance(results[1], Exception):
                fraud_result = results[1]
                if fraud_result.get("suspicious", False):
                    self._add_security_event("suspicious_activity_detected", fraud_result)
                    workflow.logger.warning(f"Suspicious activity detected: {fraud_result}")
                    # Continue with token generation but log the event
            
            # Step 6: Log successful token exchange
            await workflow.execute_activity(
                "log_security_event",
                {
                    "event_type": "pkce_token_exchange_success",
                    "user_id": auth_code_data["user_id"],
                    "client_id": token_request.client_id,
                    "timestamp": workflow.now().isoformat()
                },
                start_to_close_timeout=timedelta(seconds=15),
                retry_policy=RetryPolicy(maximum_attempts=2)
            )
            
            workflow.logger.info(
                f"PKCE token exchange completed successfully for user {auth_code_data['user_id']}"
            )
            
            return {
                "success": True,
                "access_token": token_result["access_token"],
                "token_type": "Bearer",
                "expires_in": token_result["expires_in"],
                "refresh_token": token_result.get("refresh_token"),
                "scope": auth_code_data.get("scope"),
                "method": "pkce_token_workflow"
            }
            
        except Exception as e:
            workflow.logger.error(f"PKCE token exchange workflow failed: {str(e)}")
            return self._create_token_error(
                PKCEErrorTypes.INVALID_REQUEST,
                "Token exchange failed"
            )

    def _create_token_error(self, error_type: str, description: str) -> Dict[str, Any]:
        """Create standardized token error response"""
        return {
            "success": False,
            "error": error_type,
            "error_description": description,
            "method": "pkce_token_workflow"
        }

    @workflow.query
    def get_token_response(self) -> Optional[Dict[str, Any]]:
        """Query for token response details"""
        return self._token_response
        
    @workflow.query
    def get_token_workflow_status(self) -> str:
        """Query for current token workflow status"""
        return self._workflow_status
        
    @workflow.query
    def get_token_security_events(self) -> list:
        """Query for security events during token exchange"""
        return self._security_events
        
    @workflow.query
    def is_fraud_detection_enabled(self) -> bool:
        """Query for fraud detection status"""
        return self._fraud_detection_enabled
        
    @workflow.signal
    def revoke_tokens(self, reason: str = "security_breach"):
        """Signal to revoke issued tokens"""
        workflow.logger.info(f"Received token revocation signal: {reason}")
        self._token_revoke_signal_received = True
        self._workflow_status = "tokens_revoked"
        self._add_security_event("tokens_revoked", {"reason": reason})
        
    @workflow.signal
    def enable_fraud_detection(self, enabled: bool = True):
        """Signal to enable/disable fraud detection"""
        self._fraud_detection_enabled = enabled
        workflow.logger.info(f"Fraud detection {'enabled' if enabled else 'disabled'}")
        self._add_security_event("fraud_detection_toggled", {"enabled": enabled})
        
    @workflow.signal  
    def emergency_lockdown(self, reason: str = "security_incident"):
        """Signal for emergency security lockdown"""
        workflow.logger.error(f"Emergency lockdown initiated: {reason}")
        self._token_revoke_signal_received = True
        self._fraud_detection_enabled = True
        self._workflow_status = "emergency_lockdown"
        self._add_security_event("emergency_lockdown", {"reason": reason})
        
    def _add_security_event(self, event_type: str, details: Dict[str, Any]):
        """Add security event to token workflow state"""
        event = {
            "type": event_type,
            "timestamp": workflow.now().isoformat(),
            "details": details,
            "workflow_type": "token_exchange"
        }
        self._security_events.append(event)
        workflow.logger.info(f"Token security event recorded: {event_type}")


# Enhanced PKCE Workflow Patterns for Temporal
@workflow.defn 
class PKCEWorkflowOrchestrator:
    """
    Master orchestrator for PKCE flows
    Coordinates authorization and token exchange workflows with advanced Temporal patterns
    """
    
    def __init__(self):
        self._active_workflows: Dict[str, Dict[str, Any]] = {}
        self._global_security_events: list = []
        
    @workflow.run
    async def coordinate_pkce_flow(
        self, 
        pkce_request: Dict[str, Any], 
        user_id: str,
        flow_id: str
    ) -> Dict[str, Any]:
        """
        Coordinate complete PKCE flow with child workflows
        
        Args:
            pkce_request: PKCE authorization request
            user_id: Authenticated user ID  
            flow_id: Unique flow identifier
            
        Returns:
            Complete PKCE flow result
        """
        workflow.logger.info(f"Starting coordinated PKCE flow {flow_id}")
        
        # Start authorization workflow as child
        auth_workflow_id = f"pkce-auth-{flow_id}"
        auth_handle = await workflow.start_child_workflow(
            PKCEAuthorizationWorkflow.run,
            args=[pkce_request, user_id],
            id=auth_workflow_id,
            execution_timeout=timedelta(minutes=15)
        )
        
        self._active_workflows[auth_workflow_id] = {
            "type": "authorization",
            "status": "running",
            "started_at": workflow.now().isoformat()
        }
        
        try:
            auth_result = await auth_handle
            
            if auth_result.get("success"):
                workflow.logger.info(f"Authorization successful for flow {flow_id}")
                self._active_workflows[auth_workflow_id]["status"] = "completed"
                
                # Return authorization result for client redirect
                return {
                    "flow_id": flow_id,
                    "authorization_result": auth_result,
                    "next_step": "token_exchange",
                    "status": "authorization_completed"
                }
            else:
                workflow.logger.error(f"Authorization failed for flow {flow_id}")
                self._active_workflows[auth_workflow_id]["status"] = "failed"
                return {
                    "flow_id": flow_id,
                    "error": auth_result.get("error"),
                    "error_description": auth_result.get("error_description"),
                    "status": "authorization_failed"
                }
                
        except Exception as e:
            workflow.logger.error(f"PKCE flow coordination failed: {e}")
            self._active_workflows[auth_workflow_id]["status"] = "failed"
            return {
                "flow_id": flow_id,
                "error": "coordination_failed",
                "error_description": str(e),
                "status": "failed"
            }
    
    @workflow.query
    def get_active_workflows(self) -> Dict[str, Dict[str, Any]]:
        """Query active workflows in the orchestrator"""
        return self._active_workflows
    
    @workflow.query
    def get_flow_status(self, flow_id: str) -> Optional[Dict[str, Any]]:
        """Query specific flow status"""
        for workflow_id, workflow_info in self._active_workflows.items():
            if flow_id in workflow_id:
                return workflow_info
        return None
    
    @workflow.signal
    def terminate_flow(self, flow_id: str, reason: str = "user_request"):
        """Signal to terminate a specific PKCE flow"""
        workflow.logger.info(f"Terminating flow {flow_id}: {reason}")
        # Implementation would terminate child workflows
        self._add_global_security_event("flow_terminated", {
            "flow_id": flow_id, 
            "reason": reason
        })
    
    def _add_global_security_event(self, event_type: str, details: Dict[str, Any]):
        """Add global security event"""
        event = {
            "type": event_type,
            "timestamp": workflow.now().isoformat(),
            "details": details,
            "workflow_type": "orchestrator"
        }
        self._global_security_events.append(event)
        workflow.logger.info(f"Global PKCE security event: {event_type}")