"""
Advanced Temporal Authentication Saga Patterns

This module implements sophisticated Temporal patterns for authentication:
- Saga pattern for distributed authentication transactions
- Child workflows for complex auth flows  
- Signals and updates for real-time auth decisions
- Workflow versioning for production deployments
- Continue-as-new for long-running auth sessions
"""

from temporalio import workflow, activity
from temporalio.common import RetryPolicy, SearchAttributeKey
from temporalio.exceptions import ApplicationError, ActivityError
from datetime import timedelta, datetime
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import asyncio
import uuid
import logging

logger = logging.getLogger(__name__)

@dataclass
class AuthTransaction:
    """Authentication transaction for saga pattern"""
    transaction_id: str
    user_id: str
    steps: List[str]
    completed_steps: List[str]
    failed_steps: List[str]
    compensation_steps: List[str]
    status: str  # pending, committed, aborted
    created_at: str

@dataclass 
class AuthDecision:
    """Real-time authentication decision"""
    decision_id: str
    user_id: str
    risk_score: float
    required_factors: List[str]
    decision: str  # allow, deny, challenge
    expires_at: str

class AuthSagaError(ApplicationError):
    """Custom error for authentication saga failures"""
    pass

class AuthSagaCompensationError(ApplicationError):
    """Error during saga compensation"""
    pass

# Search attributes for advanced observability
SAGA_TRANSACTION_ID = SearchAttributeKey.for_keyword("SagaTransactionId")
AUTH_DECISION_ID = SearchAttributeKey.for_keyword("AuthDecisionId")
USER_RISK_SCORE = SearchAttributeKey.for_double("UserRiskScore")
AUTH_STATUS = SearchAttributeKey.for_keyword("AuthStatus")

@workflow.defn
class AuthenticationSagaWorkflow:
    """
    Distributed Authentication Saga Pattern
    
    Implements a saga for multi-step authentication that can handle:
    - Account creation across multiple services
    - Email verification with external providers
    - Identity verification with third-party APIs
    - Fraud check with multiple ML models
    - Account provisioning in downstream systems
    
    If any step fails, compensating transactions are executed
    to maintain data consistency across all services.
    """
    
    def __init__(self):
        self.transaction_id = str(uuid.uuid4())
        self.completed_steps = []
        self.compensation_queue = []
        
    @workflow.run
    async def run(self, auth_request: Dict[str, Any]) -> Dict[str, Any]:
        """Execute distributed authentication saga"""
        
        # Set search attributes for observability
        workflow.upsert_search_attributes({
            SAGA_TRANSACTION_ID: self.transaction_id,
            AUTH_STATUS: "saga_started"
        })
        
        user_id = auth_request.get("user_id", str(uuid.uuid4()))
        
        workflow.logger.info(f"Starting authentication saga", extra={
            "transaction_id": self.transaction_id,
            "user_id": user_id,
            "auth_type": auth_request.get("auth_type", "registration")
        })
        
        saga_transaction = AuthTransaction(
            transaction_id=self.transaction_id,
            user_id=user_id,
            steps=["fraud_check", "create_account", "verify_email", "provision_services", "finalize"],
            completed_steps=[],
            failed_steps=[],
            compensation_steps=[],
            status="pending",
            created_at=datetime.utcnow().isoformat()
        )
        
        try:
            # Step 1: AI-powered fraud detection (compensatable)
            await self._execute_saga_step(
                "fraud_check",
                self._fraud_check_step,
                auth_request,
                saga_transaction
            )
            
            # Step 2: Create user account (compensatable)
            account_result = await self._execute_saga_step(
                "create_account", 
                self._create_account_step,
                auth_request,
                saga_transaction
            )
            
            # Step 3: Email verification (compensatable)
            verification_result = await self._execute_saga_step(
                "verify_email",
                self._email_verification_step, 
                {**auth_request, **account_result},
                saga_transaction
            )
            
            # Step 4: Provision downstream services (compensatable)
            provision_result = await self._execute_saga_step(
                "provision_services",
                self._provision_services_step,
                {**auth_request, **account_result, **verification_result},
                saga_transaction
            )
            
            # Step 5: Finalize authentication (non-compensatable)
            final_result = await self._execute_saga_step(
                "finalize",
                self._finalize_auth_step,
                {**auth_request, **account_result, **verification_result, **provision_result},
                saga_transaction,
                compensatable=False
            )
            
            # Saga completed successfully
            workflow.upsert_search_attributes({
                AUTH_STATUS: "saga_committed"
            })
            
            saga_transaction.status = "committed"
            
            workflow.logger.info(f"Authentication saga completed successfully", extra={
                "transaction_id": self.transaction_id,
                "user_id": user_id,
                "completed_steps": len(saga_transaction.completed_steps)
            })
            
            return {
                "success": True,
                "transaction_id": self.transaction_id,
                "user_id": user_id,
                "saga_status": "committed",
                "completed_steps": saga_transaction.completed_steps,
                "final_result": final_result,
                "commit_timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            workflow.logger.error(f"Authentication saga failed, executing compensation", extra={
                "transaction_id": self.transaction_id,
                "user_id": user_id,
                "error": str(e),
                "completed_steps": saga_transaction.completed_steps
            })
            
            # Execute compensation for all completed steps
            compensation_result = await self._execute_compensation(saga_transaction)
            
            workflow.upsert_search_attributes({
                AUTH_STATUS: "saga_aborted"
            })
            
            return {
                "success": False,
                "transaction_id": self.transaction_id,
                "user_id": user_id,
                "saga_status": "aborted",
                "error": str(e),
                "compensation_result": compensation_result,
                "abort_timestamp": datetime.utcnow().isoformat()
            }
    
    async def _execute_saga_step(self, step_name: str, step_function, 
                                step_data: Dict[str, Any], saga_transaction: AuthTransaction,
                                compensatable: bool = True) -> Dict[str, Any]:
        """Execute a saga step with compensation tracking"""
        
        workflow.logger.info(f"Executing saga step: {step_name}")
        
        try:
            # Execute the step
            result = await step_function(step_data, saga_transaction)
            
            # Track completed step
            saga_transaction.completed_steps.append(step_name)
            if compensatable:
                saga_transaction.compensation_steps.append(step_name)
            
            workflow.logger.info(f"Saga step completed: {step_name}")
            return result
            
        except Exception as e:
            saga_transaction.failed_steps.append(step_name)
            workflow.logger.error(f"Saga step failed: {step_name}, error: {e}")
            raise AuthSagaError(f"Step {step_name} failed: {str(e)}")
    
    async def _fraud_check_step(self, auth_data: Dict[str, Any], 
                               saga: AuthTransaction) -> Dict[str, Any]:
        """Step 1: AI-powered fraud detection"""
        
        result = await workflow.execute_activity(
            "ai_fraud_detection_ml",
            auth_data,
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=RetryPolicy(
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=30),
                maximum_attempts=3
            )
        )
        
        fraud_score = result.get("fraud_score", 0.0)
        
        # Update search attributes with risk score
        workflow.upsert_search_attributes({
            USER_RISK_SCORE: fraud_score
        })
        
        # Block if high fraud risk
        if fraud_score > 0.8:
            raise AuthSagaError(f"High fraud risk detected: {fraud_score}")
        
        return {
            "fraud_check_passed": True,
            "fraud_score": fraud_score,
            "ai_insights": result.get("ai_insights", {})
        }
    
    async def _create_account_step(self, auth_data: Dict[str, Any], 
                                  saga: AuthTransaction) -> Dict[str, Any]:
        """Step 2: Create user account"""
        
        account_result = await workflow.execute_activity(
            "create_user_account_saga",
            {
                "auth_data": auth_data,
                "transaction_id": saga.transaction_id,
                "fraud_score": auth_data.get("fraud_score", 0.0)
            },
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=RetryPolicy(
                initial_interval=timedelta(seconds=2),
                maximum_interval=timedelta(minutes=1),
                maximum_attempts=3,
                non_retryable_error_types=["UserExistsError"]
            )
        )
        
        return {
            "user_id": account_result["user_id"],
            "account_created": True,
            "account_status": account_result.get("status", "pending_verification")
        }
    
    async def _email_verification_step(self, auth_data: Dict[str, Any],
                                      saga: AuthTransaction) -> Dict[str, Any]:
        """Step 3: Email verification with external providers"""
        
        # Start child workflow for email verification
        email_workflow_handle = await workflow.start_child_workflow(
            EmailVerificationChildWorkflow.run,
            {
                "user_id": auth_data["user_id"],
                "email": auth_data.get("email"),
                "transaction_id": saga.transaction_id
            },
            id=f"email-verification-{saga.transaction_id}",
            task_queue="email-verification-queue",
            execution_timeout=timedelta(minutes=10)
        )
        
        email_result = await email_workflow_handle
        
        return {
            "email_verification_started": True,
            "verification_token": email_result.get("verification_token"),
            "email_workflow_id": email_workflow_handle.id
        }
    
    async def _provision_services_step(self, auth_data: Dict[str, Any],
                                      saga: AuthTransaction) -> Dict[str, Any]:
        """Step 4: Provision user in downstream services"""
        
        # Provision in parallel across multiple services
        provision_tasks = []
        
        # CRM provisioning
        provision_tasks.append(
            workflow.execute_activity(
                "provision_user_crm",
                {
                    "user_id": auth_data["user_id"], 
                    "transaction_id": saga.transaction_id
                },
                start_to_close_timeout=timedelta(minutes=1)
            )
        )
        
        # Analytics provisioning  
        provision_tasks.append(
            workflow.execute_activity(
                "provision_user_analytics",
                {
                    "user_id": auth_data["user_id"],
                    "transaction_id": saga.transaction_id
                },
                start_to_close_timeout=timedelta(minutes=1)
            )
        )
        
        # Marketing provisioning
        provision_tasks.append(
            workflow.execute_activity(
                "provision_user_marketing",
                {
                    "user_id": auth_data["user_id"],
                    "transaction_id": saga.transaction_id,
                    "fraud_score": auth_data.get("fraud_score", 0.0)
                },
                start_to_close_timeout=timedelta(minutes=1)
            )
        )
        
        # Wait for all provisioning to complete
        provision_results = await asyncio.gather(*provision_tasks)
        
        return {
            "services_provisioned": len(provision_results),
            "crm_provisioned": provision_results[0].get("success", False),
            "analytics_provisioned": provision_results[1].get("success", False), 
            "marketing_provisioned": provision_results[2].get("success", False)
        }
    
    async def _finalize_auth_step(self, auth_data: Dict[str, Any],
                                 saga: AuthTransaction) -> Dict[str, Any]:
        """Step 5: Finalize authentication (non-compensatable)"""
        
        final_result = await workflow.execute_activity(
            "finalize_user_authentication",
            {
                "user_id": auth_data["user_id"],
                "transaction_id": saga.transaction_id,
                "saga_data": auth_data
            },
            start_to_close_timeout=timedelta(minutes=1),
            retry_policy=RetryPolicy(
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=10),
                maximum_attempts=5
            )
        )
        
        return {
            "authentication_finalized": True,
            "final_status": final_result.get("status", "completed"),
            "access_token": final_result.get("access_token"),
            "user_profile": final_result.get("user_profile", {})
        }
    
    async def _execute_compensation(self, saga_transaction: AuthTransaction) -> Dict[str, Any]:
        """Execute compensating transactions for completed steps"""
        
        workflow.upsert_search_attributes({
            AUTH_STATUS: "executing_compensation"
        })
        
        compensation_results = {}
        
        # Execute compensation in reverse order
        for step in reversed(saga_transaction.compensation_steps):
            try:
                workflow.logger.info(f"Executing compensation for step: {step}")
                
                compensation_result = await self._compensate_step(step, saga_transaction)
                compensation_results[step] = {
                    "success": True,
                    "result": compensation_result
                }
                
            except Exception as e:
                workflow.logger.error(f"Compensation failed for step {step}: {e}")
                compensation_results[step] = {
                    "success": False,
                    "error": str(e)
                }
        
        return {
            "compensation_executed": True,
            "compensated_steps": list(compensation_results.keys()),
            "compensation_results": compensation_results
        }
    
    async def _compensate_step(self, step_name: str, saga_transaction: AuthTransaction) -> Any:
        """Execute compensation for a specific step"""
        
        compensation_map = {
            "fraud_check": self._compensate_fraud_check,
            "create_account": self._compensate_create_account,
            "verify_email": self._compensate_verify_email,
            "provision_services": self._compensate_provision_services
        }
        
        compensation_function = compensation_map.get(step_name)
        if compensation_function:
            return await compensation_function(saga_transaction)
        else:
            workflow.logger.warning(f"No compensation defined for step: {step_name}")
            return {"compensated": False, "reason": "no_compensation_defined"}
    
    async def _compensate_fraud_check(self, saga: AuthTransaction) -> Dict[str, Any]:
        """Compensate fraud check step"""
        # Clear fraud detection cache/flags
        await workflow.execute_activity(
            "clear_fraud_detection_cache",
            {"transaction_id": saga.transaction_id},
            start_to_close_timeout=timedelta(seconds=30)
        )
        return {"fraud_check_compensated": True}
    
    async def _compensate_create_account(self, saga: AuthTransaction) -> Dict[str, Any]:
        """Compensate account creation step"""
        # Delete created account
        await workflow.execute_activity(
            "delete_user_account_saga",
            {
                "user_id": saga.user_id,
                "transaction_id": saga.transaction_id
            },
            start_to_close_timeout=timedelta(minutes=1)
        )
        return {"account_deleted": True}
    
    async def _compensate_verify_email(self, saga: AuthTransaction) -> Dict[str, Any]:
        """Compensate email verification step"""
        # Cancel email verification workflow
        await workflow.execute_activity(
            "cancel_email_verification",
            {
                "user_id": saga.user_id,
                "transaction_id": saga.transaction_id
            },
            start_to_close_timeout=timedelta(seconds=30)
        )
        return {"email_verification_cancelled": True}
    
    async def _compensate_provision_services(self, saga: AuthTransaction) -> Dict[str, Any]:
        """Compensate service provisioning step"""
        # Deprovision from all services
        await workflow.execute_activity(
            "deprovision_user_all_services",
            {
                "user_id": saga.user_id,
                "transaction_id": saga.transaction_id
            },
            start_to_close_timeout=timedelta(minutes=2)
        )
        return {"services_deprovisioned": True}


@workflow.defn
class EmailVerificationChildWorkflow:
    """Child workflow for email verification process"""
    
    @workflow.run
    async def run(self, verification_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute email verification as child workflow"""
        
        user_id = verification_data.get("user_id")
        email = verification_data.get("email")
        transaction_id = verification_data.get("transaction_id")
        
        # Generate verification token
        token_result = await workflow.execute_activity(
            "generate_verification_token",
            {
                "user_id": user_id,
                "email": email,
                "transaction_id": transaction_id
            },
            start_to_close_timeout=timedelta(seconds=30)
        )
        
        # Send verification email with AI optimization
        email_result = await workflow.execute_activity(
            "ai_intelligent_email_optimization",
            {
                "email": email,
                "user_id": user_id,
                "token": token_result["token"],
                "transaction_id": transaction_id
            },
            start_to_close_timeout=timedelta(minutes=2)
        )
        
        return {
            "verification_token": token_result["token"],
            "email_sent": email_result.get("success", False),
            "optimization_applied": True
        }


@workflow.defn  
class AdaptiveAuthenticationWorkflow:
    """
    Adaptive Authentication with Signals and Updates
    
    This workflow responds to real-time signals to adjust authentication
    requirements based on changing risk conditions.
    """
    
    def __init__(self):
        self.current_decision = None
        self.risk_threshold = 0.7
        
    @workflow.run
    async def run(self, auth_session: Dict[str, Any]) -> Dict[str, Any]:
        """Execute adaptive authentication with real-time updates"""
        
        user_id = auth_session.get("user_id")
        session_id = auth_session.get("session_id", str(uuid.uuid4()))
        
        # Set search attributes
        workflow.upsert_search_attributes({
            AUTH_DECISION_ID: session_id,
            AUTH_STATUS: "adaptive_auth_started"
        })
        
        # Initial risk assessment
        initial_risk = await self._assess_initial_risk(auth_session)
        
        self.current_decision = AuthDecision(
            decision_id=session_id,
            user_id=user_id,
            risk_score=initial_risk["risk_score"],
            required_factors=initial_risk["required_factors"],
            decision=initial_risk["decision"],
            expires_at=(datetime.utcnow() + timedelta(minutes=10)).isoformat()
        )
        
        # Wait for signals or timeout
        try:
            # Listen for risk update signals
            await workflow.wait_condition(
                lambda: self._should_reevaluate(),
                timeout=timedelta(minutes=10)
            )
            
            # Reevaluate based on new signals
            updated_decision = await self._reevaluate_authentication()
            
            return {
                "final_decision": updated_decision.decision,
                "final_risk_score": updated_decision.risk_score,
                "required_factors": updated_decision.required_factors,
                "session_id": session_id,
                "adaptive_adjustments": True
            }
            
        except asyncio.TimeoutError:
            # Timeout reached, return current decision
            return {
                "final_decision": self.current_decision.decision,
                "final_risk_score": self.current_decision.risk_score,
                "required_factors": self.current_decision.required_factors,
                "session_id": session_id,
                "timeout_reached": True
            }
    
    @workflow.signal
    async def update_risk_signal(self, risk_update: Dict[str, Any]):
        """Signal to update risk assessment in real-time"""
        workflow.logger.info(f"Received risk update signal: {risk_update}")
        
        # Update current decision with new risk data
        if risk_update.get("risk_score") is not None:
            self.current_decision.risk_score = risk_update["risk_score"]
        
        if risk_update.get("new_factors"):
            self.current_decision.required_factors.extend(risk_update["new_factors"])
        
        # Update search attributes
        workflow.upsert_search_attributes({
            USER_RISK_SCORE: self.current_decision.risk_score,
            AUTH_STATUS: "risk_updated"
        })
    
    @workflow.query
    def get_current_decision(self) -> Dict[str, Any]:
        """Query current authentication decision"""
        if self.current_decision:
            return {
                "decision": self.current_decision.decision,
                "risk_score": self.current_decision.risk_score,
                "required_factors": self.current_decision.required_factors,
                "expires_at": self.current_decision.expires_at
            }
        return {"decision": "pending"}
    
    def _should_reevaluate(self) -> bool:
        """Check if authentication should be reevaluated"""
        if self.current_decision is None:
            return False
        
        # Reevaluate if risk score changed significantly
        return self.current_decision.risk_score > self.risk_threshold
    
    async def _assess_initial_risk(self, auth_session: Dict[str, Any]) -> Dict[str, Any]:
        """Assess initial authentication risk"""
        
        risk_result = await workflow.execute_activity(
            "ai_behavioral_authentication",
            auth_session,
            start_to_close_timeout=timedelta(minutes=1)
        )
        
        risk_score = risk_result.get("authentication_score", 0.5)
        
        # Determine required factors based on risk
        if risk_score > 0.8:
            decision = "deny"
            required_factors = []
        elif risk_score > 0.6:
            decision = "challenge" 
            required_factors = ["mfa", "device_verification"]
        elif risk_score > 0.4:
            decision = "challenge"
            required_factors = ["mfa"]
        else:
            decision = "allow"
            required_factors = []
        
        return {
            "risk_score": risk_score,
            "decision": decision,
            "required_factors": required_factors
        }
    
    async def _reevaluate_authentication(self) -> AuthDecision:
        """Reevaluate authentication decision based on updated signals"""
        
        # Get updated risk assessment
        updated_risk = await workflow.execute_activity(
            "reevaluate_authentication_risk",
            {
                "current_decision": {
                    "decision_id": self.current_decision.decision_id,
                    "risk_score": self.current_decision.risk_score,
                    "required_factors": self.current_decision.required_factors
                }
            },
            start_to_close_timeout=timedelta(seconds=30)
        )
        
        # Update decision based on new assessment
        self.current_decision.risk_score = updated_risk["risk_score"]
        self.current_decision.decision = updated_risk["decision"]
        self.current_decision.required_factors = updated_risk["required_factors"]
        
        workflow.upsert_search_attributes({
            USER_RISK_SCORE: self.current_decision.risk_score,
            AUTH_STATUS: "decision_updated"
        })
        
        return self.current_decision


@workflow.defn
class ContinuousAuthSessionWorkflow:
    """
    Long-running workflow for continuous authentication
    
    Uses Continue-As-New pattern for indefinite session monitoring
    """
    
    @workflow.run
    async def run(self, session_data: Dict[str, Any], iteration: int = 0) -> Dict[str, Any]:
        """Monitor authentication session continuously"""
        
        user_id = session_data.get("user_id")
        session_id = session_data.get("session_id")
        
        # Monitor for 1 hour intervals
        session_timeout = timedelta(hours=1)
        
        workflow.logger.info(f"Continuous auth monitoring started", extra={
            "user_id": user_id,
            "session_id": session_id,
            "iteration": iteration
        })
        
        try:
            # Continuous behavioral monitoring
            async with workflow.activity_timeout(session_timeout):
                monitoring_result = await workflow.execute_activity(
                    "monitor_session_behavior",
                    {
                        "user_id": user_id,
                        "session_id": session_id,
                        "iteration": iteration
                    },
                    start_to_close_timeout=session_timeout,
                    heartbeat_timeout=timedelta(minutes=5)
                )
            
            # Check if session should continue
            if monitoring_result.get("continue_session", True) and iteration < 24:  # Max 24 hours
                # Continue as new to avoid workflow history getting too large
                workflow.continue_as_new(
                    session_data,
                    iteration + 1
                )
            else:
                # End continuous monitoring
                return {
                    "session_ended": True,
                    "total_iterations": iteration + 1,
                    "end_reason": monitoring_result.get("end_reason", "max_duration"),
                    "final_status": monitoring_result.get("final_status", "completed")
                }
                
        except asyncio.TimeoutError:
            # Session timeout - end monitoring
            return {
                "session_ended": True,
                "total_iterations": iteration + 1,
                "end_reason": "timeout",
                "timeout_at_iteration": iteration
            }