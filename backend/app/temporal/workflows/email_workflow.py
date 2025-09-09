"""
Temporal-Powered Email Workflows for Reliable Email Delivery

This module provides durable, retry-capable email sending using Temporal:
- Email verification with intelligent retry logic
- Password reset emails with fallback strategies
- Admin notifications with escalation
- Email template management and personalization
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import json

from temporalio import workflow, activity
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError

# Email data models
@dataclass
class EmailRequest:
    to_email: str
    subject: str
    html_content: str
    text_content: Optional[str] = None
    template_name: Optional[str] = None
    template_data: Optional[Dict[str, Any]] = None
    priority: str = "normal"  # high, normal, low
    correlation_id: Optional[str] = None

@dataclass
class EmailDeliveryResult:
    success: bool
    provider: str
    delivery_time_ms: int
    message_id: Optional[str] = None
    error_message: Optional[str] = None
    attempts: int = 1
    fallback_used: bool = False

# Temporal Workflow for Email Delivery
@workflow.defn
class EmailDeliveryWorkflow:
    """
    Durable email delivery workflow with retry logic and fallback providers
    """
    
    def __init__(self):
        self.email_attempts = []
        self.delivery_results = []
    
    @workflow.run
    async def run(self, email_request: EmailRequest) -> Dict[str, Any]:
        """
        Execute email delivery with retry logic and fallbacks
        """
        workflow.logger.info(f"Starting email delivery workflow for {email_request.to_email}")
        
        # Set search attributes for monitoring
        await workflow.upsert_search_attributes({
            "recipient": [email_request.to_email],
            "email_type": [email_request.template_name or "generic"],
            "priority": [email_request.priority],
            "correlation_id": [email_request.correlation_id or ""]
        })
        
        try:
            # Primary delivery attempt with SMTP
            result = await workflow.execute_activity(
                "send_smtp_email",
                email_request,
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=RetryPolicy(
                    initial_interval=timedelta(seconds=10),
                    maximum_interval=timedelta(minutes=2),
                    maximum_attempts=3,
                    backoff_coefficient=2.0
                )
            )
            
            if result.success:
                workflow.logger.info(f"Email delivered successfully to {email_request.to_email}")
                return {
                    "success": True,
                    "delivery_method": "smtp",
                    "result": result,
                    "timestamp": datetime.now().isoformat()
                }
            
            # Primary delivery failed, try fallback
            workflow.logger.warning(f"Primary SMTP delivery failed for {email_request.to_email}, trying fallback")
            
            # Fallback to console/log delivery for development
            fallback_result = await workflow.execute_activity(
                "send_console_email",
                email_request,
                start_to_close_timeout=timedelta(minutes=1),
                retry_policy=RetryPolicy(maximum_attempts=1)
            )
            
            return {
                "success": fallback_result.success,
                "delivery_method": "console_fallback",
                "result": fallback_result,
                "primary_error": result.error_message,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            workflow.logger.error(f"Email delivery workflow failed for {email_request.to_email}: {e}")
            
            # Final fallback - just log the verification link
            verification_result = await workflow.execute_activity(
                "log_verification_link",
                email_request,
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(maximum_attempts=1)
            )
            
            return {
                "success": verification_result.success,
                "delivery_method": "verification_log",
                "result": verification_result,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

@workflow.defn
class EmailVerificationWorkflow:
    """
    Specialized workflow for email verification with user-friendly features
    """
    
    @workflow.run
    async def run(self, verification_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send email verification with personalized content and tracking
        """
        email = verification_data["email"]
        token = verification_data["token"]
        user_name = verification_data.get("user_name", email.split("@")[0])
        
        workflow.logger.info(f"Starting email verification workflow for {email}")
        
        # Generate verification link
        base_url = verification_data.get("base_url", "http://localhost:3000")
        verification_link = f"{base_url}/verify-email?token={token}"
        
        # Create personalized email content
        email_request = EmailRequest(
            to_email=email,
            subject="🔐 Verify Your Account - OAuth2 Auth Service",
            template_name="email_verification",
            html_content=f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #667eea;">🛡️ OAuth2 Auth Service</h1>
                </div>
                
                <div style="background: #f8f9ff; padding: 25px; border-radius: 10px; margin-bottom: 25px;">
                    <h2 style="color: #2d3748; margin-top: 0;">Welcome, {user_name}! 👋</h2>
                    <p style="color: #4a5568; font-size: 16px; line-height: 1.6;">
                        Thanks for joining our AI-powered authentication platform! 
                        To complete your registration, please verify your email address.
                    </p>
                </div>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{verification_link}" 
                       style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                              color: white; 
                              padding: 15px 30px; 
                              text-decoration: none; 
                              border-radius: 8px; 
                              font-weight: 600; 
                              display: inline-block;">
                        ✅ Verify My Email
                    </a>
                </div>
                
                <div style="background: #edf2f7; padding: 20px; border-radius: 8px; margin: 25px 0;">
                    <h3 style="color: #2d3748; margin-top: 0;">🔒 Security Features:</h3>
                    <ul style="color: #4a5568; margin: 0; padding-left: 20px;">
                        <li>AI-powered fraud detection</li>
                        <li>Temporal workflow reliability</li>
                        <li>Advanced encryption</li>
                        <li>Real-time monitoring</li>
                    </ul>
                </div>
                
                <div style="border-top: 1px solid #e2e8f0; padding-top: 20px; text-align: center;">
                    <p style="color: #718096; font-size: 14px;">
                        If you didn't create this account, you can safely ignore this email.<br>
                        This verification link expires in 24 hours.
                    </p>
                    <p style="color: #a0aec0; font-size: 12px; margin-top: 15px;">
                        Powered by Temporal workflows for reliable delivery 🌊
                    </p>
                </div>
            </div>
            """,
            text_content=f"""
            Welcome to OAuth2 Auth Service!
            
            Hi {user_name},
            
            Thanks for joining our AI-powered authentication platform!
            Please verify your email address by clicking the link below:
            
            {verification_link}
            
            Security Features:
            - AI-powered fraud detection
            - Temporal workflow reliability  
            - Advanced encryption
            - Real-time monitoring
            
            If you didn't create this account, you can safely ignore this email.
            This verification link expires in 24 hours.
            
            Powered by Temporal workflows for reliable delivery.
            """,
            priority="high",
            correlation_id=verification_data.get("correlation_id", f"verify_{token[:8]}")
        )
        
        # Use the email delivery workflow as a child workflow
        email_result = await workflow.execute_child_workflow(
            EmailDeliveryWorkflow.run,
            email_request,
            id=f"email-verify-{email}-{datetime.now().timestamp()}",
            execution_timeout=timedelta(minutes=10)
        )
        
        # Record metrics for analytics
        await workflow.execute_activity(
            "record_email_metric",
            {
                "email_type": "verification",
                "recipient": email,
                "success": email_result["success"],
                "delivery_method": email_result["delivery_method"],
                "timestamp": datetime.now().isoformat()
            },
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=2)
        )
        
        return {
            "verification_email_sent": email_result["success"],
            "delivery_method": email_result["delivery_method"],
            "verification_link": verification_link,
            "expires_at": (datetime.now() + timedelta(hours=24)).isoformat(),
            "email_result": email_result
        }

@workflow.defn
class PasswordResetEmailWorkflow:
    """
    Specialized workflow for password reset emails with security features
    """
    
    @workflow.run
    async def run(self, reset_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send password reset email with security checks and monitoring
        """
        email = reset_data["email"]
        token = reset_data["token"]
        user_name = reset_data.get("user_name", email.split("@")[0])
        ip_address = reset_data.get("ip_address", "unknown")
        
        workflow.logger.info(f"Starting password reset email workflow for {email}")
        
        # Security check - rate limiting via activity
        security_check = await workflow.execute_activity(
            "check_password_reset_rate_limit",
            {"email": email, "ip_address": ip_address},
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=2)
        )
        
        if not security_check["allowed"]:
            workflow.logger.warning(f"Password reset rate limit exceeded for {email}")
            return {
                "success": False,
                "error": "Rate limit exceeded",
                "retry_after": security_check.get("retry_after", 3600)
            }
        
        # Generate reset link
        base_url = reset_data.get("base_url", "http://localhost:3000")
        reset_link = f"{base_url}/reset-password?token={token}"
        
        # Create security-focused email content
        email_request = EmailRequest(
            to_email=email,
            subject="🔐 Password Reset Request - OAuth2 Auth Service",
            template_name="password_reset",
            html_content=f"""
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #667eea;">🛡️ OAuth2 Auth Service</h1>
                </div>
                
                <div style="background: #fff5f5; border-left: 4px solid #f56565; padding: 25px; border-radius: 10px; margin-bottom: 25px;">
                    <h2 style="color: #c53030; margin-top: 0;">🔐 Password Reset Request</h2>
                    <p style="color: #4a5568; font-size: 16px; line-height: 1.6;">
                        Hi {user_name}, we received a request to reset your password.
                        If this was you, click the button below to proceed.
                    </p>
                </div>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_link}" 
                       style="background: linear-gradient(135deg, #f56565 0%, #c53030 100%); 
                              color: white; 
                              padding: 15px 30px; 
                              text-decoration: none; 
                              border-radius: 8px; 
                              font-weight: 600; 
                              display: inline-block;">
                        🔄 Reset My Password
                    </a>
                </div>
                
                <div style="background: #edf2f7; padding: 20px; border-radius: 8px; margin: 25px 0;">
                    <h3 style="color: #2d3748; margin-top: 0;">🔍 Security Information:</h3>
                    <ul style="color: #4a5568; margin: 0; padding-left: 20px;">
                        <li><strong>Request IP:</strong> {ip_address}</li>
                        <li><strong>Request Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</li>
                        <li><strong>Expires:</strong> 1 hour from now</li>
                        <li><strong>AI Security:</strong> This request was validated by our fraud detection system</li>
                    </ul>
                </div>
                
                <div style="background: #fed7d7; padding: 20px; border-radius: 8px; margin: 25px 0;">
                    <p style="color: #c53030; margin: 0; font-weight: 600;">
                        ⚠️ If you didn't request this password reset, please ignore this email and consider:
                    </p>
                    <ul style="color: #c53030; margin: 10px 0 0 20px;">
                        <li>Checking if your account is secure</li>
                        <li>Enabling two-factor authentication</li>
                        <li>Contacting support if you see suspicious activity</li>
                    </ul>
                </div>
                
                <div style="border-top: 1px solid #e2e8f0; padding-top: 20px; text-align: center;">
                    <p style="color: #a0aec0; font-size: 12px; margin-top: 15px;">
                        Secured by AI-powered fraud detection and Temporal workflows 🌊
                    </p>
                </div>
            </div>
            """,
            text_content=f"""
            Password Reset Request - OAuth2 Auth Service
            
            Hi {user_name},
            
            We received a request to reset your password. If this was you, 
            click the link below to proceed:
            
            {reset_link}
            
            Security Information:
            - Request IP: {ip_address}
            - Request Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
            - Expires: 1 hour from now
            - AI Security: This request was validated by our fraud detection system
            
            If you didn't request this password reset, please ignore this email.
            Consider enabling two-factor authentication for better security.
            
            Secured by AI-powered fraud detection and Temporal workflows.
            """,
            priority="high",
            correlation_id=reset_data.get("correlation_id", f"reset_{token[:8]}")
        )
        
        # Send the email
        email_result = await workflow.execute_child_workflow(
            EmailDeliveryWorkflow.run,
            email_request,
            id=f"email-reset-{email}-{datetime.now().timestamp()}",
            execution_timeout=timedelta(minutes=10)
        )
        
        # Record security event for monitoring
        await workflow.execute_activity(
            "record_security_event",
            {
                "event_type": "password_reset_email",
                "email": email,
                "ip_address": ip_address,
                "success": email_result["success"],
                "timestamp": datetime.now().isoformat()
            },
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=2)
        )
        
        return {
            "reset_email_sent": email_result["success"],
            "delivery_method": email_result["delivery_method"],
            "reset_link": reset_link,
            "expires_at": (datetime.now() + timedelta(hours=1)).isoformat(),
            "email_result": email_result
        }

# Helper function to start email workflows
async def send_verification_email_workflow(
    temporal_client, 
    email: str, 
    token: str, 
    user_name: str = None,
    base_url: str = "http://localhost:3000"
) -> Dict[str, Any]:
    """Start email verification workflow"""
    
    verification_data = {
        "email": email,
        "token": token,
        "user_name": user_name or email.split("@")[0],
        "base_url": base_url,
        "correlation_id": f"verify_{email}_{int(datetime.now().timestamp())}"
    }
    
    result = await temporal_client.execute_workflow(
        EmailVerificationWorkflow.run,
        verification_data,
        id=f"email-verification-{email}-{datetime.now().timestamp()}",
        task_queue="auth-task-queue",
        execution_timeout=timedelta(minutes=15)
    )
    
    return result

async def send_password_reset_email_workflow(
    temporal_client,
    email: str,
    token: str,
    user_name: str = None,
    ip_address: str = "unknown",
    base_url: str = "http://localhost:3000"
) -> Dict[str, Any]:
    """Start password reset email workflow"""
    
    reset_data = {
        "email": email,
        "token": token,
        "user_name": user_name or email.split("@")[0],
        "ip_address": ip_address,
        "base_url": base_url,
        "correlation_id": f"reset_{email}_{int(datetime.now().timestamp())}"
    }
    
    result = await temporal_client.execute_workflow(
        PasswordResetEmailWorkflow.run,
        reset_data,
        id=f"password-reset-{email}-{datetime.now().timestamp()}",
        task_queue="auth-task-queue",
        execution_timeout=timedelta(minutes=15)
    )
    
    return result