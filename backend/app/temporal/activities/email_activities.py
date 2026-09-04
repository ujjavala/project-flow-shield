"""
Temporal Email Activities for Reliable Email Delivery

Provides durable email sending capabilities with multiple provider support:
- SMTP email delivery with authentication
- Console/log fallback for development
- Email template rendering and personalization
- Delivery tracking and metrics
"""

import asyncio
import smtplib
import ssl
from datetime import datetime
from typing import Dict, Any, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import logging

from temporalio import activity
import aiosmtplib
import redis.asyncio as redis

from app.config import settings

logger = logging.getLogger(__name__)


class EmailActivities:
    """Email delivery activities for Temporal workflows"""
    
    def __init__(self):
        self.redis_client = None
    
    async def _get_redis(self):
        """Get Redis client for rate limiting and metrics"""
        if self.redis_client is None:
            try:
                redis_host = "redis"  # Docker service name
                redis_port = 6379
                self.redis_client = redis.Redis(
                    host=redis_host, 
                    port=redis_port, 
                    decode_responses=True
                )
                await self.redis_client.ping()
                logger.info("Email Redis connected successfully")
            except Exception as exc:
                logger.error("Email Redis connection failed exception_type=%s", type(exc).__name__)
                self.redis_client = None
        return self.redis_client
    
    @activity.defn(name="send_smtp_email")
    async def send_smtp_email(self, email_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send email via SMTP with retry capability
        """
        activity.logger.info("Attempting SMTP delivery")
        
        start_time = datetime.now()
        
        try:
            # Check if SMTP is configured
            if not settings.SMTP_USERNAME or not settings.SMTP_PASSWORD:
                activity.logger.warning("SMTP credentials not configured, cannot send email")
                return {
                    "success": False,
                    "provider": "smtp",
                    "delivery_time_ms": int((datetime.now() - start_time).total_seconds() * 1000),
                    "error_message": "SMTP credentials not configured",
                    "attempts": 1,
                    "fallback_used": False
                }
            
            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = email_request["subject"]
            message["From"] = f"{settings.EMAIL_FROM_NAME} <{settings.EMAIL_FROM}>"
            message["To"] = email_request["to_email"]
            
            # Add text and HTML parts
            if email_request.get("text_content"):
                text_part = MIMEText(email_request["text_content"], "plain")
                message.attach(text_part)
            
            if email_request.get("html_content"):
                html_part = MIMEText(email_request["html_content"], "html")
                message.attach(html_part)
            
            # Send via SMTP
            await aiosmtplib.send(
                message,
                hostname=settings.SMTP_SERVER,
                port=settings.SMTP_PORT,
                start_tls=True,
                username=settings.SMTP_USERNAME,
                password=settings.SMTP_PASSWORD,
                timeout=30
            )
            
            delivery_time = int((datetime.now() - start_time).total_seconds() * 1000)
            
            activity.logger.info("SMTP email delivered delivery_time_ms=%s", delivery_time)
            
            return {
                "success": True,
                "provider": "smtp",
                "delivery_time_ms": delivery_time,
                "message_id": f"smtp_{int(start_time.timestamp())}",
                "attempts": 1,
                "fallback_used": False
            }
            
        except Exception as exc:
            delivery_time = int((datetime.now() - start_time).total_seconds() * 1000)
            activity.logger.error("SMTP delivery failed exception_type=%s", type(exc).__name__)
            
            return {
                "success": False,
                "provider": "smtp",
                "delivery_time_ms": delivery_time,
                "error_message": "SMTP delivery failed",
                "attempts": 1,
                "fallback_used": False
            }
    
    @activity.defn(name="send_console_email")
    async def send_console_email(self, email_request: Dict[str, Any]) -> Dict[str, Any]:
        """Reject the legacy console fallback because message bodies contain secrets."""
        activity.logger.warning("Console email delivery is disabled for authentication messages")
        return {
            "success": False,
            "provider": "console_disabled",
            "delivery_time_ms": 0,
            "error_message": "Console delivery is disabled",
            "attempts": 0,
            "fallback_used": False,
        }
    
    @activity.defn(name="log_verification_link")
    async def log_verification_link(self, email_request: Dict[str, Any]) -> Dict[str, Any]:
        """Reject the legacy fallback instead of exposing one-time links."""
        activity.logger.warning("Verification-link logging is disabled")
        return {
            "success": False,
            "provider": "verification_log_disabled",
            "delivery_time_ms": 0,
            "error_message": "Verification-link logging is disabled",
            "attempts": 0,
            "fallback_used": False,
        }
    
    @activity.defn(name="check_password_reset_rate_limit")
    async def check_password_reset_rate_limit(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check rate limiting for password reset requests
        """
        email = data["email"]
        ip_address = data.get("ip_address", "unknown")
        
        activity.logger.info("Checking password reset rate limit")
        
        try:
            redis_client = await self._get_redis()
            if not redis_client:
                # No Redis, allow request
                return {"allowed": True}
            
            # Rate limiting keys
            email_key = f"rate_limit:password_reset:email:{email}"
            ip_key = f"rate_limit:password_reset:ip:{ip_address}"
            
            # Check email rate limit (max 3 per hour)
            email_count = await redis_client.get(email_key) or 0
            email_count = int(email_count)
            
            # Check IP rate limit (max 10 per hour)
            ip_count = await redis_client.get(ip_key) or 0
            ip_count = int(ip_count)
            
            if email_count >= 3:
                activity.logger.warning("Email rate limit exceeded attempts=%s", email_count)
                return {
                    "allowed": False,
                    "reason": "email_rate_limit",
                    "retry_after": 3600
                }
            
            if ip_count >= 10:
                activity.logger.warning("IP rate limit exceeded attempts=%s", ip_count)
                return {
                    "allowed": False,
                    "reason": "ip_rate_limit", 
                    "retry_after": 3600
                }
            
            # Increment counters
            await redis_client.setex(email_key, 3600, email_count + 1)
            await redis_client.setex(ip_key, 3600, ip_count + 1)
            
            return {"allowed": True}
            
        except Exception as exc:
            activity.logger.error("Password reset rate limit check failed exception_type=%s", type(exc).__name__)
            # On error, allow the request
            return {"allowed": True}
    
    @activity.defn(name="record_email_metric")
    async def record_email_metric(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Record email delivery metrics for analytics
        """
        activity.logger.info("Recording email metric email_type=%s", data["email_type"])
        
        try:
            redis_client = await self._get_redis()
            if redis_client:
                # Store metric for analytics
                metric_key = f"email_metric:{data['email_type']}:{int(datetime.now().timestamp())}"
                await redis_client.setex(metric_key, 86400 * 7, str(data))  # Keep for 7 days
                
                # Update counters
                counter_key = f"email_counter:{data['email_type']}"
                await redis_client.incr(counter_key)
                
                if data["success"]:
                    success_key = f"email_success:{data['email_type']}"
                    await redis_client.incr(success_key)
            
            return {"recorded": True}
            
        except Exception as exc:
            activity.logger.error("Failed to record email metric exception_type=%s", type(exc).__name__)
            return {"recorded": False, "error": "metric_recording_failed"}
    
    @activity.defn(name="record_security_event")
    async def record_security_event(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Record security-related events for monitoring
        """
        activity.logger.info("Recording security event event_type=%s", data["event_type"])
        
        try:
            redis_client = await self._get_redis()
            if redis_client:
                # Store security event
                event_key = f"security_event:{data['event_type']}:{int(datetime.now().timestamp())}"
                await redis_client.setex(event_key, 86400 * 30, str(data))  # Keep for 30 days
                
                # Add to security events list for monitoring
                await redis_client.lpush("security_events", str(data))
                await redis_client.ltrim("security_events", 0, 999)  # Keep last 1000 events
            
            return {"recorded": True}
            
        except Exception as exc:
            activity.logger.error("Failed to record security event exception_type=%s", type(exc).__name__)
            return {"recorded": False, "error": "security_event_recording_failed"}


# Global instance
email_activities = EmailActivities()