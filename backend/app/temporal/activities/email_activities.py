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
            except Exception as e:
                logger.warning(f"Email Redis connection failed: {e}")
                self.redis_client = None
        return self.redis_client
    
    @activity.defn(name="send_smtp_email")
    async def send_smtp_email(self, email_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send email via SMTP with retry capability
        """
        activity.logger.info(f"Attempting SMTP delivery to {email_request['to_email']}")
        
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
            
            activity.logger.info(f"SMTP email delivered successfully to {email_request['to_email']} in {delivery_time}ms")
            
            return {
                "success": True,
                "provider": "smtp",
                "delivery_time_ms": delivery_time,
                "message_id": f"smtp_{int(start_time.timestamp())}",
                "attempts": 1,
                "fallback_used": False
            }
            
        except Exception as e:
            delivery_time = int((datetime.now() - start_time).total_seconds() * 1000)
            error_msg = str(e)
            
            activity.logger.error(f"SMTP delivery failed for {email_request['to_email']}: {error_msg}")
            
            return {
                "success": False,
                "provider": "smtp",
                "delivery_time_ms": delivery_time,
                "error_message": error_msg,
                "attempts": 1,
                "fallback_used": False
            }
    
    @activity.defn(name="send_console_email")
    async def send_console_email(self, email_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fallback email delivery via console/log output
        """
        activity.logger.info(f"Delivering email to console for {email_request['to_email']}")
        
        start_time = datetime.now()
        
        try:
            # Create a nicely formatted console output
            email_output = f"""
{'='*80}
📧 EMAIL DELIVERY (Console Fallback)
{'='*80}
To: {email_request['to_email']}
Subject: {email_request['subject']}
Priority: {email_request.get('priority', 'normal')}
Template: {email_request.get('template_name', 'generic')}
Correlation ID: {email_request.get('correlation_id', 'N/A')}
Timestamp: {datetime.now().isoformat()}
{'='*80}

{email_request.get('text_content', email_request.get('html_content', 'No content'))}

{'='*80}
✅ Email delivered via console fallback
{'='*80}
            """
            
            # Output to both logger and console
            activity.logger.info(email_output)
            print(email_output)  # Also print to console for development
            
            # Store in Redis for dashboard viewing if available
            redis_client = await self._get_redis()
            if redis_client:
                email_key = f"console_email:{email_request['to_email']}:{int(start_time.timestamp())}"
                email_data = {
                    "to_email": email_request["to_email"],
                    "subject": email_request["subject"],
                    "content": email_request.get("text_content", email_request.get("html_content", "")),
                    "delivered_at": datetime.now().isoformat(),
                    "method": "console"
                }
                await redis_client.setex(email_key, 86400, str(email_data))  # Keep for 24 hours
            
            delivery_time = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return {
                "success": True,
                "provider": "console",
                "delivery_time_ms": delivery_time,
                "message_id": f"console_{int(start_time.timestamp())}",
                "attempts": 1,
                "fallback_used": True
            }
            
        except Exception as e:
            activity.logger.error(f"Console delivery failed: {e}")
            return {
                "success": False,
                "provider": "console",
                "delivery_time_ms": int((datetime.now() - start_time).total_seconds() * 1000),
                "error_message": str(e),
                "attempts": 1,
                "fallback_used": True
            }
    
    @activity.defn(name="log_verification_link")
    async def log_verification_link(self, email_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Final fallback - extract and log verification link for manual use
        """
        activity.logger.info(f"Logging verification link for {email_request['to_email']}")
        
        start_time = datetime.now()
        
        try:
            # Extract verification link from content
            content = email_request.get("text_content", email_request.get("html_content", ""))
            
            # Try to find verification link
            verification_link = None
            if "verify-email?token=" in content:
                # Extract the link
                lines = content.split('\n')
                for line in lines:
                    if "verify-email?token=" in line:
                        # Extract URL from HTML or text
                        if "href=" in line:
                            start = line.find('"') + 1
                            end = line.find('"', start)
                            verification_link = line[start:end]
                        else:
                            verification_link = line.strip()
                        break
            
            if "reset-password?token=" in content:
                # Extract password reset link
                lines = content.split('\n')
                for line in lines:
                    if "reset-password?token=" in line:
                        # Extract URL from HTML or text
                        if "href=" in line:
                            start = line.find('"') + 1
                            end = line.find('"', start)
                            verification_link = line[start:end]
                        else:
                            verification_link = line.strip()
                        break
            
            # Log the verification link prominently
            if verification_link:
                verification_output = f"""
🔗 VERIFICATION LINK FOR {email_request['to_email']}:
{verification_link}
⏰ Link expires in 24 hours (for verification) or 1 hour (for password reset)
📧 Email subject: {email_request['subject']}
"""
                activity.logger.info(verification_output)
                print(verification_output)  # Also print to console
                
                # Store in Redis for easy access
                redis_client = await self._get_redis()
                if redis_client:
                    link_key = f"verification_link:{email_request['to_email']}"
                    link_data = {
                        "email": email_request["to_email"],
                        "link": verification_link,
                        "subject": email_request["subject"],
                        "created_at": datetime.now().isoformat()
                    }
                    await redis_client.setex(link_key, 86400, str(link_data))  # Keep for 24 hours
            
            delivery_time = int((datetime.now() - start_time).total_seconds() * 1000)
            
            return {
                "success": True,
                "provider": "verification_log",
                "delivery_time_ms": delivery_time,
                "message_id": f"log_{int(start_time.timestamp())}",
                "verification_link": verification_link,
                "attempts": 1,
                "fallback_used": True
            }
            
        except Exception as e:
            activity.logger.error(f"Verification link logging failed: {e}")
            return {
                "success": False,
                "provider": "verification_log",
                "delivery_time_ms": int((datetime.now() - start_time).total_seconds() * 1000),
                "error_message": str(e),
                "attempts": 1,
                "fallback_used": True
            }
    
    @activity.defn(name="check_password_reset_rate_limit")
    async def check_password_reset_rate_limit(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check rate limiting for password reset requests
        """
        email = data["email"]
        ip_address = data.get("ip_address", "unknown")
        
        activity.logger.info(f"Checking password reset rate limit for {email} from {ip_address}")
        
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
                activity.logger.warning(f"Email rate limit exceeded for {email}: {email_count} attempts")
                return {
                    "allowed": False,
                    "reason": "email_rate_limit",
                    "retry_after": 3600
                }
            
            if ip_count >= 10:
                activity.logger.warning(f"IP rate limit exceeded for {ip_address}: {ip_count} attempts")
                return {
                    "allowed": False,
                    "reason": "ip_rate_limit", 
                    "retry_after": 3600
                }
            
            # Increment counters
            await redis_client.setex(email_key, 3600, email_count + 1)
            await redis_client.setex(ip_key, 3600, ip_count + 1)
            
            return {"allowed": True}
            
        except Exception as e:
            activity.logger.error(f"Rate limit check failed: {e}")
            # On error, allow the request
            return {"allowed": True}
    
    @activity.defn(name="record_email_metric")
    async def record_email_metric(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Record email delivery metrics for analytics
        """
        activity.logger.info(f"Recording email metric: {data['email_type']} to {data['recipient']}")
        
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
            
        except Exception as e:
            activity.logger.error(f"Failed to record email metric: {e}")
            return {"recorded": False, "error": str(e)}
    
    @activity.defn(name="record_security_event")
    async def record_security_event(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Record security-related events for monitoring
        """
        activity.logger.info(f"Recording security event: {data['event_type']} for {data['email']}")
        
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
            
        except Exception as e:
            activity.logger.error(f"Failed to record security event: {e}")
            return {"recorded": False, "error": str(e)}


# Global instance
email_activities = EmailActivities()