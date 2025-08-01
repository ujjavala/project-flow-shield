from temporalio import activity
from dataclasses import dataclass
from typing import Optional
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from jinja2 import Template

from app.config import settings

logger = logging.getLogger(__name__)

@dataclass
class EmailData:
    to: str
    subject: str
    template_name: str
    context: dict
    from_email: Optional[str] = None
    from_name: Optional[str] = None

class EmailActivities:
    
    def __init__(self):
        self.smtp_server = settings.SMTP_SERVER
        self.smtp_port = settings.SMTP_PORT
        self.smtp_username = settings.SMTP_USERNAME
        self.smtp_password = settings.SMTP_PASSWORD
        self.from_email = settings.EMAIL_FROM
        self.from_name = settings.EMAIL_FROM_NAME
    
    @activity.defn(name="send_verification_email")
    async def send_verification_email(self, email: str, verification_token: str, user_name: str = None) -> bool:
        """Send email verification email"""
        try:
            verification_url = f"{settings.FRONTEND_URL}/verify-email?token={verification_token}"
            
            context = {
                "user_name": user_name or email.split("@")[0],
                "verification_url": verification_url,
                "frontend_url": settings.FRONTEND_URL
            }
            
            email_data = EmailData(
                to=email,
                subject="Verify Your Email Address",
                template_name="email_verification",
                context=context
            )
            
            return await self._send_email(email_data)
            
        except Exception as e:
            logger.error(f"Failed to send verification email to {email}: {e}")
            return False
    
    @activity.defn(name="send_password_reset_email")
    async def send_password_reset_email(self, email: str, reset_token: str, user_name: str = None) -> bool:
        """Send password reset email"""
        try:
            reset_url = f"{settings.FRONTEND_URL}/reset-password?token={reset_token}"
            
            context = {
                "user_name": user_name or email.split("@")[0],
                "reset_url": reset_url,
                "frontend_url": settings.FRONTEND_URL,
                "expire_hours": settings.PASSWORD_RESET_EXPIRE_HOURS
            }
            
            email_data = EmailData(
                to=email,
                subject="Reset Your Password",
                template_name="password_reset",
                context=context
            )
            
            return await self._send_email(email_data)
            
        except Exception as e:
            logger.error(f"Failed to send password reset email to {email}: {e}")
            return False
    
    @activity.defn(name="send_welcome_email")
    async def send_welcome_email(self, email: str, user_name: str = None) -> bool:
        """Send welcome email after successful registration"""
        try:
            context = {
                "user_name": user_name or email.split("@")[0],
                "frontend_url": settings.FRONTEND_URL,
                "login_url": f"{settings.FRONTEND_URL}/login"
            }
            
            email_data = EmailData(
                to=email,
                subject="Welcome to OAuth2 Auth Service!",
                template_name="welcome",
                context=context
            )
            
            return await self._send_email(email_data)
            
        except Exception as e:
            logger.error(f"Failed to send welcome email to {email}: {e}")
            return False
    
    async def _send_email(self, email_data: EmailData) -> bool:
        """Send email using SMTP"""
        try:
            # Create message
            message = MIMEMultipart("alternative")
            message["From"] = f"{self.from_name} <{self.from_email}>"
            message["To"] = email_data.to
            message["Subject"] = email_data.subject
            
            # Generate HTML content from template
            html_content = self._render_template(email_data.template_name, email_data.context)
            
            # Create HTML part
            html_part = MIMEText(html_content, "html")
            message.attach(html_part)
            
            # Send email
            await aiosmtplib.send(
                message,
                hostname=self.smtp_server,
                port=self.smtp_port,
                start_tls=True,
                username=self.smtp_username,
                password=self.smtp_password
            )
            
            logger.info(f"Email sent successfully to {email_data.to}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {email_data.to}: {e}")
            return False
    
    def _render_template(self, template_name: str, context: dict) -> str:
        """Render email template"""
        templates = {
            "email_verification": """
            <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333;">Verify Your Email Address</h2>
                <p>Hello {{ user_name }},</p>
                <p>Thank you for registering with OAuth2 Auth Service. Please click the button below to verify your email address:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{{ verification_url }}" style="background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Verify Email</a>
                </div>
                <p>If you didn't create an account, you can safely ignore this email.</p>
                <p>This verification link will expire in 24 hours.</p>
                <hr>
                <p style="color: #666; font-size: 12px;">OAuth2 Auth Service</p>
            </body>
            </html>
            """,
            "password_reset": """
            <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333;">Reset Your Password</h2>
                <p>Hello {{ user_name }},</p>
                <p>We received a request to reset your password. Click the button below to reset it:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{{ reset_url }}" style="background-color: #dc3545; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Reset Password</a>
                </div>
                <p>If you didn't request a password reset, you can safely ignore this email.</p>
                <p>This reset link will expire in {{ expire_hours }} hour(s).</p>
                <hr>
                <p style="color: #666; font-size: 12px;">OAuth2 Auth Service</p>
            </body>
            </html>
            """,
            "welcome": """
            <html>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #333;">Welcome to OAuth2 Auth Service!</h2>
                <p>Hello {{ user_name }},</p>
                <p>Your account has been successfully created and verified. You can now log in to your account:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{{ login_url }}" style="background-color: #28a745; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">Login to Your Account</a>
                </div>
                <p>Thank you for joining us!</p>
                <hr>
                <p style="color: #666; font-size: 12px;">OAuth2 Auth Service</p>
            </body>
            </html>
            """
        }
        
        template = Template(templates.get(template_name, ""))
        return template.render(**context)