"""Delivery of authentication emails without writing one-time secrets to logs."""

from __future__ import annotations

import json
import logging
import os
import uuid
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from urllib.parse import urlencode

from app.config import settings

logger = logging.getLogger(__name__)


class EmailDeliveryError(RuntimeError):
    """Raised when an authentication email cannot be delivered."""


class EmailDeliveryService:
    async def send_verification(self, email: str, token: str) -> None:
        query = urlencode({"token": token})
        await self._send(
            email,
            "Verify your email address",
            f"Open {settings.FRONTEND_URL}/verify-email?{query} to verify your account. "
            f"This link expires in {settings.EMAIL_VERIFICATION_EXPIRE_HOURS} hours.",
        )

    async def send_password_reset(self, email: str, token: str) -> None:
        query = urlencode({"token": token})
        await self._send(
            email,
            "Reset your password",
            f"Open {settings.FRONTEND_URL}/reset-password?{query} to reset your password. "
            f"This link expires in {settings.PASSWORD_RESET_EXPIRE_HOURS} hour(s).",
        )

    async def _send(self, recipient: str, subject: str, body: str) -> None:
        mode = settings.EMAIL_DELIVERY_MODE
        if mode == "development_file":
            if settings.ENVIRONMENT not in {"development", "test"}:
                raise EmailDeliveryError("Development mail sink is disabled outside development and test")
            self._write_development_message(recipient, subject, body)
            logger.info("Authentication email written to development mail sink")
            return
        if mode != "smtp":
            raise EmailDeliveryError(f"Unsupported email delivery mode: {mode}")

        import aiosmtplib

        message = MIMEMultipart("alternative")
        message["From"] = f"{settings.EMAIL_FROM_NAME} <{settings.EMAIL_FROM}>"
        message["To"] = recipient
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain", "utf-8"))
        await aiosmtplib.send(
            message,
            hostname=settings.SMTP_SERVER,
            port=settings.SMTP_PORT,
            start_tls=settings.SMTP_START_TLS,
            username=settings.SMTP_USERNAME or None,
            password=settings.SMTP_PASSWORD or None,
        )
        logger.info("Authentication email sent")

    @staticmethod
    def _write_development_message(recipient: str, subject: str, body: str) -> None:
        outbox = Path(settings.DEVELOPMENT_MAILBOX_PATH)
        outbox.mkdir(parents=True, exist_ok=True)
        try:
            outbox.chmod(0o700)
        except OSError:
            pass
        destination = outbox / f"{uuid.uuid4().hex}.json"
        destination.write_text(
            json.dumps({"to": recipient, "subject": subject, "body": body}, indent=2),
            encoding="utf-8",
        )
        try:
            os.chmod(destination, 0o600)
        except OSError:
            pass


email_delivery = EmailDeliveryService()
