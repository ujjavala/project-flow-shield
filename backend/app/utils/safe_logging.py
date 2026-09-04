"""Central logging configuration with bounded, one-line sensitive-data redaction."""

from __future__ import annotations

import logging
import re
import sys


MAX_LOG_TEXT_LENGTH = 8192

_REDACTIONS = (
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"), "[REDACTED_EMAIL]"),
    (
        re.compile(
            r"(?i)([\"']?(?:password|passwd|secret|client_secret|access_token|refresh_token|"
            r"api_key|authorization|cookie|set-cookie|csrf_token|bff_session|challenge_token|"
            r"verification_token|reset_token)[\"']?\s*[:=]\s*)"
            r"(?:\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)"
        ),
        r"\1[REDACTED]",
    ),
)


def sanitize_log_text(value: object) -> str:
    """Return a one-line representation with common credentials and PII removed."""
    text = str(value).replace("\r", "\\r").replace("\n", "\\n")
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    if len(text) > MAX_LOG_TEXT_LENGTH:
        text = f"{text[:MAX_LOG_TEXT_LENGTH]}...[TRUNCATED]"
    return text


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return sanitize_log_text(super().format(record))


def configure_safe_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        RedactingFormatter(
            "%(asctime)s level=%(levelname)s logger=%(name)s message=%(message)s"
        )
    )
    logging.basicConfig(level=level, handlers=[handler], force=True)
