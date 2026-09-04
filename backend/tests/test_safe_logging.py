"""Tests that operational logs cannot emit common credentials or direct identifiers."""

import logging

from app.utils.safe_logging import MAX_LOG_TEXT_LENGTH, RedactingFormatter, sanitize_log_text


def test_sanitize_log_text_redacts_credentials_email_and_log_forging():
    raw = (
        "email=person@example.test password=hunter2 "
        "Authorization: Bearer abc.def.ghi\nlevel=CRITICAL forged=true"
    )

    sanitized = sanitize_log_text(raw)

    assert "person@example.test" not in sanitized
    assert "hunter2" not in sanitized
    assert "abc.def.ghi" not in sanitized
    assert "\n" not in sanitized
    assert "\\nlevel=CRITICAL" in sanitized
    assert sanitized.count("[REDACTED]") >= 2


def test_formatter_redacts_exception_messages():
    formatter = RedactingFormatter("%(levelname)s %(message)s")
    try:
        raise RuntimeError("refresh_token=canary-refresh person@example.test")
    except RuntimeError:
        record = logging.getLogger("test").makeRecord(
            "test",
            logging.ERROR,
            __file__,
            1,
            "operation failed",
            (),
            __import__("sys").exc_info(),
        )

    formatted = formatter.format(record)

    assert "canary-refresh" not in formatted
    assert "person@example.test" not in formatted
    assert "[REDACTED]" in formatted


def test_sanitize_log_text_redacts_quoted_structured_credentials_and_cookies():
    raw = (
        '{"password": "secret with spaces", "challenge_token": "challenge-value", '
        '"cookie": "bff_session=browser-secret; csrf_token=csrf-secret"}'
    )

    sanitized = sanitize_log_text(raw)

    for secret in ("secret with spaces", "challenge-value", "browser-secret", "csrf-secret"):
        assert secret not in sanitized


def test_sanitize_log_text_bounds_untrusted_values():
    sanitized = sanitize_log_text("x" * (MAX_LOG_TEXT_LENGTH + 100))

    assert sanitized.endswith("...[TRUNCATED]")
    assert len(sanitized) == MAX_LOG_TEXT_LENGTH + len("...[TRUNCATED]")
