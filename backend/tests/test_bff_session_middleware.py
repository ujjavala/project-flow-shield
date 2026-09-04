"""BFF middleware tests for server-side bearer injection and CSRF enforcement."""

from unittest.mock import AsyncMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.middleware.security import BFFSessionMiddleware


def make_request(method="GET", *, headers=None):
    encoded_headers = [(name.lower().encode(), value.encode()) for name, value in (headers or {}).items()]
    return Request(
        {
            "type": "http",
            "method": method,
            "path": "/admin/health",
            "raw_path": b"/admin/health",
            "query_string": b"",
            "headers": encoded_headers,
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "scheme": "http",
        }
    )


@pytest.mark.asyncio
async def test_injects_server_side_bearer_for_valid_browser_session():
    request = make_request(headers={"cookie": "bff_session=browser-session"})
    session = {"access_token": "server-only-access-token"}
    observed = {}

    async def call_next(received):
        observed["authorization"] = received.headers.get("authorization")
        observed["session"] = received.state.bff_session
        return JSONResponse({"ok": True})

    with patch("app.middleware.security.get_bff_session", AsyncMock(return_value=session)):
        response = await BFFSessionMiddleware(app=AsyncMock()).dispatch(request, call_next)

    assert response.status_code == 200
    assert observed == {"authorization": "Bearer server-only-access-token", "session": session}


@pytest.mark.asyncio
async def test_rejects_unsafe_request_when_csrf_is_invalid():
    request = make_request(
        method="POST",
        headers={"cookie": "bff_session=browser-session; csrf_token=cookie-value"},
    )
    call_next = AsyncMock()

    with (
        patch("app.middleware.security.get_bff_session", AsyncMock(return_value={"access_token": "access"})),
        patch("app.middleware.security.valid_csrf", return_value=False),
    ):
        response = await BFFSessionMiddleware(app=AsyncMock()).dispatch(request, call_next)

    assert response.status_code == 403
    call_next.assert_not_awaited()


@pytest.mark.asyncio
async def test_does_not_override_explicit_authorization_header():
    request = make_request(
        headers={
            "cookie": "bff_session=browser-session",
            "authorization": "Bearer explicit-api-token",
        }
    )
    observed = {}

    async def call_next(received):
        observed["authorization"] = received.headers.get("authorization")
        return JSONResponse({"ok": True})

    with patch(
        "app.middleware.security.get_bff_session",
        AsyncMock(return_value={"access_token": "server-only-access-token"}),
    ):
        await BFFSessionMiddleware(app=AsyncMock()).dispatch(request, call_next)

    assert observed["authorization"] == "Bearer explicit-api-token"
