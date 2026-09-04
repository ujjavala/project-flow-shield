"""Focused tests for the current fail-safe Ollama client contract."""

from unittest.mock import AsyncMock, patch

import pytest

from app.services.ollama_ai_service import OllamaAIService


class FakeResponse:
    def __init__(self, status: int, payload: dict | None = None):
        self.status = status
        self._payload = payload or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def json(self):
        return self._payload


class FakeSession:
    def __init__(self, response: FakeResponse | None = None, error: Exception | None = None):
        self.response = response
        self.error = error
        self.requests: list[dict] = []
        self.closed = False

    def post(self, url, **kwargs):
        self.requests.append({"url": url, **kwargs})
        if self.error is not None:
            raise self.error
        return self.response

    async def close(self):
        self.closed = True


def test_service_initialization():
    service = OllamaAIService(host="localhost", port=11434, model="llama3")

    assert service.base_url == "http://localhost:11434"
    assert service.model == "llama3"
    assert service.session is None


@pytest.mark.asyncio
async def test_ensure_session_creation():
    service = OllamaAIService()
    session = AsyncMock()

    with patch("aiohttp.ClientSession", return_value=session) as session_factory:
        await service._ensure_session()

    assert service.session is session
    session_factory.assert_called_once_with()


@pytest.mark.asyncio
async def test_make_request_returns_trimmed_response_and_bounded_options():
    service = OllamaAIService(host="localhost", port=11434, model="llama3")
    session = FakeSession(FakeResponse(200, {"response": "  bounded advice  "}))
    service.session = session

    result = await service._make_request("bounded prompt", max_tokens=500)

    assert result == "bounded advice"
    assert session.requests[0]["url"] == "http://localhost:11434/api/generate"
    assert session.requests[0]["json"]["options"]["num_predict"] == 500
    assert session.requests[0]["json"]["stream"] is False


@pytest.mark.asyncio
async def test_make_request_fails_safe_for_server_and_transport_errors():
    server_failure = OllamaAIService()
    server_failure.session = FakeSession(FakeResponse(503))
    transport_failure = OllamaAIService()
    transport_failure.session = FakeSession(error=OSError("provider unavailable"))

    assert await server_failure._make_request("prompt") == ""
    assert await transport_failure._make_request("prompt") == ""


@pytest.mark.asyncio
async def test_close_releases_session():
    service = OllamaAIService()
    session = FakeSession()
    service.session = session

    await service.close()

    assert session.closed is True
    assert service.session is None
