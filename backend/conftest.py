"""
Pytest configuration and fixtures for Temporal PKCE tests
Special test environment setup for Temporal workflows
"""
import pytest
import asyncio
import os
from datetime import timedelta
from typing import AsyncGenerator, Dict, Any

# Set test environment variables
os.environ["PYTEST_CURRENT_TEST"] = "True"
os.environ["TEMPORAL_TEST_MODE"] = "True"

try:
    from temporalio.testing import WorkflowEnvironment
    from temporalio.worker import Worker
    from temporalio.client import Client
    TEMPORAL_AVAILABLE = True
except ImportError:
    TEMPORAL_AVAILABLE = False

from app.models.pkce import PKCEUtils


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def temporal_env() -> AsyncGenerator[Any, None]:
    """
    Fixture for Temporal test environment
    Creates isolated test environment for workflow execution
    """
    if not TEMPORAL_AVAILABLE:
        pytest.skip("Temporal not available for testing")
    
    env = await WorkflowEnvironment.start_time_skipping()
    try:
        yield env
    finally:
        await env.shutdown()


@pytest.fixture
async def temporal_client(temporal_env) -> Client:
    """Fixture for Temporal test client"""
    return temporal_env.client


@pytest.fixture
def test_task_queue() -> str:
    """Task queue name for tests"""
    return "test-pkce-queue"


@pytest.fixture
async def pkce_worker(temporal_env, temporal_client, test_task_queue) -> AsyncGenerator[Worker, None]:
    """
    Fixture for Temporal worker with PKCE workflows and test activities
    """
    if not TEMPORAL_AVAILABLE:
        pytest.skip("Temporal not available for testing")
    
    # Import here to avoid import errors when Temporal is not available
    from app.temporal.workflows.pkce_authorization import (
        PKCEAuthorizationWorkflow,
        PKCETokenExchangeWorkflow,
        PKCEWorkflowOrchestrator
    )
    from app.temporal.activities.test_pkce_activities import get_test_activities
    
    worker = Worker(
        temporal_client,
        task_queue=test_task_queue,
        workflows=[
            PKCEAuthorizationWorkflow,
            PKCETokenExchangeWorkflow,
            PKCEWorkflowOrchestrator
        ],
        activities=get_test_activities()
    )
    
    async with worker:
        # Give worker a moment to start up
        await asyncio.sleep(0.1)
        yield worker


@pytest.fixture
def sample_pkce_request() -> Dict[str, Any]:
    """Sample PKCE request for testing"""
    code_verifier = "a" * 43  # Valid 43-character verifier
    code_challenge = PKCEUtils.generate_code_challenge(code_verifier, "S256")
    
    return {
        "client_id": "test-client",
        "redirect_uri": "http://localhost:3000/callback",
        "scope": "read write",
        "state": "test-state-123",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "response_type": "code"
    }


@pytest.fixture
def sample_token_request() -> Dict[str, Any]:
    """Sample token request for testing"""
    return {
        "grant_type": "authorization_code",
        "code": "test-auth-code",
        "redirect_uri": "http://localhost:3000/callback", 
        "client_id": "test-client",
        "code_verifier": "a" * 43  # Valid 43-character verifier
    }


@pytest.fixture
def invalid_pkce_request() -> Dict[str, Any]:
    """Invalid PKCE request for error testing"""
    return {
        "client_id": "invalid-client",  # Will trigger validation failure
        "redirect_uri": "http://localhost:3000/callback",
        "scope": "read write",
        "state": "invalid-test-state",
        "code_challenge": PKCEUtils.generate_code_challenge("a" * 43, "S256"),
        "code_challenge_method": "S256",
        "response_type": "code"
    }


@pytest.fixture
def workflow_timeout() -> timedelta:
    """Default timeout for workflow execution in tests"""
    return timedelta(seconds=30)


# Pytest markers for different test categories
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.temporal
]


def pytest_configure(config):
    """Configure pytest with custom settings"""
    config.addinivalue_line("markers", "temporal: Temporal workflow tests")
    config.addinivalue_line("markers", "pkce: PKCE-specific tests") 
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "unit: Unit tests")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically"""
    for item in items:
        # Mark temporal workflow tests
        if "temporal" in item.fspath.basename:
            item.add_marker(pytest.mark.temporal)
        
        # Mark PKCE tests
        if "pkce" in item.fspath.basename:
            item.add_marker(pytest.mark.pkce)
        
        # Mark async tests
        if asyncio.iscoroutinefunction(item.function):
            item.add_marker(pytest.mark.asyncio)


@pytest.fixture(autouse=True)
def setup_test_environment():
    """Automatically setup test environment for all tests"""
    # Set environment variables for testing
    os.environ["TESTING"] = "True"
    os.environ["LOG_LEVEL"] = "INFO"
    
    yield
    
    # Cleanup after test
    if "TESTING" in os.environ:
        del os.environ["TESTING"]


# Skip temporal tests if Temporal is not available
def pytest_runtest_setup(item):
    """Setup for individual test runs"""
    if "temporal" in item.keywords and not TEMPORAL_AVAILABLE:
        pytest.skip("Temporal SDK not available")