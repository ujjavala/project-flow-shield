import pytest
from unittest.mock import AsyncMock, patch
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from app.temporal.workflows.user_login import UserLoginWorkflow
from app.temporal.types import LoginRequest
from app.temporal.activities.auth import AuthActivities


class TestUserLoginWorkflow:
    
    @pytest.fixture
    async def workflow_environment(self):
        async with WorkflowEnvironment.start_time_skipping() as env:
            yield env
    
    @pytest.fixture
    def login_request(self):
        return LoginRequest(
            email="test@example.com",
            password="password123"
        )
    
    @pytest.mark.asyncio
    async def test_successful_login_workflow(self, workflow_environment, login_request):
        """Test successful login workflow execution"""
        
        # Mock activity results
        auth_result = {
            "success": True,
            "user_id": "user-123",
            "email": "test@example.com",
            "is_verified": True
        }
        
        token_result = {
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expires_in": 3600
        }
        
        storage_result = {
            "success": True,
            "last_login": "2023-01-01T00:00:00"
        }
        
        # Create worker with mocked activities
        async with Worker(
            workflow_environment.client,
            task_queue="test-task-queue",
            workflows=[UserLoginWorkflow],
            activities=[
                AsyncMock(return_value=auth_result, spec_set=True, name="authenticate_user"),
                AsyncMock(return_value=token_result, spec_set=True, name="create_login_tokens"),
                AsyncMock(return_value=storage_result, spec_set=True, name="store_login_session"),
            ],
        ):
            # Execute workflow
            result = await workflow_environment.client.execute_workflow(
                UserLoginWorkflow.run,
                login_request,
                id="test-workflow-id",
                task_queue="test-task-queue",
            )
            
            # Verify result
            assert result["success"] is True
            assert result["access_token"] == "access-token"
            assert result["refresh_token"] == "refresh-token"
            assert result["token_type"] == "bearer"
            assert result["expires_in"] == 3600
            assert result["user_id"] == "user-123"
            assert result["email"] == "test@example.com"
            assert result["method"] == "temporal_workflow"
    
    @pytest.mark.asyncio
    async def test_failed_authentication_workflow(self, workflow_environment, login_request):
        """Test workflow with failed authentication"""
        
        # Mock failed authentication
        auth_result = {
            "success": False,
            "error": "Invalid credentials"
        }
        
        async with Worker(
            workflow_environment.client,
            task_queue="test-task-queue",
            workflows=[UserLoginWorkflow],
            activities=[
                AsyncMock(return_value=auth_result, spec_set=True, name="authenticate_user"),
            ],
        ):
            # Execute workflow
            result = await workflow_environment.client.execute_workflow(
                UserLoginWorkflow.run,
                login_request,
                id="test-workflow-id",
                task_queue="test-task-queue",
            )
            
            # Verify result
            assert result["success"] is False
            assert result["error"] == "Invalid credentials"
            assert result["method"] == "temporal_workflow"
    
    @pytest.mark.asyncio
    async def test_workflow_with_activity_exception(self, workflow_environment, login_request):
        """Test workflow handling of activity exceptions"""
        
        async with Worker(
            workflow_environment.client,
            task_queue="test-task-queue",
            workflows=[UserLoginWorkflow],
            activities=[
                AsyncMock(side_effect=Exception("Database error"), spec_set=True, name="authenticate_user"),
            ],
        ):
            # Execute workflow
            result = await workflow_environment.client.execute_workflow(
                UserLoginWorkflow.run,
                login_request,
                id="test-workflow-id",
                task_queue="test-task-queue",
            )
            
            # Verify error handling
            assert result["success"] is False
            assert "Login workflow failed" in result["error"]
            assert result["method"] == "temporal_workflow"
    
    @pytest.mark.asyncio
    async def test_token_creation_failure(self, workflow_environment, login_request):
        """Test workflow when token creation fails"""
        
        auth_result = {
            "success": True,
            "user_id": "user-123",
            "email": "test@example.com",
            "is_verified": True
        }
        
        async with Worker(
            workflow_environment.client,
            task_queue="test-task-queue",
            workflows=[UserLoginWorkflow],
            activities=[
                AsyncMock(return_value=auth_result, spec_set=True, name="authenticate_user"),
                AsyncMock(side_effect=Exception("Token creation failed"), spec_set=True, name="create_login_tokens"),
            ],
        ):
            # Execute workflow
            result = await workflow_environment.client.execute_workflow(
                UserLoginWorkflow.run,
                login_request,
                id="test-workflow-id",
                task_queue="test-task-queue",
            )
            
            # Verify error handling
            assert result["success"] is False
            assert "Login workflow failed" in result["error"]
    
    @pytest.mark.asyncio
    async def test_session_storage_failure(self, workflow_environment, login_request):
        """Test workflow when session storage fails"""
        
        auth_result = {
            "success": True,
            "user_id": "user-123",
            "email": "test@example.com",
            "is_verified": True
        }
        
        token_result = {
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expires_in": 3600
        }
        
        async with Worker(
            workflow_environment.client,
            task_queue="test-task-queue",
            workflows=[UserLoginWorkflow],
            activities=[
                AsyncMock(return_value=auth_result, spec_set=True, name="authenticate_user"),
                AsyncMock(return_value=token_result, spec_set=True, name="create_login_tokens"),
                AsyncMock(side_effect=Exception("Storage failed"), spec_set=True, name="store_login_session"),
            ],
        ):
            # Execute workflow
            result = await workflow_environment.client.execute_workflow(
                UserLoginWorkflow.run,
                login_request,
                id="test-workflow-id",
                task_queue="test-task-queue",
            )
            
            # Verify error handling
            assert result["success"] is False
            assert "Login workflow failed" in result["error"]