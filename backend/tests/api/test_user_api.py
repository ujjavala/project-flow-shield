import pytest
from httpx import AsyncClient
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
import uuid

from app.main import app
from app.models.user import User, RefreshToken
from app.utils.security import hash_password, create_access_token, create_refresh_token


class TestUserAPI:
    
    @pytest.fixture
    async def client(self):
        async with AsyncClient(app=app, base_url="http://test") as ac:
            yield ac
    
    @pytest.fixture
    def mock_db_session(self):
        mock_session = AsyncMock()
        return mock_session
    
    @pytest.fixture
    def sample_user_data(self):
        return {
            "email": "test@example.com",
            "password": "Password123!",
            "first_name": "John",
            "last_name": "Doe",
            "username": "johndoe"
        }
    
    @pytest.fixture
    def existing_user(self):
        user = User(
            id=str(uuid.uuid4()),
            email="test@example.com",
            username="johndoe",
            hashed_password=hash_password("Password123!"),
            first_name="John",
            last_name="Doe",
            is_active=True,
            is_verified=True
        )
        return user

    @pytest.mark.asyncio
    async def test_register_success(self, client, mock_db_session, sample_user_data):
        """Test successful user registration"""
        
        with patch('app.api.user.get_db') as mock_get_db, \
             patch('app.api.user.get_temporal_client') as mock_temporal_client:
            
            # Mock database
            mock_get_db.return_value = mock_db_session
            
            # Mock no existing user
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = None
            mock_db_session.execute.return_value = mock_result
            
            # Mock temporal client failure to use fallback
            mock_temporal_client.side_effect = Exception("Temporal unavailable")
            
            # Execute request
            response = await client.post("/register", json=sample_user_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["email"] == sample_user_data["email"]
            assert data["method"] == "direct_registration"
            assert "user_id" in data
            
            # Verify database operations
            mock_db_session.add.assert_called_once()
            mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_register_user_already_exists(self, client, mock_db_session, sample_user_data, existing_user):
        """Test registration with existing user"""
        
        with patch('app.api.user.get_db') as mock_get_db:
            
            # Mock database
            mock_get_db.return_value = mock_db_session
            
            # Mock existing user
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = existing_user
            mock_db_session.execute.return_value = mock_result
            
            # Execute request
            response = await client.post("/register", json=sample_user_data)
            
            # Verify response
            assert response.status_code == 400
            assert "already exists" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_register_temporal_workflow_success(self, client, mock_db_session, sample_user_data):
        """Test registration using Temporal workflow"""
        
        with patch('app.api.user.get_db') as mock_get_db, \
             patch('app.api.user.get_temporal_client') as mock_temporal_client:
            
            # Mock database
            mock_get_db.return_value = mock_db_session
            
            # Mock no existing user
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = None
            mock_db_session.execute.return_value = mock_result
            
            # Mock temporal workflow success
            mock_client = AsyncMock()
            mock_workflow_result = {
                "success": True,
                "user_id": "user-123",
                "email": sample_user_data["email"],
                "message": "Registration successful",
                "verification_email_sent": True
            }
            mock_client.execute_workflow.return_value = mock_workflow_result
            mock_temporal_client.return_value = mock_client
            
            # Execute request
            response = await client.post("/register", json=sample_user_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["method"] == "temporal_workflow"
            assert data["verification_email_sent"] is True
    
    @pytest.mark.asyncio
    async def test_login_success(self, client, mock_db_session, existing_user):
        """Test successful user login"""
        
        with patch('app.api.user.get_db') as mock_get_db, \
             patch('app.api.user.get_temporal_client') as mock_temporal_client:
            
            # Mock database
            mock_get_db.return_value = mock_db_session
            
            # Mock temporal client failure to use fallback
            mock_temporal_client.side_effect = Exception("Temporal unavailable")
            
            # Mock user lookup
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = existing_user
            mock_db_session.execute.return_value = mock_result
            
            # Execute request
            login_data = {
                "email": "test@example.com",
                "password": "Password123!"
            }
            response = await client.post("/login", json=login_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert "refresh_token" in data
            assert data["token_type"] == "bearer"
            assert "expires_in" in data
            
            # Verify database operations
            mock_db_session.add.assert_called_once()  # refresh token
            mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, client, mock_db_session):
        """Test login with invalid credentials"""
        
        with patch('app.api.user.get_db') as mock_get_db, \
             patch('app.api.user.get_temporal_client') as mock_temporal_client:
            
            # Mock database
            mock_get_db.return_value = mock_db_session
            
            # Mock temporal client failure to use fallback
            mock_temporal_client.side_effect = Exception("Temporal unavailable")
            
            # Mock no user found
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = None
            mock_db_session.execute.return_value = mock_result
            
            # Execute request
            login_data = {
                "email": "nonexistent@example.com",
                "password": "wrongpassword"
            }
            response = await client.post("/login", json=login_data)
            
            # Verify response
            assert response.status_code == 401
            assert "Invalid email or password" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_login_inactive_user(self, client, mock_db_session, existing_user):
        """Test login with inactive user"""
        
        existing_user.is_active = False
        
        with patch('app.api.user.get_db') as mock_get_db, \
             patch('app.api.user.get_temporal_client') as mock_temporal_client:
            
            # Mock database
            mock_get_db.return_value = mock_db_session
            
            # Mock temporal client failure to use fallback
            mock_temporal_client.side_effect = Exception("Temporal unavailable")
            
            # Mock inactive user lookup
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = existing_user
            mock_db_session.execute.return_value = mock_result
            
            # Execute request
            login_data = {
                "email": "test@example.com",
                "password": "Password123!"
            }
            response = await client.post("/login", json=login_data)
            
            # Verify response
            assert response.status_code == 401
            assert "Account is deactivated" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_login_temporal_workflow_success(self, client, mock_db_session):
        """Test login using Temporal workflow"""
        
        with patch('app.api.user.get_db') as mock_get_db, \
             patch('app.api.user.get_temporal_client') as mock_temporal_client:
            
            # Mock database
            mock_get_db.return_value = mock_db_session
            
            # Mock temporal workflow success
            mock_client = AsyncMock()
            mock_workflow_result = {
                "success": True,
                "access_token": "access-token",
                "refresh_token": "refresh-token",
                "token_type": "bearer",
                "expires_in": 3600
            }
            mock_client.execute_workflow.return_value = mock_workflow_result
            mock_temporal_client.return_value = mock_client
            
            # Execute request
            login_data = {
                "email": "test@example.com",
                "password": "Password123!"
            }
            response = await client.post("/login", json=login_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert data["access_token"] == "access-token"
            assert data["refresh_token"] == "refresh-token"
    
    @pytest.mark.asyncio
    async def test_refresh_token_success(self, client, mock_db_session, existing_user):
        """Test successful token refresh"""
        
        with patch('app.api.user.get_db') as mock_get_db, \
             patch('app.api.user.verify_token') as mock_verify_token:
            
            # Mock database
            mock_get_db.return_value = mock_db_session
            
            # Mock token verification
            mock_verify_token.return_value = {
                "sub": existing_user.id,
                "type": "refresh"
            }
            
            # Mock refresh token lookup
            refresh_token_record = RefreshToken(
                user_id=existing_user.id,
                token="valid-refresh-token",
                expires_at=datetime.utcnow() + timedelta(days=7),
                is_revoked=False
            )
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = refresh_token_record
            mock_db_session.execute.return_value = mock_result
            
            # Mock user lookup
            mock_db_session.get.return_value = existing_user
            
            # Execute request
            refresh_data = {
                "refresh_token": "valid-refresh-token"
            }
            response = await client.post("/refresh", json=refresh_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert data["refresh_token"] == "valid-refresh-token"
            assert data["token_type"] == "bearer"
    
    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, client, mock_db_session):
        """Test token refresh with invalid token"""
        
        with patch('app.api.user.get_db') as mock_get_db, \
             patch('app.api.user.verify_token') as mock_verify_token:
            
            # Mock database
            mock_get_db.return_value = mock_db_session
            
            # Mock token verification failure
            mock_verify_token.return_value = None
            
            # Execute request
            refresh_data = {
                "refresh_token": "invalid-refresh-token"
            }
            response = await client.post("/refresh", json=refresh_data)
            
            # Verify response
            assert response.status_code == 401
            assert "Invalid refresh token" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_password_reset_request_success(self, client, mock_db_session, existing_user):
        """Test successful password reset request"""
        
        with patch('app.api.user.get_db') as mock_get_db, \
             patch('app.api.user.get_temporal_client') as mock_temporal_client:
            
            # Mock database
            mock_get_db.return_value = mock_db_session
            
            # Mock temporal client failure to use fallback
            mock_temporal_client.side_effect = Exception("Temporal unavailable")
            
            # Mock user lookup
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = existing_user
            mock_db_session.execute.return_value = mock_result
            
            # Execute request
            reset_data = {
                "email": "test@example.com"
            }
            response = await client.post("/password-reset/request", json=reset_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert "password reset link has been sent" in data["message"]
            assert data["method"] == "direct_method"
            
            # Verify database operations
            mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_password_reset_confirm_success(self, client, mock_db_session, existing_user):
        """Test successful password reset confirmation"""
        
        existing_user.password_reset_token = "valid-reset-token"
        existing_user.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
        
        with patch('app.api.user.get_db') as mock_get_db, \
             patch('app.api.user.get_temporal_client') as mock_temporal_client:
            
            # Mock database
            mock_get_db.return_value = mock_db_session
            
            # Mock temporal client failure to use fallback
            mock_temporal_client.side_effect = Exception("Temporal unavailable")
            
            # Mock user lookup by reset token
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = existing_user
            mock_db_session.execute.return_value = mock_result
            
            # Execute request
            reset_data = {
                "token": "valid-reset-token",
                "new_password": "NewPassword123!"
            }
            response = await client.post("/password-reset/confirm", json=reset_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert "Password has been reset successfully" in data["message"]
            assert data["method"] == "direct_method"
            
            # Verify database operations
            mock_db_session.commit.assert_called_once()
            
            # Verify token is cleared
            assert existing_user.password_reset_token is None
            assert existing_user.password_reset_expires is None
    
    @pytest.mark.asyncio
    async def test_password_reset_confirm_invalid_token(self, client, mock_db_session):
        """Test password reset confirmation with invalid token"""
        
        with patch('app.api.user.get_db') as mock_get_db, \
             patch('app.api.user.get_temporal_client') as mock_temporal_client:
            
            # Mock database
            mock_get_db.return_value = mock_db_session
            
            # Mock temporal client failure to use fallback
            mock_temporal_client.side_effect = Exception("Temporal unavailable")
            
            # Mock no user found with reset token
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = None
            mock_db_session.execute.return_value = mock_result
            
            # Execute request
            reset_data = {
                "token": "invalid-reset-token",
                "new_password": "NewPassword123!"
            }
            response = await client.post("/password-reset/confirm", json=reset_data)
            
            # Verify response
            assert response.status_code == 400
            assert "Invalid or expired reset token" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_verify_email_success(self, client, mock_db_session, existing_user):
        """Test successful email verification"""
        
        existing_user.is_verified = False
        existing_user.email_verification_token = "valid-verification-token"
        
        with patch('app.api.user.get_db') as mock_get_db, \
             patch('app.api.user.get_temporal_client') as mock_temporal_client:
            
            # Mock database
            mock_get_db.return_value = mock_db_session
            
            # Mock temporal client failure to use fallback
            mock_temporal_client.side_effect = Exception("Temporal unavailable")
            
            # Mock user lookup by verification token
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = existing_user
            mock_db_session.execute.return_value = mock_result
            
            # Execute request
            verification_data = {
                "token": "valid-verification-token"
            }
            response = await client.post("/verify-email", json=verification_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert "Email verified successfully" in data["message"]
            assert data["method"] == "direct_verification"
            
            # Verify user is marked as verified
            assert existing_user.is_verified is True
            assert existing_user.email_verification_token is None
    
    @pytest.mark.asyncio
    async def test_verify_email_already_verified(self, client, mock_db_session, existing_user):
        """Test email verification for already verified user"""
        
        existing_user.is_verified = True
        existing_user.email_verification_token = "verification-token"
        
        with patch('app.api.user.get_db') as mock_get_db, \
             patch('app.api.user.get_temporal_client') as mock_temporal_client:
            
            # Mock database
            mock_get_db.return_value = mock_db_session
            
            # Mock temporal client failure to use fallback
            mock_temporal_client.side_effect = Exception("Temporal unavailable")
            
            # Mock user lookup
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = existing_user
            mock_db_session.execute.return_value = mock_result
            
            # Execute request
            verification_data = {
                "token": "verification-token"
            }
            response = await client.post("/verify-email", json=verification_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert "Email already verified" in data["message"]
    
    @pytest.mark.asyncio
    async def test_logout_success(self, client, mock_db_session):
        """Test successful logout"""
        
        refresh_token_record = RefreshToken(
            user_id="user-123",
            token="valid-refresh-token",
            expires_at=datetime.utcnow() + timedelta(days=7),
            is_revoked=False
        )
        
        with patch('app.api.user.get_db') as mock_get_db:
            
            # Mock database
            mock_get_db.return_value = mock_db_session
            
            # Mock refresh token lookup
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = refresh_token_record
            mock_db_session.execute.return_value = mock_result
            
            # Execute request
            logout_data = {
                "refresh_token": "valid-refresh-token"
            }
            response = await client.post("/logout", json=logout_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert "Logged out successfully" in data["message"]
            
            # Verify token is revoked
            assert refresh_token_record.is_revoked is True
            mock_db_session.commit.assert_called_once()