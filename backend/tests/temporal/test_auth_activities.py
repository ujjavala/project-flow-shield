import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
import secrets

from app.temporal.activities.auth import AuthActivities
from app.config import settings


class TestAuthActivities:
    
    @pytest.fixture
    def auth_activities(self):
        return AuthActivities()
    
    @pytest.mark.asyncio
    async def test_generate_verification_token(self, auth_activities):
        """Test email verification token generation"""
        
        with patch('secrets.token_urlsafe') as mock_token, \
             patch('app.temporal.activities.auth.datetime') as mock_datetime:
            
            # Setup mocks
            mock_token.return_value = "test-token"
            mock_now = datetime(2023, 1, 1, 12, 0, 0)
            mock_datetime.utcnow.return_value = mock_now
            
            # Execute activity
            result = await auth_activities.generate_verification_token()
            
            # Verify result
            assert result["token"] == "test-token"
            expected_expires = mock_now + timedelta(hours=settings.EMAIL_VERIFICATION_EXPIRE_HOURS)
            assert result["expires_at"] == expected_expires.isoformat()
    
    @pytest.mark.asyncio
    async def test_generate_password_reset_token(self, auth_activities):
        """Test password reset token generation"""
        
        with patch('secrets.token_urlsafe') as mock_token, \
             patch('app.temporal.activities.auth.datetime') as mock_datetime:
            
            # Setup mocks
            mock_token.return_value = "reset-token"
            mock_now = datetime(2023, 1, 1, 12, 0, 0)
            mock_datetime.utcnow.return_value = mock_now
            
            # Execute activity
            result = await auth_activities.generate_password_reset_token()
            
            # Verify result
            assert result["token"] == "reset-token"
            expected_expires = mock_now + timedelta(hours=settings.PASSWORD_RESET_EXPIRE_HOURS)
            assert result["expires_at"] == expected_expires.isoformat()
    
    @pytest.mark.asyncio
    async def test_validate_password_reset_token_valid(self, auth_activities):
        """Test validating a valid password reset token"""
        
        mock_user = MagicMock()
        mock_user.password_reset_token = "valid-token"
        mock_user.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
        
        with patch('app.temporal.activities.auth.AsyncSessionLocal') as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session
            
            # Mock query result
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = mock_user
            mock_session.execute.return_value = mock_result
            
            # Execute activity
            result = await auth_activities.validate_password_reset_token("valid-token")
            
            # Verify result
            assert result is True
    
    @pytest.mark.asyncio
    async def test_validate_password_reset_token_invalid(self, auth_activities):
        """Test validating an invalid password reset token"""
        
        with patch('app.temporal.activities.auth.AsyncSessionLocal') as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session
            
            # Mock query result - no user found
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = None
            mock_session.execute.return_value = mock_result
            
            # Execute activity
            result = await auth_activities.validate_password_reset_token("invalid-token")
            
            # Verify result
            assert result is False
    
    @pytest.mark.asyncio
    async def test_validate_password_reset_token_expired(self, auth_activities):
        """Test validating an expired password reset token"""
        
        mock_user = MagicMock()
        mock_user.password_reset_token = "expired-token"
        mock_user.password_reset_expires = datetime.utcnow() - timedelta(hours=1)  # Expired
        
        with patch('app.temporal.activities.auth.AsyncSessionLocal') as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session
            
            # Mock query result
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = mock_user
            mock_session.execute.return_value = mock_result
            
            # Execute activity
            result = await auth_activities.validate_password_reset_token("expired-token")
            
            # Verify result
            assert result is False
    
    @pytest.mark.asyncio
    async def test_authenticate_user_success(self, auth_activities):
        """Test successful user authentication"""
        
        mock_user = MagicMock()
        mock_user.id = "user-123"
        mock_user.email = "test@example.com"
        mock_user.is_active = True
        mock_user.is_verified = True
        mock_user.hashed_password = "hashed-password"
        
        with patch('app.temporal.activities.auth.AsyncSessionLocal') as mock_session_class, \
             patch('app.temporal.activities.auth.verify_password') as mock_verify:
            
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session
            
            # Mock query result
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = mock_user
            mock_session.execute.return_value = mock_result
            
            # Mock password verification
            mock_verify.return_value = True
            
            # Execute activity
            result = await auth_activities.authenticate_user("test@example.com", "password")
            
            # Verify result
            assert result["success"] is True
            assert result["user_id"] == "user-123"
            assert result["email"] == "test@example.com"
            assert result["is_verified"] is True
    
    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self, auth_activities):
        """Test authentication with non-existent user"""
        
        with patch('app.temporal.activities.auth.AsyncSessionLocal') as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session
            
            # Mock query result - no user found
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = None
            mock_session.execute.return_value = mock_result
            
            # Execute activity
            result = await auth_activities.authenticate_user("nonexistent@example.com", "password")
            
            # Verify result
            assert result["success"] is False
            assert result["error"] == "Invalid credentials"
    
    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password(self, auth_activities):
        """Test authentication with wrong password"""
        
        mock_user = MagicMock()
        mock_user.email = "test@example.com"
        mock_user.hashed_password = "hashed-password"
        
        with patch('app.temporal.activities.auth.AsyncSessionLocal') as mock_session_class, \
             patch('app.temporal.activities.auth.verify_password') as mock_verify:
            
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session
            
            # Mock query result
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = mock_user
            mock_session.execute.return_value = mock_result
            
            # Mock password verification failure
            mock_verify.return_value = False
            
            # Execute activity
            result = await auth_activities.authenticate_user("test@example.com", "wrong-password")
            
            # Verify result
            assert result["success"] is False
            assert result["error"] == "Invalid credentials"
    
    @pytest.mark.asyncio
    async def test_authenticate_user_inactive(self, auth_activities):
        """Test authentication with inactive user"""
        
        mock_user = MagicMock()
        mock_user.email = "test@example.com"
        mock_user.is_active = False
        mock_user.hashed_password = "hashed-password"
        
        with patch('app.temporal.activities.auth.AsyncSessionLocal') as mock_session_class, \
             patch('app.temporal.activities.auth.verify_password') as mock_verify:
            
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session
            
            # Mock query result
            mock_result = AsyncMock()
            mock_result.scalar_one_or_none.return_value = mock_user
            mock_session.execute.return_value = mock_result
            
            # Mock password verification success
            mock_verify.return_value = True
            
            # Execute activity
            result = await auth_activities.authenticate_user("test@example.com", "password")
            
            # Verify result
            assert result["success"] is False
            assert result["error"] == "Account is deactivated"
    
    @pytest.mark.asyncio
    async def test_create_login_tokens(self, auth_activities):
        """Test JWT token creation"""
        
        with patch('app.temporal.activities.auth.create_access_token') as mock_access, \
             patch('app.temporal.activities.auth.create_refresh_token') as mock_refresh:
            
            # Setup mocks
            mock_access.return_value = "access-token"
            mock_refresh.return_value = "refresh-token"
            
            # Execute activity
            result = await auth_activities.create_login_tokens("user-123", "test@example.com")
            
            # Verify result
            assert result["access_token"] == "access-token"
            assert result["refresh_token"] == "refresh-token"
            assert result["expires_in"] == settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
            
            # Verify token creation calls
            mock_access.assert_called_once_with({"sub": "user-123", "email": "test@example.com"})
            mock_refresh.assert_called_once_with({"sub": "user-123"})
    
    @pytest.mark.asyncio
    async def test_store_login_session(self, auth_activities):
        """Test storing login session"""
        
        mock_user = MagicMock()
        mock_user.email = "test@example.com"
        mock_user.last_login = None
        
        with patch('app.temporal.activities.auth.AsyncSessionLocal') as mock_session_class, \
             patch('app.temporal.activities.auth.datetime') as mock_datetime:
            
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session
            
            # Mock user retrieval
            mock_session.get.return_value = mock_user
            
            # Mock datetime
            mock_now = datetime(2023, 1, 1, 12, 0, 0)
            mock_datetime.utcnow.return_value = mock_now
            
            # Execute activity
            result = await auth_activities.store_login_session("user-123", "refresh-token")
            
            # Verify result
            assert result["success"] is True
            assert result["last_login"] == mock_now.isoformat()
            
            # Verify database operations
            mock_session.add.assert_called_once()
            mock_session.commit.assert_called_once()
            
            # Verify user last_login update
            assert mock_user.last_login == mock_now
    
    @pytest.mark.asyncio
    async def test_store_login_session_user_not_found(self, auth_activities):
        """Test storing login session when user not found"""
        
        with patch('app.temporal.activities.auth.AsyncSessionLocal') as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session
            
            # Mock user not found
            mock_session.get.return_value = None
            
            # Execute activity and expect exception
            with pytest.raises(ValueError, match="User not found"):
                await auth_activities.store_login_session("nonexistent-user", "refresh-token")
    
    @pytest.mark.asyncio
    async def test_generate_oauth_authorization_code(self, auth_activities):
        """Test OAuth2 authorization code generation"""
        
        with patch('secrets.token_urlsafe') as mock_token, \
             patch('app.temporal.activities.auth.AsyncSessionLocal') as mock_session_class, \
             patch('app.temporal.activities.auth.datetime') as mock_datetime:
            
            # Setup mocks
            mock_token.return_value = "auth-code"
            mock_now = datetime(2023, 1, 1, 12, 0, 0)
            mock_datetime.utcnow.return_value = mock_now
            
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__.return_value = mock_session
            
            # Execute activity
            result = await auth_activities.generate_oauth_authorization_code(
                "client-123",
                "user-123", 
                "https://example.com/callback",
                "read write",
                "state-123"
            )
            
            # Verify result
            assert result["code"] == "auth-code"
            assert result["state"] == "state-123"
            expected_expires = mock_now + timedelta(minutes=settings.OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES)
            assert result["expires_at"] == expected_expires.isoformat()
            
            # Verify database operations
            mock_session.add.assert_called_once()
            mock_session.commit.assert_called_once()