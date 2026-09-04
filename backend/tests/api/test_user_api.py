import pytest
from httpx import ASGITransport, AsyncClient
from unittest.mock import AsyncMock, patch, MagicMock
import uuid

from app.api import user as user_api
from app.main import app
from app.models.user import User
from app.utils.security import hash_password


class TestUserAPI:
    
    @pytest.fixture
    def mock_db_session(self):
        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        return mock_session

    @pytest.fixture
    async def client(self, mock_db_session):
        async def override_db():
            yield mock_db_session

        app.dependency_overrides[user_api.get_db] = override_db
        allowed = {
            "allowed": True,
            "remaining": 99,
            "reset_time": "2099-01-01T00:00:00+00:00",
            "current_count": 1,
            "limit": 100,
            "retry_after": None,
            "blocked_reason": None,
        }
        try:
            with patch(
                "app.middleware.security.rate_limiter.check",
                new=AsyncMock(return_value=allowed),
            ):
                async with AsyncClient(
                    transport=ASGITransport(app=app),
                    base_url="http://test",
                ) as ac:
                    yield ac
        finally:
            app.dependency_overrides.pop(user_api.get_db, None)
    
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
        
        with patch('app.api.user.email_delivery.send_verification', new_callable=AsyncMock) as mock_send:
            # Mock no existing user
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = None
            mock_db_session.execute.return_value = mock_result
            
            # Execute request
            response = await client.post("/user/register", json=sample_user_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["email"] == sample_user_data["email"]
            assert data["method"] == "database"
            assert "user_id" in data
            
            # Verify database operations
            mock_db_session.add.assert_called_once()
            mock_db_session.commit.assert_awaited_once()
            mock_send.assert_awaited_once()
    
    @pytest.mark.asyncio
    async def test_register_user_already_exists(self, client, mock_db_session, sample_user_data, existing_user):
        """Test registration with existing user"""
        
        with patch('app.api.user.get_db') as mock_get_db:
            
            # Mock database
            mock_get_db.return_value = mock_db_session
            
            # Mock existing user
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = existing_user
            mock_db_session.execute.return_value = mock_result
            
            # Execute request
            response = await client.post("/user/register", json=sample_user_data)
            
            # Verify response
            assert response.status_code == 400
            assert "already exists" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_login_success(self, client, mock_db_session, existing_user):
        """Test successful user login"""
        
        with patch('app.api.user._evaluate_login_risk', new_callable=AsyncMock) as mock_risk, \
             patch('app.api.user.create_session_tokens', new_callable=AsyncMock) as mock_create_session:
            mock_risk.return_value = None
            mock_create_session.return_value = MagicMock(
                access_token="access-token",
                refresh_token="refresh-token",
                session_id="session-123",
            )

            # Mock user lookup
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = existing_user
            mock_db_session.execute.return_value = mock_result
            
            # Execute request
            login_data = {
                "email": "test@example.com",
                "password": "Password123!"
            }
            response = await client.post("/user/login", json=login_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert "refresh_token" in data
            assert data["token_type"] == "bearer"
            assert "expires_in" in data
            
            mock_risk.assert_awaited_once()
            mock_create_session.assert_awaited_once()
    
    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, client, mock_db_session):
        """Test login with invalid credentials"""
        
        with patch('app.api.user._evaluate_login_risk', new_callable=AsyncMock) as mock_risk:
            # Mock no user found
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = None
            mock_db_session.execute.return_value = mock_result
            
            # Execute request
            login_data = {
                "email": "nonexistent@example.com",
                "password": "wrongpassword"
            }
            response = await client.post("/user/login", json=login_data)
            
            # Verify response
            assert response.status_code == 401
            assert "Invalid email or password" in response.json()["detail"]
            mock_risk.assert_not_awaited()
    
    @pytest.mark.asyncio
    async def test_login_inactive_user(self, client, mock_db_session, existing_user):
        """Test login with inactive user"""
        
        existing_user.is_active = False
        
        with patch('app.api.user._evaluate_login_risk', new_callable=AsyncMock) as mock_risk:
            # Mock inactive user lookup
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = existing_user
            mock_db_session.execute.return_value = mock_result
            
            # Execute request
            login_data = {
                "email": "test@example.com",
                "password": "Password123!"
            }
            response = await client.post("/user/login", json=login_data)
            
            # Verify response
            assert response.status_code == 401
            assert "Account is deactivated" in response.json()["detail"]
            mock_risk.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_login_unverified_user(self, client, mock_db_session, existing_user):
        """Test login is blocked until the user's email is verified"""

        existing_user.is_verified = False

        with patch('app.api.user._evaluate_login_risk', new_callable=AsyncMock) as mock_risk:
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = existing_user
            mock_db_session.execute.return_value = mock_result

            response = await client.post("/user/login", json={
                "email": "test@example.com",
                "password": "Password123!"
            })

            assert response.status_code == 403
            assert "Email not verified" in response.json()["detail"]
            mock_db_session.add.assert_not_called()
            mock_risk.assert_not_awaited()
    
    @pytest.mark.asyncio
    async def test_refresh_token_success(self, client, mock_db_session):
        """Test successful token refresh"""
        
        with patch('app.api.user.rotate_refresh_token', new_callable=AsyncMock) as mock_rotate:
            mock_rotate.return_value = MagicMock(
                access_token="new-access-token",
                refresh_token="new-refresh-token",
                session_id="session-123",
            )
            
            # Execute request
            refresh_data = {
                "refresh_token": "valid-refresh-token"
            }
            response = await client.post("/user/refresh", json=refresh_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert data["access_token"] == "new-access-token"
            assert data["refresh_token"] == "new-refresh-token"
            assert data["token_type"] == "bearer"
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["pragma"] == "no-cache"
            mock_rotate.assert_awaited_once_with(mock_db_session, "valid-refresh-token")
    
    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, client, mock_db_session):
        """Test token refresh with invalid token"""
        
        with patch('app.api.user.rotate_refresh_token', new_callable=AsyncMock) as mock_rotate:
            mock_rotate.side_effect = user_api.InvalidRefreshToken()

            # Execute request
            refresh_data = {
                "refresh_token": "invalid-refresh-token"
            }
            response = await client.post("/user/refresh", json=refresh_data)
            
            # Verify response
            assert response.status_code == 401
            assert "Invalid refresh token" in response.json()["detail"]
            mock_rotate.assert_awaited_once_with(mock_db_session, "invalid-refresh-token")
    
    @pytest.mark.asyncio
    async def test_logout_success(self, client, mock_db_session):
        """Test successful logout"""
        refresh_token_record = MagicMock(
            user_id="user-123",
            session_id="session-123",
        )

        with patch('app.api.user.revoke_session', new_callable=AsyncMock) as mock_revoke:
            # Mock refresh token lookup
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = refresh_token_record
            mock_db_session.execute.return_value = mock_result
            
            # Execute request
            logout_data = {
                "refresh_token": "valid-refresh-token"
            }
            response = await client.post("/user/logout", json=logout_data)
            
            # Verify response
            assert response.status_code == 200
            data = response.json()
            assert "Logged out successfully" in data["message"]

            mock_revoke.assert_awaited_once_with(
                mock_db_session,
                "session-123",
                "user-123",
            )