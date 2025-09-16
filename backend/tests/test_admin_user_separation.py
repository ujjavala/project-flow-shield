"""
Tests for Admin/User Separation
Ensures clear distinction between admin and regular user access
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch
from datetime import datetime

from app.main import app
from app.models.user import User

# Create test client
client = TestClient(app)

class TestAdminUserSeparation:
    """Test admin and user separation functionality"""

    def test_regular_user_cannot_access_admin_dashboard(self):
        """Test that regular users cannot access admin dashboard"""

        # Mock a regular user token
        with patch('app.utils.admin_auth.verify_token') as mock_verify:
            mock_verify.return_value = {
                'sub': 'user123',
                'email': 'user@example.com',
                'role': 'user'
            }

            with patch('app.database.connection.get_db'):
                with patch('app.utils.admin_auth.get_admin_user') as mock_get_admin:
                    mock_get_admin.side_effect = Exception("Not an admin")

                    headers = {"Authorization": "Bearer user_token"}
                    response = client.get("/admin/", headers=headers)

                    # Should be denied
                    assert response.status_code == 401

    def test_admin_user_can_access_admin_dashboard(self):
        """Test that admin users can access admin dashboard"""

        # Mock an admin user
        mock_admin = User(
            id="admin123",
            email="admin@example.com",
            role="admin",
            is_active=True,
            is_superuser=False
        )

        with patch('app.utils.admin_auth.get_admin_user') as mock_get_admin:
            mock_get_admin.return_value = mock_admin

            with patch('app.utils.admin_auth.create_admin_session_log'):
                headers = {"Authorization": "Bearer admin_token"}
                response = client.get("/admin/", headers=headers)

                # Should be allowed (or at least not 401/403)
                assert response.status_code not in [401, 403]

    def test_admin_user_cannot_use_regular_login(self):
        """Test that admin users are blocked from regular login"""

        login_data = {
            "email": "admin@example.com",
            "password": "admin_password"
        }

        # Mock admin user in database
        mock_admin = Mock()
        mock_admin.email = "admin@example.com"
        mock_admin.is_active = True
        mock_admin.role = "admin"
        mock_admin.is_superuser = False
        mock_admin.hashed_password = "hashed_password"

        with patch('app.utils.security.verify_password') as mock_verify_password:
            mock_verify_password.return_value = True

            with patch('app.database.connection.get_db'):
                with patch('sqlalchemy.ext.asyncio.AsyncSession.execute') as mock_execute:
                    mock_result = Mock()
                    mock_result.scalar_one_or_none.return_value = mock_admin
                    mock_execute.return_value = mock_result

                    response = client.post("/user/login", json=login_data)

                    # Should be forbidden
                    assert response.status_code == 403
                    assert "admin login endpoint" in response.json()["detail"].lower()

    def test_regular_user_can_use_regular_login(self):
        """Test that regular users can use regular login"""

        login_data = {
            "email": "user@example.com",
            "password": "user_password"
        }

        # Mock regular user in database
        mock_user = Mock()
        mock_user.email = "user@example.com"
        mock_user.is_active = True
        mock_user.role = "user"
        mock_user.is_superuser = False
        mock_user.is_verified = True
        mock_user.hashed_password = "hashed_password"
        mock_user.id = "user123"
        mock_user.last_login = None

        with patch('app.utils.security.verify_password') as mock_verify_password:
            mock_verify_password.return_value = True

            with patch('app.utils.security.create_access_token') as mock_create_access:
                mock_create_access.return_value = "access_token"

                with patch('app.utils.security.create_refresh_token') as mock_create_refresh:
                    mock_create_refresh.return_value = "refresh_token"

                    with patch('app.database.connection.get_db'):
                        with patch('sqlalchemy.ext.asyncio.AsyncSession.execute') as mock_execute:
                            mock_result = Mock()
                            mock_result.scalar_one_or_none.return_value = mock_user
                            mock_execute.return_value = mock_result

                            with patch('sqlalchemy.ext.asyncio.AsyncSession.add'):
                                with patch('sqlalchemy.ext.asyncio.AsyncSession.commit'):
                                    response = client.post("/user/login", json=login_data)

                                    # Should be successful
                                    assert response.status_code == 200
                                    data = response.json()
                                    assert "access_token" in data

    def test_user_dashboard_blocks_admin_users(self):
        """Test that user dashboard blocks admin users"""

        # Mock an admin user trying to access user dashboard
        mock_admin = User(
            id="admin123",
            email="admin@example.com",
            role="admin",
            is_active=True
        )

        with patch('app.utils.security.verify_token') as mock_verify:
            mock_verify.return_value = {'sub': 'admin123', 'email': 'admin@example.com'}

            with patch('app.database.connection.get_db'):
                with patch('sqlalchemy.ext.asyncio.AsyncSession.get') as mock_get:
                    mock_get.return_value = mock_admin

                    headers = {"Authorization": "Bearer admin_token"}
                    response = client.get("/dashboard/", headers=headers)

                    # Should be forbidden
                    assert response.status_code == 403
                    assert "admin dashboard" in response.json()["detail"].lower()

    def test_regular_user_can_access_user_dashboard(self):
        """Test that regular users can access user dashboard"""

        # Mock a regular user
        mock_user = User(
            id="user123",
            email="user@example.com",
            role="user",
            is_active=True,
            username="testuser",
            first_name="Test",
            last_name="User",
            is_verified=True
        )

        with patch('app.utils.security.verify_token') as mock_verify:
            mock_verify.return_value = {'sub': 'user123', 'email': 'user@example.com'}

            with patch('app.database.connection.get_db'):
                with patch('sqlalchemy.ext.asyncio.AsyncSession.get') as mock_get:
                    mock_get.return_value = mock_user

                    headers = {"Authorization": "Bearer user_token"}
                    response = client.get("/dashboard/", headers=headers)

                    # Should be successful
                    assert response.status_code == 200
                    data = response.json()
                    assert "Welcome" in data["message"]

class TestAdminAuthentication:
    """Test admin-specific authentication"""

    def test_admin_login_endpoint_requires_admin_role(self):
        """Test that admin login endpoint requires admin privileges"""

        login_data = {
            "email": "user@example.com",
            "password": "password"
        }

        # Mock regular user trying to use admin login
        mock_user = Mock()
        mock_user.email = "user@example.com"
        mock_user.is_active = True
        mock_user.is_verified = True
        mock_user.role = "user"
        mock_user.is_superuser = False

        with patch('app.utils.security.verify_password') as mock_verify_password:
            mock_verify_password.return_value = True

            with patch('app.database.connection.get_db'):
                with patch('sqlalchemy.ext.asyncio.AsyncSession.execute') as mock_execute:
                    mock_result = Mock()
                    mock_result.scalar_one_or_none.return_value = mock_user
                    mock_execute.return_value = mock_result

                    response = client.post("/admin/auth/login", json=login_data)

                    # Should be forbidden
                    assert response.status_code == 403
                    assert "admin privileges required" in response.json()["detail"].lower()

    def test_admin_login_success_for_admin_user(self):
        """Test successful admin login for admin user"""

        login_data = {
            "email": "admin@example.com",
            "password": "admin_password"
        }

        # Mock admin user
        mock_admin = Mock()
        mock_admin.email = "admin@example.com"
        mock_admin.is_active = True
        mock_admin.is_verified = True
        mock_admin.role = "admin"
        mock_admin.is_superuser = False
        mock_admin.id = "admin123"
        mock_admin.last_login = None

        with patch('app.utils.security.verify_password') as mock_verify_password:
            mock_verify_password.return_value = True

            with patch('app.utils.security.create_access_token') as mock_create_access:
                mock_create_access.return_value = "admin_access_token"

                with patch('app.utils.security.create_refresh_token') as mock_create_refresh:
                    mock_create_refresh.return_value = "admin_refresh_token"

                    with patch('app.utils.admin_auth.create_admin_session_log'):
                        with patch('app.database.connection.get_db'):
                            with patch('sqlalchemy.ext.asyncio.AsyncSession.execute') as mock_execute:
                                mock_result = Mock()
                                mock_result.scalar_one_or_none.return_value = mock_admin
                                mock_execute.return_value = mock_result

                                with patch('sqlalchemy.ext.asyncio.AsyncSession.add'):
                                    with patch('sqlalchemy.ext.asyncio.AsyncSession.commit'):
                                        response = client.post("/admin/auth/login", json=login_data)

                                        # Should be successful
                                        assert response.status_code == 200
                                        data = response.json()
                                        assert "access_token" in data
                                        assert data["admin_role"] == "admin"
                                        assert "permissions" in data

class TestRoleBasedAccess:
    """Test role-based access control"""

    def test_moderator_has_limited_admin_permissions(self):
        """Test that moderator role has appropriate permissions"""

        from app.utils.admin_auth import AdminPermissionChecker

        # Mock moderator user
        mock_moderator = User(
            id="mod123",
            email="moderator@example.com",
            role="moderator",
            is_superuser=False
        )

        checker = AdminPermissionChecker()

        # Moderator should have some but not all permissions
        assert checker.can_view_system_logs(mock_moderator) == True
        assert checker.can_manage_users(mock_moderator) == False  # Only admins
        assert checker.can_export_data(mock_moderator) == False   # Only super admins

    def test_admin_has_full_permissions(self):
        """Test that admin role has full permissions"""

        from app.utils.admin_auth import AdminPermissionChecker

        # Mock admin user
        mock_admin = User(
            id="admin123",
            email="admin@example.com",
            role="admin",
            is_superuser=False
        )

        checker = AdminPermissionChecker()

        # Admin should have most permissions
        assert checker.can_view_system_logs(mock_admin) == True
        assert checker.can_manage_users(mock_admin) == True
        assert checker.can_modify_security_settings(mock_admin) == True
        assert checker.can_access_rate_limiting(mock_admin) == True
        assert checker.can_export_data(mock_admin) == False  # Only super admins

    def test_superuser_has_all_permissions(self):
        """Test that superuser has all permissions"""

        from app.utils.admin_auth import AdminPermissionChecker

        # Mock superuser
        mock_superuser = User(
            id="super123",
            email="super@example.com",
            role="admin",
            is_superuser=True
        )

        checker = AdminPermissionChecker()

        # Superuser should have all permissions
        assert checker.can_view_system_logs(mock_superuser) == True
        assert checker.can_manage_users(mock_superuser) == True
        assert checker.can_modify_security_settings(mock_superuser) == True
        assert checker.can_access_rate_limiting(mock_superuser) == True
        assert checker.can_export_data(mock_superuser) == True

class TestEndpointAccess:
    """Test endpoint access control"""

    def test_health_endpoints_accessible_without_auth(self):
        """Test that health endpoints don't require authentication"""

        # Test various health endpoints
        health_endpoints = [
            "/health",
            "/admin/auth/health",
            "/dashboard/health"
        ]

        for endpoint in health_endpoints:
            response = client.get(endpoint)
            # Should not be 401 unauthorized (might be 404 if endpoint doesn't exist)
            assert response.status_code != 401

    def test_rate_limiting_admin_actions_require_auth(self):
        """Test that rate limiting admin actions require proper authentication"""

        action_data = {
            "action": "reset_counters",
            "target": "all",
            "parameters": {}
        }

        # Without authentication
        response = client.post("/admin/rate-limiting/actions", json=action_data)
        assert response.status_code == 422  # Missing auth header

        # With invalid authentication
        headers = {"Authorization": "Bearer invalid_token"}
        response = client.post("/admin/rate-limiting/actions", json=action_data, headers=headers)
        assert response.status_code in [401, 403]  # Unauthorized or forbidden

if __name__ == "__main__":
    pytest.main([__file__, "-v"])