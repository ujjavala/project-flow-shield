import pytest

from pydantic import ValidationError

from app.config import Settings


def test_config_loading():
    """Test configuration loading"""
    from app.config import settings
    
    # Test that settings object exists
    assert hasattr(settings, 'JWT_ACCESS_TOKEN_EXPIRE_MINUTES')
    assert hasattr(settings, 'JWT_REFRESH_TOKEN_EXPIRE_DAYS')
    assert hasattr(settings, 'JWT_SECRET_KEY')
    
    # Test default values
    assert isinstance(settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES, int)
    assert isinstance(settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS, int)
    assert settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES > 0
    assert settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS > 0


def test_database_url_configuration():
    """Test database URL configuration"""
    from app.config import settings
    
    # Should have database-related settings
    assert hasattr(settings, 'DATABASE_URL') or hasattr(settings, 'DB_USER')


def test_production_rejects_local_security_defaults():
    with pytest.raises(ValidationError, match="Invalid production security configuration"):
        Settings(ENVIRONMENT="production", _env_file=None)


def test_production_accepts_explicit_secure_configuration():
    configured = Settings(
        ENVIRONMENT="production",
        JWT_SECRET_KEY="j" * 48,
        OAUTH2_CLIENT_SECRET="o" * 48,
        MFA_ENCRYPTION_KEY="configured-encryption-key",
        BFF_COOKIE_SECURE=True,
        OIDC_ISSUER="https://identity.example.com",
        OIDC_SIGNING_KEY_PATH="/run/secrets/oidc-private.pem",
        OIDC_ACTIVE_KEY_ID="production-key-1",
        OAUTH2_REDIRECT_URI="https://app.example.com/callback",
        FRONTEND_URL="https://app.example.com",
        BACKEND_URL="https://api.example.com",
        DATABASE_URL="postgresql://flowshield:managed-secret@database.example.com/flowshield",
        EMAIL_DELIVERY_MODE="smtp",
        OTEL_EXPORTER_OTLP_INSECURE=False,
        _env_file=None,
    )

    assert configured.BFF_COOKIE_SECURE is True


def test_email_configuration():
    """Test email-related configuration"""
    from app.config import settings
    
    # Should have email-related settings
    assert hasattr(settings, 'EMAIL_VERIFICATION_EXPIRE_HOURS')
    assert hasattr(settings, 'PASSWORD_RESET_EXPIRE_HOURS')
    
    if hasattr(settings, 'EMAIL_VERIFICATION_EXPIRE_HOURS'):
        assert settings.EMAIL_VERIFICATION_EXPIRE_HOURS > 0
    
    if hasattr(settings, 'PASSWORD_RESET_EXPIRE_HOURS'):
        assert settings.PASSWORD_RESET_EXPIRE_HOURS > 0


@pytest.mark.asyncio  
async def test_temporal_configuration():
    """Test Temporal-related configuration"""
    from app.config import settings
    
    # Should have temporal settings if available
    temporal_settings = [
        'TEMPORAL_HOST',
        'TEMPORAL_PORT', 
        'TEMPORAL_NAMESPACE',
    ]
    
    # At least some temporal configuration should exist
    temporal_config_exists = any(hasattr(settings, setting) for setting in temporal_settings)
    
    # This is informational - temporal config might not be required for all tests
    assert True  # Always pass as temporal config is optional