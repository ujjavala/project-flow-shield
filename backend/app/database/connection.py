from ast import stmt
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from app.database.base import Base
from app.config import settings
from sqlalchemy import select
import logging

logger = logging.getLogger(__name__)

# Create async engine
engine = create_async_engine(
    settings.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://"),
    echo=False,
    pool_size=10,
    max_overflow=0
)

# Create async session maker
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

async def init_db():
    """Initialize database tables"""
    try:
        from app.models.user import User, RefreshToken
        from app.models.oauth import OAuth2Client, OAuth2AuthorizationCode, OAuth2AccessToken
        from app.models.iam import (
            IAMAccessEvaluation, IAMAuditLog, IAMContextualRole, IAMOperationEffect,
            IAMPermission, IAMPolicy, IAMResource, IAMRole, IAMRoleRequest, IAMScope,
            IAMSession,
        )
        from app.models.auth_security import AuthChallenge, AuthSession, PasskeyCredential, TOTPRecoveryCode
        from app.models.risk_policy import RiskDecision, RiskPolicy
        from app.models.security_lab import SecuritySimulationRun
        
        async with engine.begin() as conn:
            # Create all tables
            await conn.run_sync(Base.metadata.create_all)
            
        logger.info("Database tables created successfully")
        
        # Create default OAuth2 client
        await create_default_oauth_client()
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

async def create_default_oauth_client():
    """Create default OAuth2 client for the application"""
    try:
        from app.models.oauth import OAuth2Client
        from app.utils.security import hash_password
        
        async with AsyncSessionLocal() as session:
            # Check if default client exists
            stmt = select(OAuth2Client).where(OAuth2Client.client_id == settings.OAUTH2_CLIENT_ID)
            result = await session.execute(stmt)
            existing_client = result.scalar_one_or_none()
            
            client_secret = (
                hash_password(settings.OAUTH2_CLIENT_SECRET)
                if settings.OAUTH2_CLIENT_CONFIDENTIAL and settings.OAUTH2_CLIENT_SECRET
                else None
            )
            redirect_uris = [settings.OAUTH2_REDIRECT_URI, f"{settings.FRONTEND_URL}/callback"]

            if not existing_client:
                default_client = OAuth2Client(
                    client_id=settings.OAUTH2_CLIENT_ID,
                    client_secret=client_secret,
                    client_name="FlowShield Local Demo Client",
                    redirect_uris=redirect_uris,
                    grant_types=["authorization_code", "refresh_token"],
                    response_types=["code"],
                    scope="openid read write profile email",
                    description="Deterministic local OAuth 2.1/OIDC PKCE demo client",
                    is_confidential=settings.OAUTH2_CLIENT_CONFIDENTIAL,
                )
                
                session.add(default_client)
                await session.commit()
                logger.info("Default OAuth2 client created")
            else:
                existing_client.client_name = "FlowShield Local Demo Client"
                existing_client.client_secret = client_secret
                existing_client.redirect_uris = redirect_uris
                existing_client.grant_types = ["authorization_code", "refresh_token"]
                existing_client.response_types = ["code"]
                existing_client.scope = "openid read write profile email"
                existing_client.description = "Deterministic local OAuth 2.1/OIDC PKCE demo client"
                existing_client.is_confidential = settings.OAUTH2_CLIENT_CONFIDENTIAL
                existing_client.is_active = True
                await session.commit()
                logger.info("Default OAuth2 client reconciled")
                
    except Exception as e:
        logger.error(f"Failed to create default OAuth2 client: {e}")

async def get_db() -> AsyncSession:
    """Dependency to get database session"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

async def close_db():
    """Close database connections"""
    await engine.dispose()