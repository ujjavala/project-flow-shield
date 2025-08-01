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
            
            if not existing_client:
                default_client = OAuth2Client(
                    client_id=settings.OAUTH2_CLIENT_ID,
                    client_secret=hash_password(settings.OAUTH2_CLIENT_SECRET),
                    client_name="OAuth2 Auth Default Client",
                    redirect_uris=[settings.OAUTH2_REDIRECT_URI, f"{settings.FRONTEND_URL}/callback"],
                    grant_types=["authorization_code", "refresh_token"],
                    response_types=["code"],
                    scope="read write profile email",
                    description="Default OAuth2 client for the authentication service"
                )
                
                session.add(default_client)
                await session.commit()
                logger.info("Default OAuth2 client created")
            else:
                logger.info("Default OAuth2 client already exists")
                
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