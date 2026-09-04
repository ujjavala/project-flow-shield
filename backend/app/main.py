from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import uuid
from sqlalchemy import text
from app.utils.safe_logging import configure_safe_logging

# Configure logging first
configure_safe_logging()
logger = logging.getLogger(__name__)

from app.config import settings
from app.database.connection import init_db
from app.database.connection import AsyncSessionLocal
from app.api import user, oauth
from app.observability import configure_observability

# Import security middleware
from app.middleware.security import (
    BFFSessionMiddleware,
    SecurityHeadersMiddleware,
    TokenTheftProtectionMiddleware,
    CSPReportMiddleware,
    RateLimitingMiddleware
)

# Import AI endpoints (simple version that works with current setup)
try:
    from app.api import ai_simple
    AI_AVAILABLE = True
    logger.info("AI endpoints available")
except ImportError as e:
    AI_AVAILABLE = False
    logger.warning("AI endpoints not available exception_type=%s", type(e).__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting FlowShield Authentication Service")
    await init_db()
    logger.info("Database initialized")
    
    # Initialize analytics service
    try:
        from app.api.admin_dashboard import initialize_analytics
        await initialize_analytics()
        logger.info("Analytics service initialized")
    except Exception as exc:
        logger.warning("Analytics service initialization failed exception_type=%s", type(exc).__name__)
    
    yield
    # Shutdown
    logger.info("Shutting down FlowShield Authentication Service")

app = FastAPI(
    title="OAuth2 Authentication Service",
    description="OAuth2 authentication system with Temporal workflows",
    version="1.0.0",
    lifespan=lifespan
)

configure_observability(app)

# Security middleware (order matters - add before CORS)
app.add_middleware(BFFSessionMiddleware)
app.add_middleware(
    SecurityHeadersMiddleware,
    config={"environment": getattr(settings, "ENVIRONMENT", "development")}
)
app.add_middleware(TokenTheftProtectionMiddleware)
app.add_middleware(CSPReportMiddleware)
# Add rate limiting middleware
app.add_middleware(
    RateLimitingMiddleware,
    config={"environment": getattr(settings, "ENVIRONMENT", "development")}
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception handlers
@app.exception_handler(Exception)
async def custom_exception_handler(request: Request, exc: Exception):
    correlation_id = str(uuid.uuid4())
    logger.error(
        "Unhandled request failure correlation_id=%s method=%s path=%s exception_type=%s",
        correlation_id,
        request.method,
        request.url.path,
        type(exc).__name__,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "internal_server_error",
            "message": "The request could not be completed",
            "correlation_id": correlation_id,
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR
        }
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": "HTTPException",
            "detail": exc.detail,
            "status_code": exc.status_code
        }
    )

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "oauth2-auth"}

@app.get("/health/ready")
async def readiness_check():
    """Report whether the API's required backing services are reachable."""
    checks = {"database": False, "redis": False, "temporal": False}
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception as exc:
        logger.warning("Database readiness check failed: %s", exc)

    try:
        from redis.asyncio import from_url

        redis_client = from_url(settings.REDIS_URL, socket_timeout=1)
        try:
            checks["redis"] = bool(await redis_client.ping())
        finally:
            await redis_client.aclose()
    except Exception as exc:
        logger.warning("Redis readiness check failed: %s", exc)

    try:
        from app.temporal.client import get_temporal_client

        await get_temporal_client()
        checks["temporal"] = True
    except Exception as exc:
        logger.warning("Temporal readiness check failed: %s", exc)

    ready = all(checks.values())
    return JSONResponse(
        status_code=status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"status": "ready" if ready else "not_ready", "checks": checks},
    )

# Temporal status endpoint
@app.get("/temporal-status")
async def temporal_status():
    try:
        from app.temporal.client import get_temporal_client
        client = await get_temporal_client()
        
        # Try to list workflows to test connection
        async for workflow in client.list_workflows():
            # Just test the connection works
            break
        
        return {
            "temporal_connected": True,
            "status": "available"
        }
    except Exception:
        return {
            "temporal_connected": False,
            "status": "unavailable"
        }

# Temporal ping test endpoint
@app.post("/temporal-ping")
async def temporal_ping(message: str = "Hello Temporal!"):
    try:
        from app.temporal.client import get_temporal_client
        from app.temporal.workflows.ping import PingWorkflow, PingRequest
        from datetime import datetime, timedelta
        
        client = await get_temporal_client()
        
        ping_request = PingRequest(message=message)
        
        result = await client.execute_workflow(
            PingWorkflow.run,
            ping_request,
            id=f"ping-test-{datetime.utcnow().timestamp()}",
            task_queue=settings.TEMPORAL_TASK_QUEUE,
            execution_timeout=timedelta(seconds=30)
        )
        
        return {
            "temporal_working": True,
            "workflow_result": result,
            "method": "temporal_workflow"
        }
        
    except Exception:
        return {
            "temporal_working": False,
            "method": "error"
        }

# Include routers
app.include_router(user.router, prefix="/user", tags=["user"])
app.include_router(oauth.router, prefix="/oauth", tags=["oauth2"])

# PKCE is a security-critical OAuth route and must fail fast if it cannot load.
from app.api.routes import pkce
app.include_router(pkce.router, tags=["pkce"])
logger.info("PKCE endpoints registered")

from app.api.routes import oidc
app.include_router(oidc.router, tags=["oidc"])
logger.info("OIDC endpoints registered")

from app.api.routes import strong_auth
app.include_router(strong_auth.router)
logger.info("Passkey, MFA, and session endpoints registered")

from app.api import risk_policy
app.include_router(risk_policy.router)
logger.info("Deterministic risk-policy endpoints registered")

from app.api import security_lab
app.include_router(security_lab.router)
logger.info("Sandboxed security-lab endpoints registered")

# The optional BFF remains isolated until its session flow is modernized.
try:
    from app.api.routes import bff
    app.include_router(bff.router, tags=["bff"])
    logger.info("BFF endpoints registered")
except ImportError as e:
    logger.warning("BFF endpoints not available exception_type=%s", type(e).__name__)

# Include AI router if available
if AI_AVAILABLE:
    app.include_router(ai_simple.router, tags=["ai"])
    logger.info("AI endpoints registered")
else:
    logger.warning("AI endpoints not registered - check dependencies")

# Include Admin Analytics router
try:
    from app.api import admin_analytics
    app.include_router(admin_analytics.router, tags=["admin-analytics"])
    logger.info("Admin analytics endpoints registered")
except ImportError as e:
    logger.warning("Admin analytics endpoints not available exception_type=%s", type(e).__name__)

# Include Admin Dashboard router
try:
    from app.api import admin_dashboard
    app.include_router(admin_dashboard.router, tags=["admin-dashboard"])
    logger.info("Admin dashboard endpoints registered")
except ImportError as e:
    logger.warning("Admin dashboard endpoints not available exception_type=%s", type(e).__name__)

# Include Rate Limiting router
try:
    from app.api import rate_limiting
    app.include_router(rate_limiting.router, tags=["rate-limiting"])
    logger.info("Rate limiting endpoints registered")
except ImportError as e:
    logger.warning("Rate limiting endpoints not available exception_type=%s", type(e).__name__)

# Include User Dashboard router
try:
    from app.api import user_dashboard
    app.include_router(user_dashboard.router, tags=["user-dashboard"])
    logger.info("User dashboard endpoints registered")
except ImportError as e:
    logger.warning("User dashboard endpoints not available exception_type=%s", type(e).__name__)

# Include Admin Authentication router
try:
    from app.api import admin_auth
    app.include_router(admin_auth.router, tags=["admin-auth"])
    logger.info("Admin authentication endpoints registered")
except ImportError as e:
    logger.warning("Admin authentication endpoints not available exception_type=%s", type(e).__name__)

try:
    from app.api import behavioral_analytics
    app.include_router(behavioral_analytics.router, prefix="/behavioral-analytics", tags=["behavioral-analytics"])
    logger.info("Behavioral analytics endpoints registered")
except ImportError as e:
    logger.warning("Behavioral analytics endpoints not available exception_type=%s", type(e).__name__)

# Include Predictive Attack Simulation router
try:
    from app.api import predictive_attack
    app.include_router(predictive_attack.router, tags=["predictive-attack"])
    logger.info("Predictive attack simulation endpoints registered")
except ImportError as e:
    logger.warning("Predictive attack simulation endpoints not available exception_type=%s", type(e).__name__)

# Include IAM Management router
try:
    from app.api import iam_management
    app.include_router(iam_management.router, tags=["iam-management"])
    logger.info("IAM management endpoints registered")
except ImportError as e:
    logger.warning("IAM management endpoints not available exception_type=%s", type(e).__name__)

@app.get("/")
async def root():
    return {
        "message": "OAuth2 Authentication Service",
        "version": "1.0.0",
        "docs": "/docs"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )