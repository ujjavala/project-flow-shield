from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging

# Configure logging first
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from app.config import settings
from app.database.connection import init_db
from app.api import user, oauth

# Import security middleware
from app.middleware.security import (
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
    logger.warning(f"AI endpoints not available: {e}")

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
    except Exception as e:
        logger.warning(f"Analytics service initialization failed: {e}")
    
    yield
    # Shutdown
    logger.info("Shutting down FlowShield Authentication Service")

app = FastAPI(
    title="OAuth2 Authentication Service",
    description="OAuth2 authentication system with Temporal workflows",
    version="1.0.0",
    lifespan=lifespan
)

# Security middleware (order matters - add before CORS)
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
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": exc.__class__.__name__,
            "message": str(exc),
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
            "namespace": "default",
            "temporal_server": settings.TEMPORAL_HOST,
            "task_queue": settings.TEMPORAL_TASK_QUEUE
        }
    except Exception as e:
        return {
            "temporal_connected": False,
            "error": str(e),
            "temporal_server": settings.TEMPORAL_HOST,
            "task_queue": settings.TEMPORAL_TASK_QUEUE
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
        
    except Exception as e:
        return {
            "temporal_working": False,
            "error": str(e),
            "method": "error"
        }

# Include routers
app.include_router(user.router, prefix="/user", tags=["user"])
app.include_router(oauth.router, prefix="/oauth", tags=["oauth2"])

# Include PKCE and BFF routers
try:
    from app.api.routes import pkce, bff
    app.include_router(pkce.router, tags=["pkce"])
    app.include_router(bff.router, tags=["bff"])
    logger.info("PKCE and BFF endpoints registered")
except ImportError as e:
    logger.warning(f"PKCE/BFF endpoints not available: {e}")

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
    logger.warning(f"Admin analytics endpoints not available: {e}")

# Include Admin Dashboard router
try:
    from app.api import admin_dashboard
    app.include_router(admin_dashboard.router, tags=["admin-dashboard"])
    logger.info("Admin dashboard endpoints registered")
except ImportError as e:
    logger.warning(f"Admin dashboard endpoints not available: {e}")

# Include Rate Limiting router
try:
    from app.api import rate_limiting
    app.include_router(rate_limiting.router, tags=["rate-limiting"])
    logger.info("Rate limiting endpoints registered")
except ImportError as e:
    logger.warning(f"Rate limiting endpoints not available: {e}")

# Include User Dashboard router
try:
    from app.api import user_dashboard
    app.include_router(user_dashboard.router, tags=["user-dashboard"])
    logger.info("User dashboard endpoints registered")
except ImportError as e:
    logger.warning(f"User dashboard endpoints not available: {e}")

# Include Admin Authentication router
try:
    from app.api import admin_auth
    app.include_router(admin_auth.router, tags=["admin-auth"])
    logger.info("Admin authentication endpoints registered")
except ImportError as e:
    logger.warning(f"Admin authentication endpoints not available: {e}")

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