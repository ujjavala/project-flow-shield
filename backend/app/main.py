from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from contextlib import asynccontextmanager
import logging

from app.config import settings
from app.database.connection import init_db
from app.api import user, oauth

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting OAuth2 Authentication Service")
    await init_db()
    logger.info("Database initialized")
    yield
    # Shutdown
    logger.info("Shutting down OAuth2 Authentication Service")

app = FastAPI(
    title="OAuth2 Authentication Service",
    description="OAuth2 authentication system with Temporal workflows",
    version="1.0.0",
    lifespan=lifespan
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
async def custom_exception_handler(request, exc: Exception):
    return {
        "error": exc.__class__.__name__,
        "message": str(exc),
        "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR
    }

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    return {
        "error": "HTTPException",
        "message": exc.detail,
        "status_code": exc.status_code
    }

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "oauth2-auth"}

# Include routers
app.include_router(user.router, prefix="/user", tags=["user"])
app.include_router(oauth.router, prefix="/oauth", tags=["oauth2"])

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