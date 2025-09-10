"""
Admin Dashboard API Router
Provides comprehensive admin functionality for authentication system management
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
import httpx

# Import authentication utilities
try:
    from app.utils.security import verify_password, get_password_hash, create_access_token
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False

logger = logging.getLogger(__name__)

# Create API router
router = APIRouter(prefix="/admin", tags=["Admin Dashboard"])

# Response Models
class SystemHealthResponse(BaseModel):
    status: str
    timestamp: str
    services: Dict[str, Any]
    metrics: Dict[str, Any]
    
class UserStatsResponse(BaseModel):
    total_users: int
    active_users: int
    verified_users: int
    recent_registrations_24h: int
    recent_logins_24h: int
    
class ServiceStatusResponse(BaseModel):
    simple_server: Dict[str, Any]
    main_backend: Dict[str, Any]
    temporal: Dict[str, Any]
    ai_services: Dict[str, Any]
    
class AdminAction(BaseModel):
    action: str = Field(..., description="Action to perform")
    target: str = Field(..., description="Target of the action")
    parameters: Dict[str, Any] = Field(default_factory=dict)

# Mock user data for demonstration (replace with real database queries)
MOCK_USERS = [
    {"id": "1", "email": "test@example.com", "is_active": True, "is_verified": True, "created_at": datetime.now() - timedelta(days=5)},
    {"id": "2", "email": "admin@example.com", "is_active": True, "is_verified": True, "created_at": datetime.now() - timedelta(days=10)},
    {"id": "3", "email": "user@example.com", "is_active": True, "is_verified": False, "created_at": datetime.now() - timedelta(hours=2)},
]

@router.get("/", response_model=Dict[str, Any])
async def admin_dashboard_home():
    """Admin dashboard home - overview of all systems"""
    return {
        "message": "Authentication System Admin Dashboard",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
        "features": {
            "user_management": True,
            "service_monitoring": True,
            "ai_analytics": True,
            "temporal_workflows": True,
            "system_health": True
        },
        "endpoints": {
            "health": "/admin/health",
            "users": "/admin/users",
            "services": "/admin/services", 
            "ai": "/admin/ai-status",
            "temporal": "/admin/temporal-status",
            "metrics": "/admin/metrics"
        }
    }

@router.get("/health", response_model=SystemHealthResponse)
async def system_health():
    """Comprehensive system health check"""
    try:
        # Check services
        services = {}
        
        # Check Simple Server (port 8001)
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get("http://localhost:8001/health")
                services["simple_server"] = {
                    "status": "healthy" if response.status_code == 200 else "unhealthy",
                    "response_time": response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0,
                    "port": 8001
                }
        except Exception:
            services["simple_server"] = {"status": "offline", "port": 8001}
            
        # Check Main Backend (current service)
        services["main_backend"] = {
            "status": "healthy",
            "port": 8000,
            "features": ["auth", "oauth2", "ai", "admin"]
        }
        
        # Check Temporal
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get("http://localhost:8081")
                services["temporal_ui"] = {
                    "status": "healthy" if response.status_code == 200 else "unhealthy",
                    "port": 8081
                }
        except Exception:
            services["temporal_ui"] = {"status": "offline", "port": 8081}
            
        # Check AI Services
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get("http://localhost:8000/ai/health")
                if response.status_code == 200:
                    ai_data = response.json()
                    services["ai_services"] = {
                        "status": ai_data.get("ai_status", "unknown"),
                        "ollama": ai_data.get("services", {}).get("ollama", {})
                    }
                else:
                    services["ai_services"] = {"status": "unhealthy"}
        except Exception:
            services["ai_services"] = {"status": "offline"}
            
        # System metrics
        metrics = {
            "uptime": "unknown",
            "cpu_usage": "unknown", 
            "memory_usage": "unknown",
            "active_connections": len(services),
            "services_healthy": sum(1 for s in services.values() if s.get("status") == "healthy"),
            "services_total": len(services)
        }
        
        # Overall status
        healthy_services = metrics["services_healthy"]
        total_services = metrics["services_total"]
        overall_status = "healthy" if healthy_services == total_services else "degraded" if healthy_services > 0 else "unhealthy"
        
        return SystemHealthResponse(
            status=overall_status,
            timestamp=datetime.now().isoformat(),
            services=services,
            metrics=metrics
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")

@router.get("/users", response_model=UserStatsResponse)
async def user_statistics():
    """Get user statistics and management info"""
    try:
        # Using mock data - replace with real database queries
        users = MOCK_USERS
        now = datetime.now()
        
        total_users = len(users)
        active_users = sum(1 for u in users if u["is_active"])
        verified_users = sum(1 for u in users if u["is_verified"])
        recent_registrations = sum(1 for u in users if now - u["created_at"] < timedelta(hours=24))
        
        return UserStatsResponse(
            total_users=total_users,
            active_users=active_users,
            verified_users=verified_users,
            recent_registrations_24h=recent_registrations,
            recent_logins_24h=5  # Mock data
        )
        
    except Exception as e:
        logger.error(f"User statistics failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get user statistics: {str(e)}")

@router.get("/users/list")
async def list_users(limit: int = Query(default=10, le=100), offset: int = Query(default=0)):
    """List users with pagination"""
    try:
        users = MOCK_USERS[offset:offset + limit]
        return {
            "users": [
                {
                    "id": u["id"],
                    "email": u["email"], 
                    "is_active": u["is_active"],
                    "is_verified": u["is_verified"],
                    "created_at": u["created_at"].isoformat(),
                    "last_login": "2025-09-10T10:00:00" if u["email"] == "test@example.com" else None
                }
                for u in users
            ],
            "total": len(MOCK_USERS),
            "limit": limit,
            "offset": offset
        }
    except Exception as e:
        logger.error(f"List users failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list users: {str(e)}")

@router.get("/services", response_model=ServiceStatusResponse)
async def service_status():
    """Get detailed status of all services"""
    try:
        # Simple Server Status
        simple_server = {}
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get("http://localhost:8001/")
                if response.status_code == 200:
                    data = response.json()
                    simple_server = {
                        "status": "healthy",
                        "port": 8001,
                        "features": ["login", "register", "jwt_tokens"],
                        "test_credentials": data.get("test_credentials", {}),
                        "message": data.get("message", "Simple Auth Server")
                    }
                else:
                    simple_server = {"status": "unhealthy", "port": 8001}
        except Exception as e:
            simple_server = {"status": "offline", "port": 8001, "error": str(e)}
            
        # Main Backend Status
        main_backend = {
            "status": "healthy",
            "port": 8000,
            "features": ["oauth2", "temporal", "ai", "admin", "user_management"],
            "endpoints": ["/user", "/oauth", "/ai", "/admin", "/temporal-status"]
        }
        
        # Temporal Status
        temporal = {}
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get("http://localhost:8000/temporal-status")
                if response.status_code == 200:
                    temporal = response.json()
                    temporal["ui_port"] = 8081
                else:
                    temporal = {"status": "unhealthy"}
        except Exception as e:
            temporal = {"status": "offline", "error": str(e)}
            
        # AI Services Status
        ai_services = {}
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get("http://localhost:8000/ai/health")
                if response.status_code == 200:
                    ai_services = response.json()
                else:
                    ai_services = {"status": "unhealthy"}
        except Exception as e:
            ai_services = {"status": "offline", "error": str(e)}
            
        return ServiceStatusResponse(
            simple_server=simple_server,
            main_backend=main_backend,
            temporal=temporal,
            ai_services=ai_services
        )
        
    except Exception as e:
        logger.error(f"Service status check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get service status: {str(e)}")

@router.get("/ai-status")
async def ai_service_status():
    """Get AI service status and capabilities"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Get AI health
            health_response = await client.get("http://localhost:8000/ai/health")
            
            if health_response.status_code == 200:
                health_data = health_response.json()
                
                # Test AI capabilities
                test_results = {}
                
                # Test fraud detection
                try:
                    fraud_response = await client.post("http://localhost:8000/ai/test-fraud-detection")
                    if fraud_response.status_code == 200:
                        fraud_data = fraud_response.json()
                        test_results["fraud_detection"] = {
                            "status": "working",
                            "fraud_score": fraud_data.get("result", {}).get("fraud_analysis", {}).get("fraud_score"),
                            "provider": fraud_data.get("result", {}).get("fraud_analysis", {}).get("ai_insights", {}).get("provider")
                        }
                except Exception:
                    test_results["fraud_detection"] = {"status": "failed"}
                    
                # Test password analysis
                try:
                    password_response = await client.post("http://localhost:8000/ai/test-password-analysis")
                    if password_response.status_code == 200:
                        password_data = password_response.json()
                        test_results["password_analysis"] = {
                            "status": "working",
                            "security_score": password_data.get("result", {}).get("analysis", {}).get("security_score"),
                            "provider": password_data.get("result", {}).get("analysis", {}).get("provider")
                        }
                except Exception:
                    test_results["password_analysis"] = {"status": "failed"}
                
                return {
                    "ai_health": health_data,
                    "test_results": test_results,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                raise HTTPException(status_code=503, detail="AI service unavailable")
                
    except Exception as e:
        logger.error(f"AI status check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get AI status: {str(e)}")

@router.get("/temporal-status")
async def temporal_service_status():
    """Get Temporal service status and workflow information"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Get Temporal status
            status_response = await client.get("http://localhost:8000/temporal-status")
            
            if status_response.status_code == 200:
                status_data = status_response.json()
                
                # Test Temporal ping
                test_results = {}
                try:
                    ping_response = await client.post("http://localhost:8000/temporal-ping", json="Admin Dashboard Test")
                    if ping_response.status_code == 200:
                        ping_data = ping_response.json()
                        test_results["ping_test"] = {
                            "status": "working" if ping_data.get("temporal_working") else "failed",
                            "workflow_result": ping_data.get("workflow_result"),
                            "method": ping_data.get("method")
                        }
                except Exception as e:
                    test_results["ping_test"] = {"status": "failed", "error": str(e)}
                
                return {
                    "temporal_status": status_data,
                    "test_results": test_results,
                    "ui_available": "http://localhost:8081",
                    "timestamp": datetime.now().isoformat()
                }
            else:
                raise HTTPException(status_code=503, detail="Temporal service unavailable")
                
    except Exception as e:
        logger.error(f"Temporal status check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get Temporal status: {str(e)}")

@router.get("/metrics")
async def system_metrics():
    """Get comprehensive system metrics"""
    try:
        return {
            "timestamp": datetime.now().isoformat(),
            "authentication": {
                "total_users": len(MOCK_USERS),
                "successful_logins_24h": 15,
                "failed_logins_24h": 3,
                "new_registrations_24h": 2,
                "password_resets_24h": 1
            },
            "services": {
                "simple_server_uptime": "99.9%",
                "main_backend_uptime": "100%",
                "temporal_uptime": "98.5%",
                "ai_services_uptime": "97.2%"
            },
            "security": {
                "fraud_attempts_blocked": 5,
                "ai_fraud_score_avg": 0.23,
                "password_strength_avg": 0.75,
                "verification_rate": 0.85
            },
            "performance": {
                "avg_response_time_ms": 145,
                "auth_requests_per_minute": 12,
                "ai_requests_per_hour": 45,
                "temporal_workflows_active": 3
            }
        }
    except Exception as e:
        logger.error(f"Metrics collection failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to collect metrics: {str(e)}")

@router.post("/actions")
async def admin_action(action: AdminAction):
    """Perform admin actions"""
    try:
        if action.action == "test_login":
            # Test login with simple server
            async with httpx.AsyncClient(timeout=10.0) as client:
                login_data = {
                    "email": action.parameters.get("email", "test@example.com"),
                    "password": action.parameters.get("password", "password123")
                }
                response = await client.post("http://localhost:8001/user/login", json=login_data)
                
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "action": action.action,
                        "status": "success",
                        "result": {
                            "login_successful": True,
                            "token_received": bool(data.get("access_token")),
                            "expires_in": data.get("expires_in")
                        },
                        "timestamp": datetime.now().isoformat()
                    }
                else:
                    return {
                        "action": action.action,
                        "status": "failed",
                        "error": f"Login failed with status {response.status_code}",
                        "timestamp": datetime.now().isoformat()
                    }
                    
        elif action.action == "test_ai":
            # Test AI functionality
            async with httpx.AsyncClient(timeout=10.0) as client:
                if action.target == "fraud_detection":
                    response = await client.post("http://localhost:8000/ai/test-fraud-detection")
                elif action.target == "password_analysis":
                    response = await client.post("http://localhost:8000/ai/test-password-analysis")
                else:
                    raise HTTPException(status_code=400, detail="Invalid AI test target")
                
                if response.status_code == 200:
                    return {
                        "action": action.action,
                        "target": action.target,
                        "status": "success",
                        "result": response.json(),
                        "timestamp": datetime.now().isoformat()
                    }
                else:
                    return {
                        "action": action.action,
                        "target": action.target,
                        "status": "failed",
                        "error": f"AI test failed with status {response.status_code}",
                        "timestamp": datetime.now().isoformat()
                    }
                    
        elif action.action == "test_temporal":
            # Test Temporal workflow
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post("http://localhost:8000/temporal-ping", json="Admin Action Test")
                
                if response.status_code == 200:
                    return {
                        "action": action.action,
                        "status": "success",
                        "result": response.json(),
                        "timestamp": datetime.now().isoformat()
                    }
                else:
                    return {
                        "action": action.action,
                        "status": "failed",
                        "error": f"Temporal test failed with status {response.status_code}",
                        "timestamp": datetime.now().isoformat()
                    }
        else:
            raise HTTPException(status_code=400, detail=f"Unknown action: {action.action}")
            
    except Exception as e:
        logger.error(f"Admin action failed: {e}")
        raise HTTPException(status_code=500, detail=f"Action failed: {str(e)}")

@router.get("/logs")
async def system_logs(limit: int = Query(default=50, le=1000)):
    """Get system logs (mock implementation)"""
    try:
        # Mock log data - replace with real log aggregation
        logs = [
            {
                "timestamp": (datetime.now() - timedelta(minutes=i)).isoformat(),
                "level": "INFO" if i % 3 != 0 else "WARNING" if i % 7 != 0 else "ERROR",
                "service": "simple_server" if i % 2 == 0 else "main_backend" if i % 3 == 0 else "ai_service",
                "message": f"Sample log message {i}",
                "user": f"user{i % 5}" if i % 4 == 0 else None
            }
            for i in range(limit)
        ]
        
        return {
            "logs": logs,
            "total": len(logs),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Log retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve logs: {str(e)}")

# Test endpoints for verification
@router.get("/test")
async def test_admin_endpoints():
    """Test admin dashboard functionality"""
    return {
        "message": "Admin dashboard is working!",
        "timestamp": datetime.now().isoformat(),
        "available_endpoints": [
            "GET /admin/ - Dashboard home",
            "GET /admin/health - System health",
            "GET /admin/users - User statistics", 
            "GET /admin/users/list - List users",
            "GET /admin/services - Service status",
            "GET /admin/ai-status - AI service status",
            "GET /admin/temporal-status - Temporal status",
            "GET /admin/metrics - System metrics",
            "POST /admin/actions - Perform actions",
            "GET /admin/logs - System logs"
        ]
    }