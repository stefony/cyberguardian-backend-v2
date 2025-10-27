"""
CyberGuardian AI - FastAPI Backend
Main application entry point with Rate Limiting
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.health import router as health_router
from api.threats import router as threats_router
from api.detection import router as detection_router
from api.deception import router as deception_router
from api.ai_insights import router as ai_insights_router
from api.analytics import router as analytics_router
from api.settings import router as settings_router
from api.emails import router as emails_router
from api.honeypots import router as honeypots_router
from api.ml import router as ml_router
from api import threats, detection, deception, honeypots, ml, ai_insights, analytics, emails, settings, health
from api.auth import router as auth_router
from contextlib import asynccontextmanager
from api.websocket import router as websocket_router

# Import Rate Limiting
from middleware.rate_limiter import limiter, rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

# Initialize admin user on startup
from database.init_admin import init_admin_user

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan events"""
    # Startup
    print("🚀 Starting CyberGuardian AI Backend...")
    print("🛡️  Rate Limiting: ENABLED")
    print("   🔐 Auth: 5 req/15min")
    print("   📊 Read: 100 req/min")
    print("   ✍️  Write: 30 req/min")
    print("   🔥 Threat Intel: 60 req/min")
    init_admin_user()
    yield
    # Shutdown
    print("👋 Shutting down...")

# Initialize FastAPI app
app = FastAPI(
    title="CyberGuardian AI",
    description="Advanced AI-Powered Cybersecurity Platform with Rate Limiting",
    version="1.0.0",
    lifespan=lifespan
)

# ============================================
# Add Rate Limiting to App
# ============================================
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

# CORS Configuration - allow frontend to communicate with backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # Next.js dev server
        "http://localhost:3001",
        "http://localhost:8000",  # Backend
        "https://cyberguardian-dashboard.vercel.app",  # Production frontend
        "https://cyberguardian-dashboard-git-main-stefonys-projects.vercel.app",  # Git branch deploys
    ],
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers
    allow_origin_regex=r"https://.*\.vercel\.app",  # All Vercel domains
)

# Include routers
# Health check - NO rate limit
app.include_router(health_router, prefix="/api", tags=["Health"])

# Authentication - STRICT rate limit (applied in auth.py router)
app.include_router(auth_router, prefix="/api", tags=["Authentication"])

# Threats, Detection, Deception - Rate limited (applied in respective routers)
app.include_router(threats_router, prefix="/api", tags=["Threats"])
app.include_router(detection_router, prefix="/api", tags=["Detection"])
app.include_router(deception_router, prefix="/api", tags=["Deception"])
app.include_router(ai_insights_router, prefix="/api", tags=["AI Insights"])
app.include_router(analytics_router, prefix="/api", tags=["Analytics"])
app.include_router(settings_router, prefix="/api", tags=["Settings"])
app.include_router(emails_router, prefix="/api", tags=["Email Scanner"])
app.include_router(honeypots_router, prefix="/api", tags=["Honeypots"])
app.include_router(ml_router, prefix="/api", tags=["Machine Learning"])
app.include_router(websocket_router, tags=["WebSocket"])  # No prefix for WebSocket

@app.get("/")
async def root():
    """Root endpoint - API info"""
    return {
        "message": "CyberGuardian AI API",
        "version": "1.0.0",
        "status": "✅ Protected with Rate Limiting",
        "docs": "/docs",
        "health": "/api/health",
        "threats": "/api/threats",
        "detection": "/api/detection",
        "deception": "/api/deception",
        "ai": "/api/ai",
        "analytics": "/api/analytics",
        "settings": "/api/settings",
        "emails": "/api/emails",
        "honeypots": "/api/honeypots",
        "ml": "/api/ml",
        "ws": "/ws"
    }

# Run with: uvicorn main:app --reload --host 0.0.0.0 --port 8000
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Auto-reload on code changes
        log_level="info"
    )