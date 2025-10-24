"""
CyberGuardian AI - FastAPI Backend
Main application entry point
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


# Initialize FastAPI app
app = FastAPI(
    title="CyberGuardian AI API",
    description="Advanced AI-powered cybersecurity platform API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS Configuration - allow frontend to communicate with backend
app.add_middleware(
    CORSMiddleware,
   allow_origins=[
    "http://localhost:3000",  # Next.js dev server
    "http://localhost:3001",
    "http://localhost:8000",  # Backend
    "https://cyberguardian-dashboard.vercel.app",  # Production frontend
    "https://cyberguardian-dashboard-git-main-stefonys-projects.vercel.app",  # Git branch deploys
    "https://*.vercel.app",  # All Vercel preview deployments
],
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers
)

# Include routers
app.include_router(health_router, prefix="/api", tags=["Health"])
app.include_router(threats_router, prefix="/api", tags=["Threats"])
app.include_router(detection_router, prefix="/api", tags=["Detection"])
app.include_router(deception_router, prefix="/api", tags=["Deception"])
app.include_router(ai_insights_router, prefix="/api", tags=["AI Insights"])
app.include_router(analytics_router, prefix="/api", tags=["Analytics"])
app.include_router(settings_router, prefix="/api", tags=["Settings"])
app.include_router(emails_router, prefix="/api", tags=["Email Scanner"])
app.include_router(honeypots_router, prefix="/api", tags=["Honeypots"])
app.include_router(ml_router, prefix="/api", tags=["Machine Learning"])

@app.get("/")
async def root():
    """Root endpoint - API info"""
    return {
        "message": "CyberGuardian AI API",
        "version": "1.0.0",
        "docs": "/api/docs",
        "health": "/api/health",
        "threats": "/api/threats",
        "detection": "/api/detection",
        "deception": "/api/deception",
        "ai": "/api/ai",
        "analytics": "/api/analytics",
        "settings": "/api/settings",
        "emails": "/api/emails",
        "honeypots": "/api/honeypots",
        "ml": "/api/ml"
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