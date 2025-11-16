"""
CyberGuardian AI - FastAPI Backend
Main application entry point with Rate Limiting & Robust CORS
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
from api.protection import router as protection_router
from api.ml import router as ml_router
from api import threats, detection, deception, honeypots, ml, ai_insights, analytics, emails, settings, health
from api.auth import router as auth_router
from contextlib import asynccontextmanager
from api.websocket import router as websocket_router
from api.google_oauth import router as google_oauth_router
from api.scans import router as scans_router
from api.quarantine import router as quarantine_router
from api.exclusions import router as exclusions_router
from api.signatures import router as signatures_router
from api.threat_intel import router as threat_intel_router
from api.remediation import router as remediation_router
from api import mitre
from api.integrity import router as integrity_router
from api.watchdog import router as watchdog_router
from api.process_protection import router as process_protection_router
from api.updates import router as updates_router
from api.configuration import router as configuration_router
from api.performance import router as performance_router

# ============================================
# Logging (set up BEFORE app creation)
# ============================================
from core.logger import setup_logging, get_logger
from middleware.logging_middleware import LoggingMiddleware

# Rate Limiting
from middleware.rate_limiter import limiter, rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

# Initialize admin user on startup
from database.init_admin import init_admin_user

from core.scheduler import start_scheduler, stop_scheduler

# ============================================
# Setup Logging (BEFORE app creation)
# ============================================
logger = setup_logging(level="INFO")
app_logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan events"""
    # Startup
    app_logger.info("🚀 Starting CyberGuardian AI Backend...")
    print("🚀 Starting CyberGuardian AI Backend...")
    print("🛡️  Rate Limiting: ENABLED")
    print("   🔐 Auth: 5 req/15min")
    print("   📊 Read: 100 req/min")
    print("   ✍️  Write: 30 req/min")
    print("   🔥 Threat Intel: 60 req/min")
    init_admin_user()

    # Start background scheduler
    start_scheduler()
    print("⏰ Automated Intelligence Updates: ENABLED (every 6 hours)")

    # ✨ Start performance monitoring
    try:
        from core.performance_monitor import get_performance_monitor
        monitor = get_performance_monitor()
        monitor.start_monitoring(interval=5.0)
        print("📊 Performance Monitoring: ENABLED (5s interval)")
    except Exception as e:
        print(f"⚠️  Performance monitoring failed to start: {e}")

    yield

    # Shutdown
    stop_scheduler()

    # ✨ Stop performance monitoring
    try:
        from core.performance_monitor import get_performance_monitor
        monitor = get_performance_monitor()
        monitor.stop_monitoring()
    except Exception:
        pass

    app_logger.info("👋 Shutting down...")
    print("👋 Shutting down...")


# Initialize FastAPI app
app = FastAPI(
    title="CyberGuardian AI",
    description="Advanced AI-Powered Cybersecurity Platform with Rate Limiting",
    version="1.4.0",
    lifespan=lifespan,
)

# ============================================
# CORS MUST BE FIRST (before any other middleware)
# ============================================
ALLOWED_ORIGINS = [
    # Local dev
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:8000",
    # Production / Preview Frontends
    "https://cyberguardian-dashboard.vercel.app",
    "https://cyberguardian-dashboard-git-main-stefonys-projects.vercel.app",
    "https://cyberguardian-dashboard-novx7ny4q-stefonys-projects.vercel.app",
    # custom domains => add here later
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# Other middlewares (AFTER CORS)
# ============================================
app.add_middleware(LoggingMiddleware)

# Rate Limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

# ============================================
# Routers
# ============================================
# Health check - NO rate limit
app.include_router(health_router, prefix="/api", tags=["Health"])

# Authentication - STRICT rate limit (applied in auth.py router)
app.include_router(auth_router, prefix="/api", tags=["Authentication"])

# Feature routers
app.include_router(threats_router, prefix="/api", tags=["Threats"])
app.include_router(detection_router, prefix="/api", tags=["Detection"])
app.include_router(deception_router, prefix="/api", tags=["Deception"])
app.include_router(ai_insights_router, prefix="/api", tags=["AI Insights"])
app.include_router(analytics_router, prefix="/api/analytics", tags=["Analytics"])
app.include_router(emails_router, prefix="/api/emails", tags=["Emails"])
app.include_router(settings_router, prefix="/api", tags=["Settings"])
app.include_router(honeypots_router, prefix="/api/honeypots", tags=["Honeypots"])
app.include_router(protection_router)
app.include_router(ml_router, prefix="/api", tags=["Machine Learning"])
app.include_router(websocket_router, tags=["WebSocket"])
app.include_router(google_oauth_router, prefix="/api", tags=["Auth"])
app.include_router(scans_router)
app.include_router(quarantine_router)
app.include_router(exclusions_router, tags=["Exclusions"])
app.include_router(signatures_router, prefix="/api/signatures", tags=["Signatures"])
app.include_router(threat_intel_router, prefix="/api/threat-intel", tags=["Threat Intelligence"])
app.include_router(mitre.router, prefix="/api/mitre", tags=["MITRE ATT&CK"])
app.include_router(remediation_router, tags=["Remediation"])
app.include_router(integrity_router)
app.include_router(watchdog_router)
app.include_router(process_protection_router)
app.include_router(updates_router)
app.include_router(configuration_router)
app.include_router(performance_router, tags=["Performance"])


# ============================================
# Root
# ============================================
@app.get("/")
async def root():
    """Root endpoint - API info"""
    return {
        "message": "CyberGuardian AI API",
        "version": "1.4.0",
        "status": "✅ Protected with Rate Limiting & Logging",
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
        "signatures": "/api/signatures",
        "threat_intel": "/api/threat-intel",
        "remediation": "/api/remediation",
        "performance": "/api/performance",
        "ws": "/ws",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
    
    