"""
CyberGuardian AI - Admin API
TEMPORARY: Database initialization endpoint
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/init-db")
async def initialize_database():
    """
    TEMPORARY ENDPOINT: Initialize all database tables
    This will create organizations, roles, and other enterprise tables
    """
    try:
        logger.info("🔧 Starting database initialization...")
        
        # Initialize enterprise tables (this also creates base tables)
        from database.schema_enterprise import init_enterprise_tables
        init_enterprise_tables()
        logger.info("✅ Enterprise tables initialized")
        
        # Also init main tables for good measure
        from database.db import get_connection
        from database.init_tables import init_database
        conn = get_connection()
        init_database(conn)
        conn.close()
        logger.info("✅ Main tables initialized")
        
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": "Database initialized successfully!",
                "tables": [
                    "users",
                    "organizations", 
                    "roles",
                    "user_roles",
                    "permissions",
                    "threats",
                    "scans",
                    "and more..."
                ]
            }
        )
        
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to initialize database: {str(e)}"
        )


@router.get("/health")
async def health_check():
    """Simple health check"""
    return {"status": "ok", "message": "Admin API is running"}