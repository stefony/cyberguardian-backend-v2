"""
PostgreSQL Database Connection for Production
"""

import os
from typing import Optional
import psycopg2
from psycopg2.extras import RealDictCursor
import logging

logger = logging.getLogger(__name__)

def get_connection():
    """
    Get PostgreSQL database connection
    Uses DATABASE_URL from environment (Railway provides this)
    Falls back to SQLite if DATABASE_URL not present
    """
    database_url = os.getenv("DATABASE_URL")
    
    if database_url:
        # PostgreSQL connection
        try:
            conn = psycopg2.connect(
                database_url,
                cursor_factory=RealDictCursor
            )
            logger.info("✅ Connected to PostgreSQL")
            return conn
        except Exception as e:
            logger.error(f"❌ PostgreSQL connection failed: {e}")
            raise
    else:
        # Fallback to SQLite for local development
        import sqlite3
        from pathlib import Path
        
        DB_PATH = Path(__file__).parent / "cyberguardian.db"
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        logger.info("📁 Connected to SQLite (local)")
        return conn


def convert_query_placeholders(query: str, params: list) -> tuple:
    """
    Convert SQLite ? placeholders to PostgreSQL %s placeholders
    """
    # If using PostgreSQL, convert ? to %s
    if os.getenv("DATABASE_URL"):
        # Replace all ? with %s
        converted_query = query.replace('?', '%s')
        return (converted_query, tuple(params))
    else:
        # SQLite - keep as is
        return (query, params)