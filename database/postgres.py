"""
PostgreSQL Connection Module with Query Wrapper
Handles PostgreSQL vs SQLite auto-detection and placeholder conversion
"""
import os
import logging

logger = logging.getLogger(__name__)


def get_connection():
    """
    Get database connection - auto-detects PostgreSQL or SQLite
    
    Returns:
        connection object (psycopg2 or sqlite3)
    """
    database_url = os.environ.get("DATABASE_URL")
    
    if database_url and database_url.startswith("postgresql://"):
        # PostgreSQL (Production - Railway)
        try:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            
            logger.info("🐘 Using PostgreSQL database")
            conn = psycopg2.connect(database_url, cursor_factory=RealDictCursor)
            return conn
        except Exception as e:
            logger.error(f"❌ PostgreSQL connection failed: {e}")
            raise
    else:
        # SQLite (Local Development)
        import sqlite3
        
        logger.info("💾 Using SQLite database (local)")
        conn = sqlite3.connect("cyberguardian.db", check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn


def convert_query_placeholders(query: str, params: tuple) -> tuple:
    """
    Convert SQLite-style ? placeholders to PostgreSQL-style %s placeholders
    
    Args:
        query: SQL query string with ? placeholders
        params: tuple of parameters
        
    Returns:
        (query, params) tuple with converted placeholders
        
    Example:
        >>> query = "SELECT * FROM users WHERE id = ? AND name = ?"
        >>> params = (1, "John")
        >>> convert_query_placeholders(query, params)
        ("SELECT * FROM users WHERE id = %s AND name = %s", (1, "John"))
    """
    database_url = os.environ.get("DATABASE_URL")
    
    # Only convert if using PostgreSQL
    if database_url and database_url.startswith("postgresql://"):
        converted_query = query.replace("?", "%s")
        return (converted_query, params)
    
    # Return unchanged for SQLite
    return (query, params)


def execute_query(cursor, query: str, params=None):
    """
    Execute SQL query with automatic placeholder conversion
    
    This wrapper function:
    1. Automatically converts ? → %s for PostgreSQL
    2. Handles both parameterized and non-parameterized queries
    3. Returns the cursor for method chaining
    
    Args:
        cursor: Database cursor object
        query: SQL query string (can use ? placeholders)
        params: Optional tuple/list of parameters
        
    Returns:
        cursor object (for method chaining like .fetchone())
        
    Example:
        >>> cursor = conn.cursor()
        >>> execute_query(cursor, "SELECT * FROM users WHERE id = ?", (1,))
        >>> user = cursor.fetchone()
    """
    if params:
        # Convert placeholders if needed
        query, params = convert_query_placeholders(query, params)
        cursor.execute(query, params)
    else:
        # No parameters - execute directly
        cursor.execute(query)
    
    return cursor


def execute_many(cursor, query: str, params_list):
    """
    Execute SQL query multiple times with different parameters
    
    Args:
        cursor: Database cursor object
        query: SQL query string (can use ? placeholders)
        params_list: List of parameter tuples
        
    Returns:
        cursor object
        
    Example:
        >>> cursor = conn.cursor()
        >>> execute_many(cursor, "INSERT INTO users (name) VALUES (?)", 
        ...              [("John",), ("Jane",), ("Bob",)])
    """
    database_url = os.environ.get("DATABASE_URL")
    
    # Convert placeholders if using PostgreSQL
    if database_url and database_url.startswith("postgresql://"):
        converted_query = query.replace("?", "%s")
        cursor.executemany(converted_query, params_list)
    else:
        cursor.executemany(query, params_list)
    
    return cursor