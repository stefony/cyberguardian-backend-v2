"""
Logging Middleware - Log all API requests and responses
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import time
import json
from core.logger import get_logger

logger = get_logger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware to log all HTTP requests and responses
    """
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next):
        """Log request and response"""
        
        # Start timer
        start_time = time.time()
        
        # Extract request info
        request_data = {
            "method": request.method,
            "url": str(request.url),
            "path": request.url.path,
            "client_ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
        }
        
        # Log incoming request
        logger.info(
            f"Incoming request: {request.method} {request.url.path}",
            extra={"extra_data": request_data}
        )
        
        # Process request
        try:
            response = await call_next(request)
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Log response
            response_data = {
                **request_data,
                "status_code": response.status_code,
                "duration_ms": round(duration * 1000, 2),
            }
            
            # Choose log level based on status code
            if response.status_code >= 500:
                logger.error(
                    f"Request failed: {request.method} {request.url.path} - {response.status_code}",
                    extra={"extra_data": response_data}
                )
            elif response.status_code >= 400:
                logger.warning(
                    f"Client error: {request.method} {request.url.path} - {response.status_code}",
                    extra={"extra_data": response_data}
                )
            else:
                logger.info(
                    f"Request completed: {request.method} {request.url.path} - {response.status_code}",
                    extra={"extra_data": response_data}
                )
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            
            # Log exception
            error_data = {
                **request_data,
                "duration_ms": round(duration * 1000, 2),
                "error": str(e),
                "error_type": type(e).__name__,
            }
            
            logger.exception(
                f"Request exception: {request.method} {request.url.path}",
                extra={"extra_data": error_data}
            )
            
            raise