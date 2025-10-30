"""
WebSocket API Router
Real-time communication endpoints
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from core.websocket_manager import manager
from datetime import datetime
import asyncio
import json


router = APIRouter(prefix="/api/ws", tags=["WebSocket"])


@router.websocket("/connect")
async def websocket_endpoint(
    websocket: WebSocket,
    client_id: str = Query(None)
):
    """
    Main WebSocket endpoint for real-time updates
    """
    await manager.connect(websocket, client_id)
    
    try:
        while True:
            # Receive messages from client
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                message_type = message.get("type")
                
                # Handle ping/pong for connection keepalive
                if message_type == "ping":
                    await manager.send_personal_message({
                        "type": "pong",
                        "timestamp": datetime.utcnow().isoformat()
                    }, websocket)
                
                # Handle client requests
                elif message_type == "request_stats":
                    # Client requesting current stats
                    # You can implement this to send current system stats
                    pass
                
                elif message_type == "subscribe":
                    # Client subscribing to specific events
                    channels = message.get("channels", [])
                    # Implement subscription logic if needed
                    pass
                
            except json.JSONDecodeError:
                await manager.send_personal_message({
                    "type": "error",
                    "message": "Invalid JSON format"
                }, websocket)
    
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    
    except Exception as e:
        print(f"WebSocket error: {e}")
        manager.disconnect(websocket)


@router.get("/status")
async def get_websocket_status():
    """
    Get WebSocket server status
    """
    return {
        "status": "active",
        "active_connections": manager.get_active_connections_count(),
        "connections": manager.get_connection_info(),
        "timestamp": datetime.utcnow().isoformat()
    }