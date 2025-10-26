"""
WebSocket Connection Manager
Handles real-time connections and broadcasts
"""

from typing import Dict, List, Set
from fastapi import WebSocket
import json
import asyncio
from datetime import datetime


class ConnectionManager:
    def __init__(self):
        # Active WebSocket connections
        self.active_connections: List[WebSocket] = []
        # Connection metadata
        self.connection_info: Dict[WebSocket, dict] = {}
        
    async def connect(self, websocket: WebSocket, client_id: str = None):
        """Accept and register a new WebSocket connection"""
        await websocket.accept()
        self.active_connections.append(websocket)
        
        # Store connection metadata
        self.connection_info[websocket] = {
            "client_id": client_id,
            "connected_at": datetime.utcnow().isoformat(),
            "last_ping": datetime.utcnow().isoformat()
        }
        
        print(f"✅ WebSocket connected: {client_id or 'anonymous'} (Total: {len(self.active_connections)})")
        
        # Send welcome message
        await self.send_personal_message({
            "type": "connection",
            "status": "connected",
            "client_id": client_id,
            "timestamp": datetime.utcnow().isoformat()
        }, websocket)
    
    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            
            client_id = self.connection_info.get(websocket, {}).get("client_id", "unknown")
            if websocket in self.connection_info:
                del self.connection_info[websocket]
            
            print(f"❌ WebSocket disconnected: {client_id} (Remaining: {len(self.active_connections)})")
    
    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send message to a specific client"""
        try:
            await websocket.send_json(message)
        except Exception as e:
            print(f"Error sending personal message: {e}")
            self.disconnect(websocket)
    
    async def broadcast(self, message: dict, exclude: WebSocket = None):
        """Broadcast message to all connected clients"""
        disconnected = []
        
        for connection in self.active_connections:
            if connection == exclude:
                continue
                
            try:
                await connection.send_json(message)
            except Exception as e:
                print(f"Error broadcasting to client: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            self.disconnect(conn)
    
    async def broadcast_threat_update(self, threat_data: dict):
        """Broadcast new threat detection"""
        message = {
            "type": "threat_update",
            "data": threat_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast(message)
        print(f"📡 Broadcast: New threat - {threat_data.get('title', 'Unknown')}")
    
    async def broadcast_scan_progress(self, scan_data: dict):
        """Broadcast scan progress update"""
        message = {
            "type": "scan_progress",
            "data": scan_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast(message)
    
    async def broadcast_honeypot_event(self, event_data: dict):
        """Broadcast honeypot attack event"""
        message = {
            "type": "honeypot_event",
            "data": event_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast(message)
        print(f"🍯 Broadcast: Honeypot event - {event_data.get('type', 'Unknown')}")
    
    async def broadcast_stats_update(self, stats_data: dict):
        """Broadcast statistics update"""
        message = {
            "type": "stats_update",
            "data": stats_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast(message)
    
    def get_active_connections_count(self) -> int:
        """Get number of active connections"""
        return len(self.active_connections)
    
    def get_connection_info(self) -> List[dict]:
        """Get info about all active connections"""
        return [
            {
                "client_id": info.get("client_id"),
                "connected_at": info.get("connected_at"),
                "last_ping": info.get("last_ping")
            }
            for info in self.connection_info.values()
        ]


# Global WebSocket manager instance
manager = ConnectionManager()