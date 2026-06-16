"""WebSocket manager — broadcasts real-time threat events to connected clients."""

import json
import logging
from collections import defaultdict
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections by room (e.g., 'live', 'alerts')."""

    def __init__(self):
        self._connections: dict[str, list[WebSocket]] = defaultdict(list)
        self._total_connections = 0

    async def connect(self, websocket: WebSocket, room: str = "live"):
        await websocket.accept()
        self._connections[room].append(websocket)
        self._total_connections += 1
        logger.info(f"Client connected to room '{room}'. Total: {self._total_connections}")

    def disconnect(self, websocket: WebSocket, room: str = "live"):
        if websocket in self._connections[room]:
            self._connections[room].remove(websocket)
            self._total_connections -= 1
        logger.info(f"Client disconnected from room '{room}'. Total: {self._total_connections}")

    async def broadcast(self, message: dict, room: str = "live"):
        """Broadcast a message to all clients in a room."""
        if not self._connections[room]:
            return

        dead_connections = []
        payload = json.dumps(message)

        for connection in self._connections[room]:
            try:
                await connection.send_text(payload)
            except Exception:
                dead_connections.append(connection)

        # Clean up dead connections
        for dead in dead_connections:
            self.disconnect(dead, room)

    async def broadcast_threat(self, threat_data: dict):
        """Broadcast a scored threat event to the 'live' room."""
        message = {
            "type": "THREAT_EVENT",
            "data": threat_data,
        }
        await self.broadcast(message, room="live")

    async def broadcast_system_health(self, health_data: dict):
        """Broadcast system health metrics."""
        message = {
            "type": "SYSTEM_HEALTH",
            "data": health_data,
        }
        await self.broadcast(message, room="live")

    @property
    def connection_count(self) -> int:
        return self._total_connections


# Singleton
manager = ConnectionManager()
