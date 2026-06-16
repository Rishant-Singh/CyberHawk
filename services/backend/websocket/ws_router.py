"""WebSocket router — real-time threat streaming endpoint."""

import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from jose import JWTError

from core.config import settings
from core.security import decode_token
from services.websocket_manager import manager

ws_router = APIRouter()
logger = logging.getLogger(__name__)


@ws_router.websocket("/ws/live")
async def websocket_live(
    websocket: WebSocket,
    token: str = Query(..., description="JWT access token"),
):
    """
    WebSocket endpoint for real-time threat streaming.
    Requires a valid JWT token as query parameter.
    
    Connect: ws://localhost:8000/ws/live?token=<access_token>
    
    Message types received:
    - THREAT_EVENT: New threat detected
    - SYSTEM_HEALTH: System metrics update
    """
    # Authenticate WebSocket connection
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        if not user_id:
            await websocket.close(code=4001, reason="Invalid token")
            return
    except Exception:
        await websocket.close(code=4001, reason="Authentication failed")
        return

    # Connect client
    await manager.connect(websocket, room="live")

    # Send welcome message
    await websocket.send_text(json.dumps({
        "type": "CONNECTED",
        "data": {
            "message": "Connected to CTI real-time threat stream",
            "user_id": user_id,
            "clients": manager.connection_count,
        }
    }))

    try:
        while True:
            # Keep connection alive, handle client messages
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "PING":
                    await websocket.send_text(json.dumps({"type": "PONG"}))
            except json.JSONDecodeError:
                pass

    except WebSocketDisconnect:
        manager.disconnect(websocket, room="live")
        logger.info(f"WebSocket client disconnected: {user_id[:8]}")
