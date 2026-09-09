from fastapi import WebSocket
from typing import Dict, Tuple, List
from uuid import UUID
import json
import logging
from app.database.session import async_session_maker
from app.repositories.chat_repository import ChatRepository

logger = logging.getLogger("websocket-manager")

class WebSocketManager:
    def __init__(self):
        # Maps (user_id, device_id) -> WebSocket
        self.active_connections: Dict[Tuple[UUID, str], WebSocket] = {}

    async def connect(self, user_id: UUID, device_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[(user_id, device_id)] = websocket
        logger.info(f"WebSocket connected: User {user_id}, Device {device_id}")
        
        # Update user presence status to online
        async with async_session_maker() as db:
            chat_repo = ChatRepository(db)
            await chat_repo.update_presence(user_id, "online")
            await db.commit()
            await self.broadcast_presence(user_id, "online")

    async def disconnect(self, user_id: UUID, device_id: str):
        if (user_id, device_id) in self.active_connections:
            del self.active_connections[(user_id, device_id)]
            logger.info(f"WebSocket disconnected: User {user_id}, Device {device_id}")

        # Check if the user has any other active devices online
        user_has_other_devices = any(uid == user_id for uid, _ in self.active_connections.keys())
        if not user_has_other_devices:
            async with async_session_maker() as db:
                chat_repo = ChatRepository(db)
                await chat_repo.update_presence(user_id, "offline")
                await db.commit()
                await self.broadcast_presence(user_id, "offline")

    async def send_to_device(self, user_id: UUID, device_id: str, data: dict) -> bool:
        """Sends a real-time message to a specific active online device. Returns True if successful."""
        ws = self.active_connections.get((user_id, device_id))
        if ws:
            try:
                await ws.send_text(json.dumps(data))
                return True
            except Exception as e:
                logger.error(f"Error sending message to user {user_id} device {device_id}: {str(e)}")
                # Clean up broken connection
                await self.disconnect(user_id, device_id)
        return False

    async def broadcast_presence(self, user_id: UUID, status: str):
        """Broadcasts a user's presence update to all participants they share conversations with."""
        async with async_session_maker() as db:
            chat_repo = ChatRepository(db)
            
            # Find all conversations the user is in
            conv_tuples = await chat_repo.get_user_conversations(user_id)
            contact_ids = set()
            for _, participants in conv_tuples:
                for p_id in participants:
                    if p_id != user_id:
                        contact_ids.add(p_id)

            if not contact_ids:
                return

            event = {
                "type": "presence",
                "user_id": str(user_id),
                "status": status
            }

            # Send presence event to all online devices of contacts
            for uid, dev_id in list(self.active_connections.keys()):
                if uid in contact_ids:
                    await self.send_to_device(uid, dev_id, event)

    async def broadcast_typing(self, conversation_id: UUID, sender_id: UUID, is_typing: bool):
        """Broadcasts typing indicators to other participants in the conversation."""
        async with async_session_maker() as db:
            chat_repo = ChatRepository(db)
            participants = await chat_repo.get_conversation_participants(conversation_id)
            
            event = {
                "type": "typing",
                "conversation_id": str(conversation_id),
                "user_id": str(sender_id),
                "is_typing": is_typing
            }

            for uid, dev_id in list(self.active_connections.keys()):
                if uid in participants and uid != sender_id:
                    await self.send_to_device(uid, dev_id, event)

# Global singleton manager instance
ws_manager = WebSocketManager()
