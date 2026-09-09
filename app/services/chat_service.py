from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional, Dict
from uuid import UUID
from app.repositories.chat_repository import ChatRepository
from app.repositories.device_repository import DeviceRepository
from app.models.chat import Conversation, Message
from app.schemas.chat import ConversationResponse, MessageResponse, EnvelopeMessageResponse
from fastapi import HTTPException, status
import logging

logger = logging.getLogger("chat-service")

class ChatService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.chat_repo = ChatRepository(db)
        self.device_repo = DeviceRepository(db)

    async def create_conversation(self, creator_id: UUID, participant_ids: List[UUID], name: Optional[str] = None) -> Conversation:
        # Enforce that creator is in participants
        unique_participants = list(set(participant_ids + [creator_id]))
        
        # Check if 1-to-1 conversation already exists
        if len(unique_participants) == 2:
            existing = await self.chat_repo.get_conversation_between_users(unique_participants[0], unique_participants[1])
            if existing:
                return existing
        
        is_group = len(unique_participants) > 2
        conv = await self.chat_repo.create_conversation(
            participants=unique_participants,
            is_group=is_group,
            name=name
        )
        await self.db.commit()
        return conv

    async def list_user_conversations(self, user_id: UUID) -> List[Dict]:
        conv_tuples = await self.chat_repo.get_user_conversations(user_id)
        results = []
        for conv, participants in conv_tuples:
            results.append({
                "conversation_id": conv.id,
                "is_group": conv.is_group,
                "name": conv.name,
                "created_at": conv.created_at,
                "participants": participants
            })
        return results

    async def send_message(
        self,
        sender_id: UUID,
        sender_device_id: str,
        conversation_id: UUID,
        envelopes: Dict[str, str]
    ) -> Message:
        # 1. Verify conversation exists
        conv = await self.chat_repo.get_conversation(conversation_id)
        if not conv:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Conversation not found"
            )

        # 2. Verify sender is a participant
        participants = await self.chat_repo.get_conversation_participants(conversation_id)
        if sender_id not in participants:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not a participant in this conversation"
            )

        # 3. Save the message and envelopes
        msg = await self.chat_repo.save_message(
            conversation_id=conversation_id,
            sender_id=sender_id,
            sender_device_id=sender_device_id,
            envelopes=envelopes
        )
        await self.db.commit()

        # 4. Notify active WebSockets (will be handled by calling WS layer or manager)
        # We will import the WebSocket manager inside route or handle it reactively
        return msg

    async def get_device_envelopes(
        self, user_id: UUID, device_id: str, unread_only: bool = True, undelivered_only: bool = False
    ) -> List[Dict]:
        # Verify device belongs to user
        device = await self.device_repo.get_device(user_id, device_id)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Device does not belong to you or does not exist"
            )

        envelopes_data = await self.chat_repo.get_device_envelopes(
            device_id, unread_only=unread_only, undelivered_only=undelivered_only
        )
        results = []
        for env, msg in envelopes_data:
            results.append({
                "envelope_id": env.id,
                "message_id": msg.id,
                "conversation_id": msg.conversation_id,
                "sender_id": msg.sender_id,
                "sender_device_id": msg.sender_device_id,
                "recipient_device_id": env.recipient_device_id,
                "encrypted_payload": env.encrypted_payload,
                "status": env.status,
                "created_at": msg.created_at,
                "delivered_at": env.delivered_at,
                "read_at": env.read_at
            })
        return results

    async def mark_envelope_read(self, user_id: UUID, device_id: str, envelope_id: int):
        # Verify device belongs to user
        device = await self.device_repo.get_device(user_id, device_id)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Device registration mismatch"
            )

        await self.chat_repo.mark_envelope_status(envelope_id, "read")
        await self.db.commit()

    async def mark_conversation_read(self, user_id: UUID, device_id: str, conversation_id: UUID) -> List[int]:
        # Verify device belongs to user
        device = await self.device_repo.get_device(user_id, device_id)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Device registration mismatch"
            )

        updated_ids = await self.chat_repo.mark_conversation_envelopes_read(conversation_id, device_id)
        await self.db.commit()
        return updated_ids

    async def update_presence(self, user_id: UUID, status: str):
        await self.chat_repo.update_presence(user_id, status)
        await self.db.commit()
