from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import and_, or_, func
from typing import List, Optional, Tuple, Dict
from uuid import UUID
from app.models.chat import Conversation, ConversationParticipant, Message, MessageEnvelope, UserPresence
import datetime

class ChatRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_conversation_between_users(self, user1: UUID, user2: UUID) -> Optional[Conversation]:
        """Checks if a 1-to-1 conversation already exists between two users."""
        # Find conversations that have exactly these two participants and is_group is False
        q = (
            select(Conversation)
            .join(ConversationParticipant)
            .filter(Conversation.is_group == False)
            .filter(ConversationParticipant.user_id.in_([user1, user2]))
            .group_by(Conversation.id)
            .having(func.count(ConversationParticipant.user_id) == 2)
        )
        res = await self.db.execute(q)
        # We need to verify that there are indeed only 2 participants in total for this conversation
        for conv in res.scalars().all():
            part_count_q = select(func.count(ConversationParticipant.user_id)).filter(ConversationParticipant.conversation_id == conv.id)
            part_count_res = await self.db.execute(part_count_q)
            if part_count_res.scalar() == 2:
                return conv
        return None

    async def create_conversation(self, participants: List[UUID], is_group: bool = False, name: Optional[str] = None) -> Conversation:
        """Creates a new conversation and adds the participants."""
        conversation = Conversation(is_group=is_group, name=name)
        self.db.add(conversation)
        await self.db.flush()

        for p_id in participants:
            part = ConversationParticipant(conversation_id=conversation.id, user_id=p_id)
            self.db.add(part)
        
        await self.db.flush()
        return conversation

    async def get_conversation(self, conversation_id: UUID) -> Optional[Conversation]:
        res = await self.db.execute(select(Conversation).filter(Conversation.id == conversation_id))
        return res.scalars().first()

    async def get_conversation_participants(self, conversation_id: UUID) -> List[UUID]:
        res = await self.db.execute(
            select(ConversationParticipant.user_id).filter(ConversationParticipant.conversation_id == conversation_id)
        )
        return list(res.scalars().all())

    async def get_user_conversations(self, user_id: UUID) -> List[Tuple[Conversation, List[UUID]]]:
        """Fetches all conversations a user is part of, including participant lists."""
        # 1. Fetch conversation IDs user is part of
        user_convs_q = select(ConversationParticipant.conversation_id).filter(ConversationParticipant.user_id == user_id)
        user_convs_res = await self.db.execute(user_convs_q)
        conv_ids = list(user_convs_res.scalars().all())

        if not conv_ids:
            return []

        # 2. Fetch conversations
        convs_q = select(Conversation).filter(Conversation.id.in_(conv_ids))
        convs_res = await self.db.execute(convs_q)
        conversations = convs_res.scalars().all()

        # 3. For each conversation, fetch all participants
        result = []
        for conv in conversations:
            participants = await self.get_conversation_participants(conv.id)
            result.append((conv, participants))
        
        return result

    async def save_message(
        self,
        conversation_id: UUID,
        sender_id: UUID,
        sender_device_id: str,
        envelopes: Dict[str, str]
    ) -> Message:
        """Saves a message and creates individual ciphertext envelopes for target devices in a single transaction."""
        message = Message(
            conversation_id=conversation_id,
            sender_id=sender_id,
            sender_device_id=sender_device_id
        )
        self.db.add(message)
        await self.db.flush()

        for device_id, payload in envelopes.items():
            envelope = MessageEnvelope(
                message_id=message.id,
                recipient_device_id=device_id,
                encrypted_payload=payload,
                status="sent"
            )
            self.db.add(envelope)

        await self.db.flush()
        return message

    async def get_device_envelopes(self, recipient_device_id: str, unread_only: bool = True) -> List[Tuple[MessageEnvelope, Message]]:
        """Retrieves messages/envelopes addressed to a specific device."""
        q = select(MessageEnvelope, Message).join(Message, MessageEnvelope.message_id == Message.id)
        if unread_only:
            q = q.filter(MessageEnvelope.recipient_device_id == recipient_device_id, MessageEnvelope.status != "read")
        else:
            q = q.filter(MessageEnvelope.recipient_device_id == recipient_device_id)
        
        q = q.order_by(Message.created_at.asc())
        res = await self.db.execute(q)
        return [(row[0], row[1]) for row in res.all()]

    async def mark_envelope_status(self, envelope_id: int, status: str) -> Optional[MessageEnvelope]:
        res = await self.db.execute(select(MessageEnvelope).filter(MessageEnvelope.id == envelope_id))
        envelope = res.scalars().first()
        if envelope:
            envelope.status = status
            if status == "delivered" and not envelope.delivered_at:
                envelope.delivered_at = func.now()
            elif status == "read" and not envelope.read_at:
                envelope.read_at = func.now()
                if not envelope.delivered_at:
                    envelope.delivered_at = func.now()
            await self.db.flush()
        return envelope

    async def mark_conversation_envelopes_read(self, conversation_id: UUID, recipient_device_id: str) -> List[int]:
        """Marks all envelopes as read for a specific conversation and recipient device."""
        q = (
            select(MessageEnvelope)
            .join(Message, MessageEnvelope.message_id == Message.id)
            .filter(
                Message.conversation_id == conversation_id,
                MessageEnvelope.recipient_device_id == recipient_device_id,
                MessageEnvelope.status != "read"
            )
        )
        res = await self.db.execute(q)
        envelopes = res.scalars().all()
        updated_ids = []
        for env in envelopes:
            env.status = "read"
            env.read_at = func.now()
            if not env.delivered_at:
                env.delivered_at = func.now()
            updated_ids.append(env.id)
        if updated_ids:
            await self.db.flush()
        return updated_ids

    async def update_presence(self, user_id: UUID, status: str) -> UserPresence:
        """Upserts a user's online presence status."""
        res = await self.db.execute(select(UserPresence).filter(UserPresence.user_id == user_id))
        presence = res.scalars().first()
        if not presence:
            presence = UserPresence(user_id=user_id, status=status)
            self.db.add(presence)
        else:
            presence.status = status
            presence.last_active_at = func.now()
        await self.db.flush()
        return presence

    async def get_presence(self, user_id: UUID) -> Optional[UserPresence]:
        res = await self.db.execute(select(UserPresence).filter(UserPresence.user_id == user_id))
        return res.scalars().first()

    async def mark_envelope_status_by_device(self, message_id: UUID, device_id: str, status: str) -> Optional[MessageEnvelope]:
        res = await self.db.execute(
            select(MessageEnvelope).filter(
                MessageEnvelope.message_id == message_id,
                MessageEnvelope.recipient_device_id == device_id
            )
        )
        envelope = res.scalars().first()
        if envelope:
            envelope.status = status
            if status == "delivered" and not envelope.delivered_at:
                envelope.delivered_at = func.now()
            elif status == "read" and not envelope.read_at:
                envelope.read_at = func.now()
                if not envelope.delivered_at:
                    envelope.delivered_at = func.now()
            await self.db.flush()
        return envelope

