from sqlalchemy import Column, String, DateTime, ForeignKey, Integer, Boolean, BigInteger, ForeignKeyConstraint, UUID
from sqlalchemy.sql import func
from app.models.base import Base
import uuid

class Conversation(Base):
    __tablename__ = "conversations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    is_group = Column(Boolean, default=False, nullable=False)
    name = Column(String(100), nullable=True)


class ConversationParticipant(Base):
    __tablename__ = "conversation_participants"

    conversation_id = Column(UUID(as_uuid=True), ForeignKey("conversations.id", ondelete="CASCADE"), primary_key=True)
    user_id = Column(UUID(as_uuid=True), primary_key=True)
    joined_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Message(Base):
    __tablename__ = "messages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    conversation_id = Column(UUID(as_uuid=True), ForeignKey("conversations.id", ondelete="CASCADE"), nullable=False)
    sender_id = Column(UUID(as_uuid=True), nullable=False)
    sender_device_id = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class MessageEnvelope(Base):
    __tablename__ = "message_envelopes"

    id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    message_id = Column(UUID(as_uuid=True), ForeignKey("messages.id", ondelete="CASCADE"), nullable=False)
    recipient_device_id = Column(String(64), nullable=False)
    encrypted_payload = Column(String, nullable=False)  # Serialized Matrix event JSON containing ciphertext
    status = Column(String(20), default="sent", nullable=False)  # sent, delivered, read
    delivered_at = Column(DateTime(timezone=True), nullable=True)
    read_at = Column(DateTime(timezone=True), nullable=True)


class UserPresence(Base):
    __tablename__ = "user_presences"

    user_id = Column(UUID(as_uuid=True), primary_key=True)
    status = Column(String(20), default="offline", nullable=False)  # online, offline
    last_active_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
