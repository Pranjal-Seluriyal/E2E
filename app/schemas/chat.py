from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from uuid import UUID
from datetime import datetime

class ConversationCreateRequest(BaseModel):
    participant_ids: List[UUID] = Field(..., description="List of participant user UUIDs")
    name: Optional[str] = Field(None, max_length=100, description="Optional name for group conversation")

    class Config:
        json_schema_extra = {
            "example": {
                "participant_ids": ["9f3b6c2d-94c6-43d9-a78b-d7d8e8f81234"],
                "name": "Project Chat"
            }
        }


class ConversationResponse(BaseModel):
    conversation_id: UUID
    is_group: bool
    name: Optional[str]
    created_at: datetime
    participants: List[UUID]

    class Config:
        from_attributes = True


class MessageSendRequest(BaseModel):
    envelopes: Dict[str, str] = Field(
        ...,
        description="A dictionary mapping target device ID to the serialized encrypted Matrix event payload."
    )

    class Config:
        json_schema_extra = {
            "example": {
                "envelopes": {
                    "device-uuid-1234": "eyJ0eXBlIjogIm0ucm9vbS5lbmNyeXB0ZWQiLCAiY29udGVudCI6IHsiY2lwaGVydGV4dCI6ICJleGFtcGxlIn19"
                }
            }
        }


class MessageResponse(BaseModel):
    message_id: UUID
    conversation_id: UUID
    sender_id: UUID
    sender_device_id: str
    created_at: datetime

    class Config:
        from_attributes = True


class EnvelopeMessageResponse(BaseModel):
    envelope_id: int
    message_id: UUID
    conversation_id: UUID
    sender_id: UUID
    sender_device_id: str
    recipient_device_id: str
    encrypted_payload: str
    status: str
    created_at: datetime
    delivered_at: Optional[datetime] = None
    read_at: Optional[datetime] = None

    class Config:
        from_attributes = True
