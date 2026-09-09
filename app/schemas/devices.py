from pydantic import BaseModel, Field
from typing import Optional, List
from uuid import UUID
from datetime import datetime

class SignedPrekeySchema(BaseModel):
    key_id: int
    key: str = Field(..., description="Base64 encoded Curve25519 public signed prekey")
    signature: str = Field(..., description="Base64 encoded signature of SPK signed with Identity Key")

class OneTimePrekeySchema(BaseModel):
    key_id: int
    key: str = Field(..., description="Base64 encoded Curve25519 public one-time prekey")

class DeviceRegisterRequest(BaseModel):
    device_id: str = Field(..., max_length=64, description="Unique client-generated UUID per device")
    device_name: Optional[str] = Field(None, max_length=100, description="User-friendly device label")
    identity_key: str = Field(..., description="Base64 encoded Curve25519 public Identity Key")
    signed_prekey: SignedPrekeySchema
    one_time_prekeys: List[OneTimePrekeySchema] = Field(default_factory=list)

class DeviceResponse(BaseModel):
    user_id: UUID
    device_id: str
    device_name: Optional[str]
    created_at: datetime
    last_active_at: datetime

    class Config:
        from_attributes = True
