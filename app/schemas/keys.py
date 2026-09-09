from pydantic import BaseModel, Field
from typing import Optional, List
from uuid import UUID
from .devices import SignedPrekeySchema, OneTimePrekeySchema

class DeviceKeyBundleResponse(BaseModel):
    device_id: str
    identity_key: str
    signed_prekey: SignedPrekeySchema
    one_time_prekey: Optional[OneTimePrekeySchema] = None

class UserKeyBundleResponse(BaseModel):
    user_id: UUID
    devices: List[DeviceKeyBundleResponse]

class SignedPrekeyRotateRequest(BaseModel):
    signed_prekey: SignedPrekeySchema

class PrekeyReplenishRequest(BaseModel):
    device_id: str
    one_time_prekeys: List[OneTimePrekeySchema]
