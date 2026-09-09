from pydantic import BaseModel, Field
from typing import Optional, List
from uuid import UUID

class KeyPair(BaseModel):
    public_key: bytes
    private_key: Optional[bytes] = None

class PrekeyBundle(BaseModel):
    device_id: str
    identity_key: bytes
    signed_prekey: bytes
    signed_prekey_signature: bytes
    signed_prekey_id: int
    one_time_prekey: Optional[bytes] = None
    one_time_prekey_id: Optional[int] = None

class EncryptedEnvelope(BaseModel):
    sender_device_id: str
    recipient_device_id: str
    ciphertext: bytes
    iv: bytes
    algorithm: str = "m.olm.v1.curve25519-aes-sha2"
    one_time_prekey_id: Optional[int] = None
    signed_prekey_id: int
    ephemeral_key: bytes

class E2EPayload(BaseModel):
    conversation_id: str
    sender_id: UUID
    content: str
    timestamp: int
