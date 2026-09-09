import base64
import json
from typing import Tuple, Dict, Any
from app.crypto.exceptions import DecryptionError
from app.crypto.models import E2EPayload

def bytes_to_b64str(b: bytes) -> str:
    """Helper to convert bytes to base64 string."""
    return base64.b64encode(b).decode("utf-8")

def b64str_to_bytes(s: str) -> bytes:
    """Helper to convert base64 string to bytes."""
    try:
        return base64.b64decode(s.encode("utf-8"))
    except Exception as e:
        raise DecryptionError(f"Base64 decoding failed: {str(e)}")

def serialize_payload(payload: E2EPayload) -> bytes:
    """Serializes a platform E2EPayload to UTF-8 bytes."""
    payload_dict = {
        "conversation_id": payload.conversation_id,
        "sender_id": str(payload.sender_id),
        "content": payload.content,
        "timestamp": payload.timestamp
    }
    return json.dumps(payload_dict).encode("utf-8")

def deserialize_payload(payload_bytes: bytes) -> E2EPayload:
    """Deserializes UTF-8 bytes to an E2EPayload."""
    try:
        data = json.loads(payload_bytes.decode("utf-8"))
        return E2EPayload(**data)
    except Exception as e:
        raise DecryptionError(f"Failed to deserialize payload: {str(e)}")

def serialize_matrix_encrypted_event(
    sender_device_id: str,
    sender_identity_key: bytes,
    recipient_identity_key: bytes,
    ciphertext: bytes,
    iv: bytes,
    ephemeral_key: bytes,
    signed_prekey_id: int,
    one_time_prekey_id: int = None
) -> Dict[str, Any]:
    """Serializes E2EE ciphertext and metadata into a standard Matrix m.room.encrypted structure."""
    recipient_key_str = bytes_to_b64str(recipient_identity_key)
    
    # Pack parameters into Olm-like cipher text envelope
    packed_body = {
        "ciphertext": bytes_to_b64str(ciphertext),
        "iv": bytes_to_b64str(iv),
        "ephemeral_key": bytes_to_b64str(ephemeral_key),
        "signed_prekey_id": signed_prekey_id
    }
    if one_time_prekey_id is not None:
        packed_body["one_time_prekey_id"] = one_time_prekey_id

    event = {
        "type": "m.room.encrypted",
        "content": {
            "algorithm": "m.olm.v1.curve25519-aes-sha2",
            "sender_key": bytes_to_b64str(sender_identity_key),
            "sender_device_id": sender_device_id,
            "ciphertext": {
                recipient_key_str: {
                    "type": 0,  # 0 indicates prekey-initiated message
                    "body": base64.b64encode(json.dumps(packed_body).encode("utf-8")).decode("utf-8")
                }
            }
        }
    }
    return event

def deserialize_matrix_encrypted_event(
    event_dict: Dict[str, Any],
    local_identity_key: bytes
) -> Tuple[bytes, bytes, bytes, bytes, int, int]:
    """Deserializes a Matrix m.room.encrypted event dict.
    Returns: (sender_identity_key, ciphertext, iv, ephemeral_key, signed_prekey_id, one_time_prekey_id)
    """
    try:
        content = event_dict.get("content", {})
        algorithm = content.get("algorithm")
        if algorithm != "m.olm.v1.curve25519-aes-sha2":
            raise DecryptionError(f"Unsupported algorithm: {algorithm}")
            
        sender_identity_key = b64str_to_bytes(content.get("sender_key", ""))
        
        recipient_key_str = bytes_to_b64str(local_identity_key)
        ciphertext_map = content.get("ciphertext", {})
        
        if recipient_key_str not in ciphertext_map:
            raise DecryptionError("Message is not addressed to this device's identity key.")
            
        body_b64 = ciphertext_map[recipient_key_str].get("body", "")
        body_dict = json.loads(base64.b64decode(body_b64.encode("utf-8")).decode("utf-8"))
        
        ciphertext = b64str_to_bytes(body_dict.get("ciphertext", ""))
        iv = b64str_to_bytes(body_dict.get("iv", ""))
        ephemeral_key = b64str_to_bytes(body_dict.get("ephemeral_key", ""))
        signed_prekey_id = body_dict.get("signed_prekey_id")
        one_time_prekey_id = body_dict.get("one_time_prekey_id")
        
        return sender_identity_key, ciphertext, iv, ephemeral_key, signed_prekey_id, one_time_prekey_id
    except Exception as e:
        raise DecryptionError(f"Failed to deserialize matrix event payload: {str(e)}")
