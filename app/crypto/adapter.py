from typing import Dict, List, Optional, Tuple, Any
from uuid import UUID
import time
from app.crypto.engine import ClientCryptoEngine
from app.crypto.models import E2EPayload, PrekeyBundle
from app.crypto.exceptions import DecryptionError, SessionError
from app.crypto.serialization import (
    bytes_to_b64str,
    serialize_payload,
    deserialize_payload,
    serialize_matrix_encrypted_event,
    deserialize_matrix_encrypted_event
)

class ClientCryptoAdapter:
    def __init__(self, device_id: str):
        self.device_id = device_id
        self.engine = ClientCryptoEngine(device_id)

    def register_device(self, device_name: Optional[str] = None) -> Dict[str, Any]:
        """Generates client registration bundle to match FastAPI's DeviceRegisterRequest schema."""
        # Generate 5 initial one-time prekeys
        otk_tuples = self.engine.generate_one_time_prekeys(5)
        
        request_payload = {
            "device_id": self.device_id,
            "device_name": device_name,
            "identity_key": bytes_to_b64str(self.engine.identity_public_bytes),
            "signed_prekey": {
                "key_id": self.engine.spk_id,
                "key": bytes_to_b64str(self.engine.spk_public.public_bytes_raw()),
                "signature": bytes_to_b64str(self.engine.spk_signature)
            },
            "one_time_prekeys": [
                {
                    "key_id": id_,
                    "key": bytes_to_b64str(val)
                }
                for id_, val in otk_tuples
            ]
        }
        return request_payload

    def create_session(self, peer_device_id: str, bundle: PrekeyBundle) -> None:
        """Establishes an outbound session key with a peer device using X3DH."""
        self.engine.initiate_x3dh(
            peer_device_id=peer_device_id,
            peer_identity_bytes=bundle.identity_key,
            peer_spk_bytes=bundle.signed_prekey,
            peer_spk_signature=bundle.signed_prekey_signature,
            peer_spk_id=bundle.signed_prekey_id,
            peer_opk_bytes=bundle.one_time_prekey,
            peer_opk_id=bundle.one_time_prekey_id
        )

    def encrypt_message(self, peer_device_id: str, peer_identity_key: bytes, payload: E2EPayload) -> Dict[str, Any]:
        """Encrypts a single message for a peer device, generating a serialized Matrix event."""
        # Derive key if not already established
        session_key = self.engine.sessions.get(peer_device_id)
        if not session_key:
            raise SessionError(f"No active session with device {peer_device_id}. Call create_session first.")
            
        plaintext_bytes = serialize_payload(payload)
        ciphertext, iv = self.engine.encrypt(peer_device_id, plaintext_bytes)
        
        # Retrieve the ephemeral key generated during X3DH session initiation
        ephemeral_key = self.engine.session_ephemeral_keys.get(
            peer_device_id,
            self.engine.identity_public_dh.public_bytes_raw()
        )
        
        event = serialize_matrix_encrypted_event(
            sender_device_id=self.device_id,
            sender_identity_key=self.engine.identity_public_bytes,
            recipient_identity_key=peer_identity_key,
            ciphertext=ciphertext,
            iv=iv,
            ephemeral_key=ephemeral_key,
            signed_prekey_id=self.engine.spk_id
        )
        return event

    def decrypt_message(self, event_dict: Dict[str, Any]) -> E2EPayload:
        """Parses and decrypts a serialized Matrix encrypted event, returning the E2EPayload."""
        local_ik_bytes = self.engine.identity_public_bytes
        
        # Deserialize matrix event
        sender_identity_key, ciphertext, iv, ephemeral_key, signed_prekey_id, one_time_prekey_id = \
            deserialize_matrix_encrypted_event(event_dict, local_ik_bytes)
            
        sender_device_id = event_dict.get("content", {}).get("sender_device_id", "unknown")
        
        # Establish session key if it doesn't exist (incoming X3DH handshake)
        if sender_device_id not in self.engine.sessions:
            self.engine.receive_x3dh(
                peer_device_id=sender_device_id,
                peer_identity_bytes=sender_identity_key,
                peer_ephemeral_key_bytes=ephemeral_key,
                signed_prekey_id=signed_prekey_id,
                one_time_prekey_id=one_time_prekey_id
            )
            
        # Decrypt
        plaintext_bytes = self.engine.decrypt(sender_device_id, ciphertext, iv)
        return deserialize_payload(plaintext_bytes)

    def encrypt_for_devices(
        self,
        peer_device_bundles: List[PrekeyBundle],
        payload: E2EPayload
    ) -> Dict[str, Dict[str, Any]]:
        """Multi-device support: encrypts the payload individually for each target device.
        Returns a mapping: device_id -> Matrix encrypted event payload.
        """
        encrypted_events = {}
        for bundle in peer_device_bundles:
            peer_device_id = bundle.device_id
            
            # Setup session if missing
            if peer_device_id not in self.engine.sessions:
                self.create_session(peer_device_id, bundle)
                
            event = self.encrypt_message(peer_device_id, bundle.identity_key, payload)
            encrypted_events[peer_device_id] = event
            
        return encrypted_events

    def rotate_device_keys(self) -> Dict[str, Any]:
        """Rotates the signed prekey, generating signature update payload."""
        new_spk_id, spk_bytes, signature = self.engine.rotate_signed_prekey()
        return {
            "key_id": new_spk_id,
            "key": bytes_to_b64str(spk_bytes),
            "signature": bytes_to_b64str(signature)
        }

    def verify_device(self, peer_device_id: str, safety_number: str) -> bool:
        """Placeholder interface for device verification (SAS safety numbers comparison)."""
        # SAS verification comparing safety numbers hash is standard
        return True
