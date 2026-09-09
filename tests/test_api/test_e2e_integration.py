import pytest
import time
import uuid
import logging
from httpx import AsyncClient
from app.crypto.adapter import ClientCryptoAdapter
from app.crypto.models import E2EPayload, PrekeyBundle
from app.crypto.exceptions import DecryptionError, SessionError
from app.crypto.serialization import b64str_to_bytes, bytes_to_b64str

# Setup logging mock/interceptor
class LogCaptureHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append(self.format(record))

# ----------------- Security Gate Tests -----------------

@pytest.mark.anyio
async def test_security_gate_1_private_keys_never_reach_backend():
    """1. Private keys never reach the backend."""
    device_id = "device-test-sg1"
    adapter = ClientCryptoAdapter(device_id)
    reg_payload = adapter.register_device("My Phone")

    # Verify fields in the payload sent to the backend
    assert "device_id" in reg_payload
    assert "identity_key" in reg_payload
    assert "signed_prekey" in reg_payload
    assert "one_time_prekeys" in reg_payload

    # Convert private key raw bytes to b64 string to verify they are NOT in the payload
    id_priv_bytes = adapter.engine.identity_private_dh.private_bytes_raw()
    id_priv_b64 = bytes_to_b64str(id_priv_bytes)
    
    # Assert private keys are absent from all levels of the payload
    payload_str = str(reg_payload)
    assert id_priv_b64 not in payload_str
    assert "private" not in payload_str
    assert "private_key" not in payload_str


@pytest.mark.anyio
async def test_security_gate_2_and_3_plaintext_never_sent_and_only_ciphertext_received():
    """2. Plaintext message payloads are never sent to Chat Service.
    3. Chat Service only receives ciphertext.
    """
    sender = ClientCryptoAdapter("sender-device")
    recipient = ClientCryptoAdapter("recipient-device")
    
    # Establish session
    recipient_bundle = PrekeyBundle(
        device_id=recipient.device_id,
        identity_key=recipient.engine.identity_public_bytes,
        signed_prekey=recipient.engine.spk_public.public_bytes_raw(),
        signed_prekey_signature=recipient.engine.spk_signature,
        signed_prekey_id=recipient.engine.spk_id
    )
    sender.create_session(recipient.device_id, recipient_bundle)
    
    payload = E2EPayload(
        conversation_id="chat-conv-id",
        sender_id=uuid.uuid4(),
        content="Secret message plaintext",
        timestamp=int(time.time())
    )
    
    recipient_ik_bytes = recipient.engine.identity_public_bytes
    event = sender.encrypt_message(recipient.device_id, recipient_ik_bytes, payload)
    
    # 2. Assert plaintext is not in the event payload
    event_str = str(event)
    assert "Secret message plaintext" not in event_str
    
    # 3. Assert event matches the Matrix m.room.encrypted schema containing only ciphertext metadata
    assert event["type"] == "m.room.encrypted"
    assert "ciphertext" in event["content"]
    assert "sender_key" in event["content"]
    assert "sender_device_id" in event["content"]


@pytest.mark.anyio
async def test_security_gate_4_e2ee_service_cannot_decrypt_messages():
    """4. E2EE Service cannot decrypt messages."""
    sender = ClientCryptoAdapter("sender-device")
    recipient = ClientCryptoAdapter("recipient-device")
    
    recipient_bundle = PrekeyBundle(
        device_id=recipient.device_id,
        identity_key=recipient.engine.identity_public_bytes,
        signed_prekey=recipient.engine.spk_public.public_bytes_raw(),
        signed_prekey_signature=recipient.engine.spk_signature,
        signed_prekey_id=recipient.engine.spk_id
    )
    sender.create_session(recipient.device_id, recipient_bundle)
    
    payload = E2EPayload(
        conversation_id="chat-conv-id",
        sender_id=uuid.uuid4(),
        content="Secret data",
        timestamp=int(time.time())
    )
    recipient_ik = recipient.engine.identity_public_bytes
    event = sender.encrypt_message(recipient.device_id, recipient_ik, payload)
    
    # Simulate Server/E2EE Service attempt to decrypt using public key registry data
    server_adapter = ClientCryptoAdapter("server-spy")
    # Server tries to decrypt the message using recipient's identity public key 
    # but does NOT have recipient's private key
    with pytest.raises(DecryptionError):
        server_adapter.decrypt_message(event)


@pytest.mark.anyio
async def test_security_gate_5_matrix_types_do_not_leak():
    """5. Matrix-specific types do not leak outside the crypto adapter."""
    # Check that our API endpoints and internal schemas use standard types (strings, bytes, models)
    # and do not import or depend on Matrix models directly.
    import app.schemas.keys as keys_schemas
    import app.schemas.devices as devices_schemas
    
    # Verify no matrix modules are referenced in the FastAPI schemas
    for field_name in keys_schemas.DeviceKeyBundleResponse.model_fields:
        assert not field_name.startswith("matrix_")
    for field_name in devices_schemas.DeviceRegisterRequest.model_fields:
        assert not field_name.startswith("matrix_")


@pytest.mark.anyio
async def test_security_gate_6_revoked_devices_cannot_establish_sessions(client: AsyncClient):
    """6. Revoked devices cannot establish new sessions."""
    # Register device first
    user_uuid = uuid.uuid4()
    adapter = ClientCryptoAdapter("revoked-device-id")
    reg_payload = adapter.register_device("Device to Revoke")
    
    from app.main import app
    from app.security import require_service_or_user, AuthContext, get_current_user_id
    
    app.dependency_overrides[get_current_user_id] = lambda: user_uuid
    app.dependency_overrides[require_service_or_user] = lambda: AuthContext(user_id=user_uuid)
    
    try:
        reg_resp = await client.post("/e2ee/devices", json=reg_payload)
        assert reg_resp.status_code == 201
        
        # Revoke device
        rev_resp = await client.delete(f"/e2ee/devices/revoked-device-id")
        assert rev_resp.status_code == 204
        
        # Try to retrieve keys for revoked device
        keys_resp = await client.get(f"/e2ee/keys/{user_uuid}")
        # The E2EE Service must only return active devices in key bundles.
        # Since the only device was revoked, it must return 404.
        assert keys_resp.status_code == 404
        assert keys_resp.json()["detail"] == "No registered devices found for this user"
    finally:
        from tests.conftest import MOCK_USER_ID
        app.dependency_overrides[get_current_user_id] = lambda: MOCK_USER_ID
        del app.dependency_overrides[require_service_or_user]


@pytest.mark.anyio
async def test_security_gate_7_multiple_devices_handled_independently():
    """7. Multiple devices are handled independently."""
    sender = ClientCryptoAdapter("sender-device")
    
    # Recipient has 3 devices
    dev1 = ClientCryptoAdapter("recipient-phone")
    dev2 = ClientCryptoAdapter("recipient-laptop")
    dev3 = ClientCryptoAdapter("recipient-tablet")
    
    bundles = [
        PrekeyBundle(
            device_id=dev.device_id,
            identity_key=dev.engine.identity_public_bytes,
            signed_prekey=dev.engine.spk_public.public_bytes_raw(),
            signed_prekey_signature=dev.engine.spk_signature,
            signed_prekey_id=dev.engine.spk_id
        )
        for dev in [dev1, dev2, dev3]
    ]
    
    payload = E2EPayload(
        conversation_id="conv-id",
        sender_id=uuid.uuid4(),
        content="Broadcast message",
        timestamp=int(time.time())
    )
    
    # Encrypt for multiple devices
    encrypted_events = sender.encrypt_for_devices(bundles, payload)
    
    # Assert three distinct events are generated
    assert len(encrypted_events) == 3
    assert "recipient-phone" in encrypted_events
    assert "recipient-laptop" in encrypted_events
    assert "recipient-tablet" in encrypted_events
    
    # Verify ciphertexts are unique (independent session keys)
    cipher_phone = encrypted_events["recipient-phone"]["content"]["ciphertext"]
    cipher_laptop = encrypted_events["recipient-laptop"]["content"]["ciphertext"]
    assert cipher_phone != cipher_laptop


@pytest.mark.anyio
async def test_security_gate_8_key_rotation_does_not_break_active_sessions():
    """8. Key rotation does not break existing sessions incorrectly."""
    sender = ClientCryptoAdapter("sender-device")
    recipient = ClientCryptoAdapter("recipient-device")
    
    recipient_bundle = PrekeyBundle(
        device_id=recipient.device_id,
        identity_key=recipient.engine.identity_public_bytes,
        signed_prekey=recipient.engine.spk_public.public_bytes_raw(),
        signed_prekey_signature=recipient.engine.spk_signature,
        signed_prekey_id=recipient.engine.spk_id
    )
    sender.create_session(recipient.device_id, recipient_bundle)
    
    payload1 = E2EPayload(
        conversation_id="conv-id",
        sender_id=uuid.uuid4(),
        content="Msg 1 before rotation",
        timestamp=int(time.time())
    )
    recipient_ik = recipient.engine.identity_public_bytes
    event1 = sender.encrypt_message(recipient.device_id, recipient_ik, payload1)
    
    # Rotate recipient's signed prekey on the client
    rotation_payload = recipient.rotate_device_keys()
    assert rotation_payload["key_id"] == 2
    
    # Send another message from sender
    payload2 = E2EPayload(
        conversation_id="conv-id",
        sender_id=uuid.uuid4(),
        content="Msg 2 after rotation",
        timestamp=int(time.time())
    )
    event2 = sender.encrypt_message(recipient.device_id, recipient_ik, payload2)
    
    # Verify recipient can decrypt both messages successfully
    decrypted1 = recipient.decrypt_message(event1)
    decrypted2 = recipient.decrypt_message(event2)
    
    assert decrypted1.content == "Msg 1 before rotation"
    assert decrypted2.content == "Msg 2 after rotation"


@pytest.mark.anyio
async def test_security_gate_9_replay_protection():
    """9. Replay/duplicate ciphertext handling follows engine's behavior."""
    sender = ClientCryptoAdapter("sender-device")
    recipient = ClientCryptoAdapter("recipient-device")
    
    recipient_bundle = PrekeyBundle(
        device_id=recipient.device_id,
        identity_key=recipient.engine.identity_public_bytes,
        signed_prekey=recipient.engine.spk_public.public_bytes_raw(),
        signed_prekey_signature=recipient.engine.spk_signature,
        signed_prekey_id=recipient.engine.spk_id
    )
    sender.create_session(recipient.device_id, recipient_bundle)
    
    payload = E2EPayload(
        conversation_id="conv",
        sender_id=uuid.uuid4(),
        content="Single-use secret",
        timestamp=int(time.time())
    )
    recipient_ik = recipient.engine.identity_public_bytes
    event = sender.encrypt_message(recipient.device_id, recipient_ik, payload)
    
    # First decryption succeeds
    decrypted1 = recipient.decrypt_message(event)
    assert decrypted1.content == "Single-use secret"
    
    # Replayed decryption raises DecryptionError
    with pytest.raises(DecryptionError) as exc_info:
        recipient.decrypt_message(event)
    assert "Replay attack detected" in str(exc_info.value)


@pytest.mark.anyio
async def test_security_gate_10_invalid_ciphertext_fails_closed():
    """10. Invalid ciphertext is rejected safely."""
    sender = ClientCryptoAdapter("sender-device")
    recipient = ClientCryptoAdapter("recipient-device")
    
    recipient_bundle = PrekeyBundle(
        device_id=recipient.device_id,
        identity_key=recipient.engine.identity_public_bytes,
        signed_prekey=recipient.engine.spk_public.public_bytes_raw(),
        signed_prekey_signature=recipient.engine.spk_signature,
        signed_prekey_id=recipient.engine.spk_id
    )
    sender.create_session(recipient.device_id, recipient_bundle)
    
    payload = E2EPayload(
        conversation_id="conv",
        sender_id=uuid.uuid4(),
        content="Secret message",
        timestamp=int(time.time())
    )
    recipient_ik = recipient.engine.identity_public_bytes
    event = sender.encrypt_message(recipient.device_id, recipient_ik, payload)
    
    # Corrupt ciphertext bytes
    recipient_key_str = bytes_to_b64str(recipient_ik)
    import base64, json
    
    body_b64 = event["content"]["ciphertext"][recipient_key_str]["body"]
    body_dict = json.loads(base64.b64decode(body_b64.encode("utf-8")).decode("utf-8"))
    
    # Modify ciphertext string in event
    body_dict["ciphertext"] = bytes_to_b64str(b"corruptedciphertextbytes")
    event["content"]["ciphertext"][recipient_key_str]["body"] = \
        base64.b64encode(json.dumps(body_dict).encode("utf-8")).decode("utf-8")
        
    # Attempt decrypt: must fail closed raising DecryptionError
    with pytest.raises(DecryptionError):
        recipient.decrypt_message(event)


@pytest.mark.anyio
async def test_security_gate_11_malformed_cryptographic_payloads_do_not_crash():
    """11. Malformed cryptographic payloads do not crash the service."""
    recipient = ClientCryptoAdapter("recipient-device")
    
    # Completely invalid/empty payloads should raise DecryptionError and not crash
    malformed_event = {
        "type": "m.room.encrypted",
        "content": {}
    }
    
    with pytest.raises(DecryptionError):
        recipient.decrypt_message(malformed_event)


@pytest.mark.anyio
async def test_security_gate_12_sensitive_data_is_never_logged():
    """12. Sensitive data is never logged."""
    # Setup logger and record logs
    log_capture = LogCaptureHandler()
    logger = logging.getLogger()
    logger.addHandler(log_capture)
    logger.setLevel(logging.INFO)
    
    sender = ClientCryptoAdapter("sender-device")
    recipient = ClientCryptoAdapter("recipient-device")
    
    recipient_bundle = PrekeyBundle(
        device_id=recipient.device_id,
        identity_key=recipient.engine.identity_public_bytes,
        signed_prekey=recipient.engine.spk_public.public_bytes_raw(),
        signed_prekey_signature=recipient.engine.spk_signature,
        signed_prekey_id=recipient.engine.spk_id
    )
    sender.create_session(recipient.device_id, recipient_bundle)
    
    payload = E2EPayload(
        conversation_id="conv",
        sender_id=uuid.uuid4(),
        content="HighlyPrivateSensitiveMessageText",
        timestamp=int(time.time())
    )
    recipient_ik = recipient.engine.identity_public_bytes
    event = sender.encrypt_message(recipient.device_id, recipient_ik, payload)
    recipient.decrypt_message(event)
    
    # Verify sensitive data was not logged
    logs_output = "".join(log_capture.records)
    assert "HighlyPrivateSensitiveMessageText" not in logs_output
    
    # Convert private key to base64 and ensure it was never logged
    id_priv_bytes = sender.engine.identity_private_dh.private_bytes_raw()
    id_priv_b64 = bytes_to_b64str(id_priv_bytes)
    assert id_priv_b64 not in logs_output
    
    # Clean up handler
    logger.removeHandler(log_capture)

# Helper patch class for mocking get_current_user_id in test_security_gate_6
from unittest.mock import patch
