import pytest
import uuid
import time
import jwt
import json
from httpx import AsyncClient
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.models.chat import Message, MessageEnvelope
from sqlalchemy.future import select
from app.security import get_current_user_id
from sqlalchemy.ext.asyncio import AsyncSession

def generate_user_token(user_id: uuid.UUID) -> str:
    payload = {
        "sub": str(user_id),
        "exp": int(time.time()) + 3600
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)

@pytest.mark.anyio
async def test_create_conversation_api(client: AsyncClient):
    # Setup - Remove get_current_user_id override to use real JWT authentication
    app.dependency_overrides.pop(get_current_user_id, None)

    # Setup test token
    user1 = uuid.uuid4()
    user2 = uuid.uuid4()
    token = generate_user_token(user1)
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create a 1-to-1 conversation
    payload = {
        "participant_ids": [str(user2)],
        "name": "Test chat"
    }
    response = await client.post("/e2ee/conversations", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert "conversation_id" in data
    assert data["is_group"] is False
    assert len(data["participants"]) == 2
    assert str(user1) in data["participants"]
    assert str(user2) in data["participants"]

    conv_id = data["conversation_id"]

    # 2. Try to create duplicate conversation -> should return the same one
    response2 = await client.post("/e2ee/conversations", json=payload, headers=headers)
    assert response2.status_code == 201
    data2 = response2.json()
    assert data2["conversation_id"] == conv_id

@pytest.mark.anyio
async def test_send_and_fetch_messages_api(client: AsyncClient, db_session: AsyncSession):
    # Setup - Remove get_current_user_id override to use real JWT authentication
    app.dependency_overrides.pop(get_current_user_id, None)

    user1 = uuid.uuid4()
    user2 = uuid.uuid4()
    
    # Register device for user 2 so it is an active device in our mock db session
    from app.models.devices import Device
    dev = Device(user_id=user2, device_id="user2-device-1", device_name="User2 Phone")
    db_session.add(dev)
    await db_session.commit()

    token1 = generate_user_token(user1)
    headers1 = {"Authorization": f"Bearer {token1}", "X-Device-Id": "user1-device-1"}

    # Create conversation
    payload = {
        "participant_ids": [str(user2)]
    }
    conv_resp = await client.post("/e2ee/conversations", json=payload, headers=headers1)
    conv_id = conv_resp.json()["conversation_id"]

    # Send message with target device envelopes
    msg_payload = {
        "envelopes": {
            "user2-device-1": "OPAQ-CIPHERTEXT-ENVELOPE-DATA"
        }
    }
    msg_resp = await client.post(f"/e2ee/conversations/{conv_id}/messages", json=msg_payload, headers=headers1)
    assert msg_resp.status_code == 201
    msg_data = msg_resp.json()
    assert "message_id" in msg_data

    # Fetch messages as User 2 on device user2-device-1
    token2 = generate_user_token(user2)
    headers2 = {"Authorization": f"Bearer {token2}", "X-Device-Id": "user2-device-1"}
    
    fetch_resp = await client.get(f"/e2ee/conversations/{conv_id}/messages", headers=headers2)
    assert fetch_resp.status_code == 200
    messages = fetch_resp.json()
    assert len(messages) == 1
    assert messages[0]["recipient_device_id"] == "user2-device-1"
    assert messages[0]["encrypted_payload"] == "OPAQ-CIPHERTEXT-ENVELOPE-DATA"
    assert messages[0]["status"] == "sent"

    # Verify that database does not contain any plaintext
    res = await db_session.execute(select(Message).filter(Message.id == uuid.UUID(msg_data["message_id"])))
    db_msg = res.scalars().first()
    assert db_msg is not None
    
    res_env = await db_session.execute(select(MessageEnvelope).filter(MessageEnvelope.message_id == db_msg.id))
    envelopes = res_env.scalars().all()
    assert len(envelopes) == 1
    assert "OPAQ-CIPHERTEXT-ENVELOPE-DATA" in envelopes[0].encrypted_payload

def test_websocket_realtime_flow():
    # Setup - Remove get_current_user_id override to use real JWT authentication
    app.dependency_overrides.pop(get_current_user_id, None)

    # Setup test client
    sync_client = TestClient(app)
    
    # Define two users
    user1 = uuid.uuid4()
    user2 = uuid.uuid4()
    token1 = generate_user_token(user1)
    token2 = generate_user_token(user2)
    
    # 1. Register devices using HTTP API endpoints with bypass keys
    headers1 = {"Authorization": f"Bearer {token1}"}
    headers2 = {"Authorization": f"Bearer {token2}"}
    
    dev1_payload = {
        "device_id": "user1-device-ws",
        "device_name": "User1 PC",
        "identity_key": "dGVzdF9pZGVudGl0eV9rZXk=",
        "signed_prekey": {
            "key_id": 1,
            "key": "dGVzdF9zaWduZWRfcHJla2V5",
            "signature": "dGVzdF9zaWduYXR1cmU="
        },
        "one_time_prekeys": []
    }
    dev2_payload = {
        "device_id": "user2-device-ws",
        "device_name": "User2 PC",
        "identity_key": "dGVzdF9pZGVudGl0eV9rZXk=",
        "signed_prekey": {
            "key_id": 1,
            "key": "dGVzdF9zaWduZWRfcHJla2V5",
            "signature": "dGVzdF9zaWduYXR1cmU="
        },
        "one_time_prekeys": []
    }
    
    # Register device 1
    resp = sync_client.post("/e2ee/devices", json=dev1_payload, headers=headers1)
    assert resp.status_code == 201
    
    # Register device 2
    resp = sync_client.post("/e2ee/devices", json=dev2_payload, headers=headers2)
    assert resp.status_code == 201
    
    # 2. Create conversation
    conv_payload = {
        "participant_ids": [str(user2)]
    }
    resp = sync_client.post("/e2ee/conversations", json=conv_payload, headers=headers1)
    assert resp.status_code == 201
    conv_id = resp.json()["conversation_id"]
    
    # 3. Establish WebSocket connection for User 2 (the recipient)
    with sync_client.websocket_connect(f"/e2ee/ws?token={token2}&device_id=user2-device-ws") as ws2:
        # 4. User 1 sends a message via HTTP POST while User 2 is online
        msg_payload = {
            "envelopes": {
                "user2-device-ws": "REALTIME-ENVELOPE-DATA"
            }
        }
        headers1_with_device = {"Authorization": f"Bearer {token1}", "X-Device-Id": "user1-device-ws"}
        msg_resp = sync_client.post(
            f"/e2ee/conversations/{conv_id}/messages",
            json=msg_payload,
            headers=headers1_with_device
        )
        assert msg_resp.status_code == 201
        msg_id = msg_resp.json()["message_id"]
        
        # User 2 receives message event in real-time over WebSocket
        raw_msg_event = ws2.receive_text()
        msg_event = json.loads(raw_msg_event)
        assert msg_event["type"] == "message"
        assert msg_event["message_id"] == msg_id
        assert msg_event["encrypted_payload"] == "REALTIME-ENVELOPE-DATA"
        assert msg_event["sender_device_id"] == "user1-device-ws"

    # 5. Connect User 1 via WebSocket to test incoming typing and indicator events
    with sync_client.websocket_connect(f"/e2ee/ws?token={token1}&device_id=user1-device-ws") as ws1:
        # Send typing event
        ws1.send_text(json.dumps({
            "type": "typing",
            "conversation_id": str(conv_id),
            "is_typing": True
        }))
        # The connection should stay alive and handle it without errors


@pytest.mark.anyio
async def test_csp_and_security_headers(client: AsyncClient):
    resp = await client.get("/health")
    assert resp.status_code == 200
    headers = resp.headers
    assert "Content-Security-Policy" in headers
    assert "default-src 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-XSS-Protection"] == "1; mode=block"
    assert "max-age=63072000" in headers["Strict-Transport-Security"]


def test_peer_identity_key_change_detection():
    from app.crypto.adapter import ClientCryptoAdapter
    from app.crypto.models import PrekeyBundle
    from app.crypto.exceptions import SessionError

    sender = ClientCryptoAdapter("sender-dev")
    recipient = ClientCryptoAdapter("recipient-dev")

    # Capture original bundle
    original_bundle = PrekeyBundle(
        device_id=recipient.device_id,
        identity_key=recipient.engine.identity_public_bytes,
        signed_prekey=recipient.engine.spk_public.public_bytes_raw(),
        signed_prekey_signature=recipient.engine.spk_signature,
        signed_prekey_id=recipient.engine.spk_id
    )

    # Establish first session -> should succeed and cache key
    sender.create_session(recipient.device_id, original_bundle)
    assert recipient.device_id in sender.engine.peer_identity_keys

    # Create a new recipient adapter simulating a different identity key (rotation/spoofing)
    corrupted_recipient = ClientCryptoAdapter("recipient-dev")
    corrupted_bundle = PrekeyBundle(
        device_id=corrupted_recipient.device_id,
        identity_key=corrupted_recipient.engine.identity_public_bytes,
        signed_prekey=corrupted_recipient.engine.spk_public.public_bytes_raw(),
        signed_prekey_signature=corrupted_recipient.engine.spk_signature,
        signed_prekey_id=corrupted_recipient.engine.spk_id
    )

    # Attempt to re-establish session with different identity key -> must raise SessionError
    with pytest.raises(SessionError) as exc_info:
        sender.create_session(recipient.device_id, corrupted_bundle)
    assert "Key rotation detected" in str(exc_info.value)

