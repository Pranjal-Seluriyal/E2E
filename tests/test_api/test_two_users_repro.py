import pytest
import uuid
import json
import time
import jwt
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.security import get_current_user_id
from app.crypto.adapter import ClientCryptoAdapter

def generate_user_token(user_id: uuid.UUID) -> str:
    payload = {
        "sub": str(user_id),
        "exp": int(time.time()) + 3600
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.ALGORITHM)

def test_two_users_two_devices_full_messaging_flow():
    app.dependency_overrides.pop(get_current_user_id, None)

    sync_client = TestClient(app)

    # 1. Setup User A & User B
    user_a = uuid.uuid4()
    user_b = uuid.uuid4()
    token_a = generate_user_token(user_a)
    token_b = generate_user_token(user_b)

    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    device_a_id = "device-a-1"
    device_b_id = "device-b-1"

    adapter_a = ClientCryptoAdapter(device_a_id)
    adapter_b = ClientCryptoAdapter(device_b_id)

    dev_a_payload = adapter_a.register_device("User A Phone")
    dev_b_payload = adapter_b.register_device("User B Phone")

    # Register Device A for User A
    resp_a = sync_client.post("/e2ee/devices", json=dev_a_payload, headers=headers_a)
    assert resp_a.status_code == 201, f"Reg A failed: {resp_a.status_code} {resp_a.text}"

    # Register Device B for User B
    resp_b = sync_client.post("/e2ee/devices", json=dev_b_payload, headers=headers_b)
    assert resp_b.status_code == 201, f"Reg B failed: {resp_b.status_code} {resp_b.text}"

    # 3. Create a conversation containing both users
    conv_payload = {
        "participant_ids": [str(user_b)]
    }
    conv_resp = sync_client.post("/e2ee/conversations", json=conv_payload, headers=headers_a)
    assert conv_resp.status_code == 201, f"Create conv failed: {conv_resp.text}"
    conv_id = conv_resp.json()["conversation_id"]

    # 4 & 5. Establish WebSocket connections for User A / Device A AND User B / Device B
    with sync_client.websocket_connect(f"/e2ee/ws?token={token_a}&device_id={device_a_id}") as ws_a, \
         sync_client.websocket_connect(f"/e2ee/ws?token={token_b}&device_id={device_b_id}") as ws_b:

        # 6. Send a message from User A to User B
        msg_payload_a_to_b = {
            "envelopes": {
                device_b_id: "ENCRYPTED_PAYLOAD_FROM_A_TO_B"
            }
        }
        headers_a_with_device = {
            "Authorization": f"Bearer {token_a}",
            "X-Device-Id": device_a_id
        }
        send_resp = sync_client.post(
            f"/e2ee/conversations/{conv_id}/messages",
            json=msg_payload_a_to_b,
            headers=headers_a_with_device
        )
        assert send_resp.status_code == 201, f"Send A->B failed: {send_resp.text}"
        msg_a_id = send_resp.json()["message_id"]

        # 7. Verify User B receives the message over WebSocket
        received_b = False
        while not received_b:
            raw_data = ws_b.receive_text()
            data = json.loads(raw_data)
            if data.get("type") == "message":
                assert data["message_id"] == msg_a_id
                assert data["encrypted_payload"] == "ENCRYPTED_PAYLOAD_FROM_A_TO_B"
                assert data["sender_id"] == str(user_a)
                assert data["sender_device_id"] == device_a_id
                assert data["recipient_device_id"] == device_b_id
                received_b = True

        # 8. Send a reply from User B to User A
        msg_payload_b_to_a = {
            "envelopes": {
                device_a_id: "ENCRYPTED_PAYLOAD_FROM_B_TO_A"
            }
        }
        headers_b_with_device = {
            "Authorization": f"Bearer {token_b}",
            "X-Device-Id": device_b_id
        }
        send_reply_resp = sync_client.post(
            f"/e2ee/conversations/{conv_id}/messages",
            json=msg_payload_b_to_a,
            headers=headers_b_with_device
        )
        assert send_reply_resp.status_code == 201, f"Send B->A failed: {send_reply_resp.text}"
        msg_b_id = send_reply_resp.json()["message_id"]

        # 9. Verify User A receives the reply over WebSocket
        received_a = False
        while not received_a:
            raw_data = ws_a.receive_text()
            data = json.loads(raw_data)
            if data.get("type") == "message":
                assert data["message_id"] == msg_b_id
                assert data["encrypted_payload"] == "ENCRYPTED_PAYLOAD_FROM_B_TO_A"
                assert data["sender_id"] == str(user_b)
                assert data["sender_device_id"] == device_b_id
                assert data["recipient_device_id"] == device_a_id
                received_a = True

    # 10. User B's WebSocket is now closed (exited context manager)

    # 11. Send another message from User A while User B is offline
    msg_payload_offline = {
        "envelopes": {
            device_b_id: "ENCRYPTED_OFFLINE_PAYLOAD_FROM_A_TO_B"
        }
    }
    send_offline_resp = sync_client.post(
        f"/e2ee/conversations/{conv_id}/messages",
        json=msg_payload_offline,
        headers=headers_a_with_device
    )
    assert send_offline_resp.status_code == 201
    msg_offline_id = send_offline_resp.json()["message_id"]

    # 12. Reconnect User B
    with sync_client.websocket_connect(f"/e2ee/ws?token={token_b}&device_id={device_b_id}") as ws_b_reconnected:
        # 13. Verify the unread/offline message is flushed to User B
        flushed = False
        while not flushed:
            raw_data = ws_b_reconnected.receive_text()
            data = json.loads(raw_data)
            if data.get("type") == "message":
                assert data["message_id"] == msg_offline_id
                assert data["encrypted_payload"] == "ENCRYPTED_OFFLINE_PAYLOAD_FROM_A_TO_B"
                flushed = True
