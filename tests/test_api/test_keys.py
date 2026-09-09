import pytest
from httpx import AsyncClient
import uuid

@pytest.mark.anyio
async def test_keys_api_rotation_structure(client: AsyncClient):
    # Setup - Register a device first
    register_payload = {
        "device_id": "9f3b6c2d-94c6-43d9-a78b-d7d8e8f81234",
        "device_name": "Test Laptop",
        "identity_key": "dGVzdF9pZGVudGl0eV9rZXk=",
        "signed_prekey": {
            "key_id": 1,
            "key": "dGVzdF9zaWduZWRfcHJla2V5",
            "signature": "dGVzdF9zaWduYXR1cmU="
        },
        "one_time_prekeys": []
    }
    await client.post("/e2ee/devices", json=register_payload)

    # Test Rotation
    rotation_payload = {
        "key_id": 2,
        "key": "bmV3X3NpZ25lZF9wcmVrZXk=",
        "signature": "bmV3X3NpZ25hdHVyZQ=="
    }
    response = await client.post("/e2ee/devices/9f3b6c2d-94c6-43d9-a78b-d7d8e8f81234/rotate", json=rotation_payload)
    assert response.status_code == 200
    assert response.json()["status"] == "success"

@pytest.mark.anyio
async def test_replenish_prekeys_api_structure(client: AsyncClient):
    payload = {
        "device_id": "9f3b6c2d-94c6-43d9-a78b-d7d8e8f81234",
        "one_time_prekeys": [
            { "key_id": 105, "key": "bmV3X290aw==" }
        ]
    }
    response = await client.post("/e2ee/prekeys", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "success"
