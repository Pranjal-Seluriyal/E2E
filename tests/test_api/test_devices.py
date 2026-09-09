import pytest
from httpx import AsyncClient

@pytest.mark.anyio
async def test_register_device_api_structure(client: AsyncClient):
    payload = {
        "device_id": "9f3b6c2d-94c6-43d9-a78b-d7d8e8f81234",
        "device_name": "Test Laptop",
        "identity_key": "dGVzdF9pZGVudGl0eV9rZXk=",
        "signed_prekey": {
            "key_id": 1,
            "key": "dGVzdF9zaWduZWRfcHJla2V5",
            "signature": "dGVzdF9zaWduYXR1cmU="
        },
        "one_time_prekeys": [
            { "key_id": 100, "key": "dGVzdF9vdGtfMQ==" },
            { "key_id": 101, "key": "dGVzdF9vdGtfMg==" }
        ]
    }
    # Test route registration structure
    response = await client.post("/e2ee/devices", json=payload)
    assert response.status_code == 201
    
    data = response.json()
    assert "device_id" in data
    assert data["device_id"] == "9f3b6c2d-94c6-43d9-a78b-d7d8e8f81234"
    assert data["device_name"] == "Test Laptop"

@pytest.mark.anyio
async def test_list_devices_api_structure(client: AsyncClient):
    response = await client.get("/e2ee/devices")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
