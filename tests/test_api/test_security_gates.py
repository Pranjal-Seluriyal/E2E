import pytest
import time
import uuid
import jwt
from unittest.mock import patch
from httpx import AsyncClient
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from app.config import settings

# ----------------- Mock Redis for Rate Limiting -----------------

class MockRedis:
    def __init__(self):
        self.storage = {}

    def pipeline(self):
        return MockRedisPipeline(self.storage)

class MockRedisPipeline:
    def __init__(self, storage):
        self.storage = storage
        self.commands = []

    def zremrangebyscore(self, key, min_val, max_val):
        self.commands.append(("zremrangebyscore", key, min_val, max_val))
        return self

    def zcard(self, key):
        self.commands.append(("zcard", key))
        return self

    def zadd(self, key, mapping):
        self.commands.append(("zadd", key, mapping))
        return self

    def expire(self, key, ttl):
        self.commands.append(("expire", key, ttl))
        return self

    async def execute(self):
        results = []
        for cmd in self.commands:
            op = cmd[0]
            if op == "zremrangebyscore":
                key = cmd[1]
                min_val = cmd[2]
                max_val = cmd[3]
                if key in self.storage:
                    self.storage[key] = [x for x in self.storage[key] if not (min_val <= x <= max_val)]
                results.append(0)
            elif op == "zcard":
                key = cmd[1]
                count = len(self.storage.get(key, []))
                results.append(count)
            elif op == "zadd":
                key = cmd[1]
                mapping = cmd[2]
                if key not in self.storage:
                    self.storage[key] = []
                for val in mapping.values():
                    self.storage[key].append(val)
                results.append(len(mapping))
            elif op == "expire":
                results.append(True)
        self.commands = []
        return results

@pytest.fixture
def mock_redis_client():
    mock_rd = MockRedis()
    with patch("app.security.rate_limit.get_redis_client", return_value=mock_rd):
        yield mock_rd

# ----------------- Service JWT Keys Generation -----------------

@pytest.fixture(scope="module")
def service_keys():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    return private_key, pem_public

# ----------------- Security Gate Tests -----------------

@pytest.mark.anyio
async def test_service_to_service_auth_success(client: AsyncClient, service_keys):
    private_key, pem_public = service_keys
    
    # Override settings public key for test module
    with patch.object(settings, "CHAT_SERVICE_PUBLIC_KEY", pem_public):
        # Generate valid service token with keys:read scope
        payload = {
            "iss": settings.SERVICE_JWT_ISSUER,
            "sub": "service:chat-service",
            "exp": int(time.time()) + 300,
            "scopes": ["keys:read"]
        }
        token = jwt.encode(payload, private_key, algorithm="EdDSA")
        
        # Call GET keys route
        target_user = uuid.uuid4()
        headers = {"Authorization": f"Bearer {token}"}
        
        # Note: If database is empty, it returns 404 "No registered devices found", 
        # but the request passes authentication successfully!
        response = await client.get(f"/e2ee/keys/{target_user}", headers=headers)
        assert response.status_code == 404
        assert response.json()["detail"] == "No registered devices found for this user"

@pytest.mark.anyio
async def test_service_to_service_auth_unauthorized_scope(client: AsyncClient, service_keys):
    private_key, pem_public = service_keys
    
    with patch.object(settings, "CHAT_SERVICE_PUBLIC_KEY", pem_public):
        # Token lacks "keys:read" scope
        payload = {
            "iss": settings.SERVICE_JWT_ISSUER,
            "sub": "service:chat-service",
            "exp": int(time.time()) + 300,
            "scopes": ["some:other:scope"]
        }
        token = jwt.encode(payload, private_key, algorithm="EdDSA")
        
        target_user = uuid.uuid4()
        headers = {"Authorization": f"Bearer {token}"}
        response = await client.get(f"/e2ee/keys/{target_user}", headers=headers)
        
        # Should return 403 Forbidden
        assert response.status_code == 403
        assert "Required scope: keys:read" in response.json()["detail"]

@pytest.mark.anyio
async def test_service_to_service_auth_invalid_issuer(client: AsyncClient, service_keys):
    private_key, pem_public = service_keys
    
    with patch.object(settings, "CHAT_SERVICE_PUBLIC_KEY", pem_public):
        payload = {
            "iss": "rogue-issuer",
            "sub": "service:chat-service",
            "exp": int(time.time()) + 300,
            "scopes": ["keys:read"]
        }
        token = jwt.encode(payload, private_key, algorithm="EdDSA")
        
        target_user = uuid.uuid4()
        headers = {"Authorization": f"Bearer {token}"}
        response = await client.get(f"/e2ee/keys/{target_user}", headers=headers)
        assert response.status_code == 401
        assert "Invalid service token issuer" in response.json()["detail"]

@pytest.mark.anyio
async def test_rate_limiting_enforcement(client: AsyncClient, mock_redis_client):
    # Let's test device register rate limits
    # The register_user_limiter has a limit of 3 requests per minute.
    # We send 4 requests and expect the 4th to fail with HTTP 429.
    payload = {
        "device_id": "test-device-rate-limit-id",
        "device_name": "Test Laptop",
        "identity_key": "dGVzdF9pZGVudGl0eV9rZXk=",
        "signed_prekey": {
            "key_id": 1,
            "key": "dGVzdF9zaWduZWRfcHJla2V5",
            "signature": "dGVzdF9zaWduYXR1cmU="
        },
        "one_time_prekeys": []
    }
    
    # First 3 requests should pass authentication/validation (or fail on database rules but not 429)
    # Note: registering a device with duplicate keys or structure yields database output or 201/400.
    # But rate limiter triggers first.
    for i in range(3):
        response = await client.post("/e2ee/devices", json=payload)
        # Verify it does not return 429
        assert response.status_code != 429
        
    # The 4th request must trigger rate limit (429)
    response = await client.post("/e2ee/devices", json=payload)
    assert response.status_code == 429
    assert response.json()["detail"]["error"] == "Too Many Requests"
