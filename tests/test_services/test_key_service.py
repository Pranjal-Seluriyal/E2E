import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.services.device_service import DeviceService
from app.services.key_service import KeyService
from app.schemas.devices import DeviceRegisterRequest, SignedPrekeySchema, OneTimePrekeySchema
import uuid

@pytest.mark.anyio
async def test_key_service_bundle_flow(db_session: AsyncSession):
    device_service = DeviceService(db_session)
    key_service = KeyService(db_session)
    user_uuid = uuid.uuid4()
    
    # Register device with 1 one-time prekey
    req = DeviceRegisterRequest(
        device_id="test-device-uuid-5678",
        device_name="Tablet",
        identity_key="dGVzdF9pZGVudGl0eV9rZXk=",
        signed_prekey=SignedPrekeySchema(
            key_id=1,
            key="dGVzdF9zaWduZWRfcHJla2V5",
            signature="dGVzdF9zaWduYXR1cmU="
        ),
        one_time_prekeys=[
            OneTimePrekeySchema(key_id=10, key="dGVzdF9vdGtfMTA=")
        ]
    )
    await device_service.register_device(user_uuid, req)
    
    # Fetch bundle (should consume the prekey)
    bundle = await key_service.get_user_key_bundles(user_uuid)
    assert bundle.user_id == user_uuid
    assert len(bundle.devices) == 1
    assert bundle.devices[0].device_id == "test-device-uuid-5678"
    assert bundle.devices[0].one_time_prekey is not None
    assert bundle.devices[0].one_time_prekey.key_id == 10

    # Fetch bundle again (prekey was consumed, should be None)
    bundle2 = await key_service.get_user_key_bundles(user_uuid)
    assert bundle2.devices[0].one_time_prekey is None
