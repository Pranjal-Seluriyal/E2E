import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.services.device_service import DeviceService
from app.schemas.devices import DeviceRegisterRequest, SignedPrekeySchema
import uuid

@pytest.mark.anyio
async def test_device_service_registration_flow(db_session: AsyncSession):
    service = DeviceService(db_session)
    user_uuid = uuid.uuid4()
    
    req = DeviceRegisterRequest(
        device_id="test-device-uuid-1234",
        device_name="Android Phone",
        identity_key="dGVzdF9pZGVudGl0eV9rZXk=",
        signed_prekey=SignedPrekeySchema(
            key_id=1,
            key="dGVzdF9zaWduZWRfcHJla2V5",
            signature="dGVzdF9zaWduYXR1cmU="
        ),
        one_time_prekeys=[]
    )
    
    device = await service.register_device(user_uuid, req)
    assert device.user_id == user_uuid
    assert device.device_id == "test-device-uuid-1234"
    assert device.device_name == "Android Phone"
