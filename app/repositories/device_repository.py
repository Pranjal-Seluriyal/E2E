from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List, Optional
from uuid import UUID
from app.models.devices import Device, DeviceRevocation

class DeviceRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_device(self, user_id: UUID, device_id: str) -> Optional[Device]:
        result = await self.db.execute(
            select(Device).filter(Device.user_id == user_id, Device.device_id == device_id)
        )
        return result.scalars().first()

    async def get_user_devices(self, user_id: UUID) -> List[Device]:
        result = await self.db.execute(
            select(Device).filter(Device.user_id == user_id)
        )
        return list(result.scalars().all())

    async def create_device(self, user_id: UUID, device_id: str, device_name: Optional[str]) -> Device:
        device = Device(user_id=user_id, device_id=device_id, device_name=device_name)
        self.db.add(device)
        await self.db.flush()
        return device

    async def delete_device(self, user_id: UUID, device_id: str) -> bool:
        device = await self.get_device(user_id, device_id)
        if device:
            await self.db.delete(device)
            await self.db.flush()
            return True
        return False

    async def add_revocation(self, user_id: UUID, device_id: str) -> DeviceRevocation:
        revocation = DeviceRevocation(user_id=user_id, device_id=device_id)
        self.db.add(revocation)
        await self.db.flush()
        return revocation

    async def is_revoked(self, user_id: UUID, device_id: str) -> bool:
        result = await self.db.execute(
            select(DeviceRevocation).filter(
                DeviceRevocation.user_id == user_id,
                DeviceRevocation.device_id == device_id
            )
        )
        return result.scalars().first() is not None
