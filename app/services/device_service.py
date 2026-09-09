from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from uuid import UUID
from app.repositories.device_repository import DeviceRepository
from app.repositories.key_repository import KeyRepository
from app.schemas.devices import DeviceRegisterRequest, DeviceResponse
from app.models.devices import Device
from app.security import verify_signed_prekey_signature
from fastapi import HTTPException, status
import base64

class DeviceService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.device_repo = DeviceRepository(db)
        self.key_repo = KeyRepository(db)

    async def register_device(self, user_id: UUID, req: DeviceRegisterRequest) -> Device:
        # 1. Prevent reuse of revoked device IDs
        if await self.device_repo.is_revoked(user_id, req.device_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Device ID has been revoked and cannot be reused"
            )

        # 2. Cryptographic signature check
        is_valid = verify_signed_prekey_signature(
            identity_key_b64=req.identity_key,
            signed_prekey_b64=req.signed_prekey.key,
            signature_b64=req.signed_prekey.signature
        )
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Signed prekey signature verification failed"
            )

        # Decode base64 keys to byte arrays
        identity_bytes = base64.b64decode(req.identity_key)
        spk_bytes = base64.b64decode(req.signed_prekey.key)
        spk_sig_bytes = base64.b64decode(req.signed_prekey.signature)

        # 3. Create or update Device record
        device = await self.device_repo.get_device(user_id, req.device_id)
        if not device:
            device = await self.device_repo.create_device(
                user_id=user_id,
                device_id=req.device_id,
                device_name=req.device_name
            )

        # 4. Save device public key bundle
        await self.key_repo.save_public_keys(
            user_id=user_id,
            device_id=req.device_id,
            identity_key=identity_bytes,
            signed_prekey=spk_bytes,
            signed_prekey_sig=spk_sig_bytes,
            signed_prekey_id=req.signed_prekey.key_id
        )

        # 5. Save one-time prekeys
        prekey_tuples = [
            (pk.key_id, base64.b64decode(pk.key))
            for pk in req.one_time_prekeys
        ]
        await self.key_repo.add_one_time_prekeys(
            user_id=user_id,
            device_id=req.device_id,
            prekeys=prekey_tuples
        )

        await self.db.commit()
        return device

    async def list_user_devices(self, user_id: UUID) -> List[Device]:
        return await self.device_repo.get_user_devices(user_id)

    async def get_device(self, user_id: UUID, device_id: str) -> Optional[Device]:
        return await self.device_repo.get_device(user_id, device_id)

    async def revoke_device(self, user_id: UUID, device_id: str) -> None:
        # Add to revocation log and delete from active devices list
        deleted = await self.device_repo.delete_device(user_id, device_id)
        if deleted:
            await self.device_repo.add_revocation(user_id, device_id)
            await self.db.commit()
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
