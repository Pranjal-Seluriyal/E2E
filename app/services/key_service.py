from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
from uuid import UUID
import base64
from app.repositories.key_repository import KeyRepository
from app.repositories.device_repository import DeviceRepository
from app.schemas.keys import UserKeyBundleResponse, DeviceKeyBundleResponse
from app.schemas.devices import SignedPrekeySchema, OneTimePrekeySchema
from app.security import verify_signed_prekey_signature
from fastapi import HTTPException, status

class KeyService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.key_repo = KeyRepository(db)
        self.device_repo = DeviceRepository(db)

    async def get_user_key_bundles(self, user_id: UUID) -> UserKeyBundleResponse:
        # Get active devices
        devices = await self.device_repo.get_user_devices(user_id)
        if not devices:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No registered devices found for this user"
            )

        bundles = []
        for dev in devices:
            # 1. Fetch public keys
            pub_keys = await self.key_repo.get_public_keys(user_id, dev.device_id)
            if not pub_keys:
                continue

            # 2. Fetch and consume exactly one one-time prekey
            otk = await self.key_repo.get_unused_prekey(user_id, dev.device_id)
            otk_schema = None
            if otk:
                otk.consumed = True  # Consume immediately in transaction
                otk_schema = OneTimePrekeySchema(
                    key_id=otk.prekey_id,
                    key=base64.b64encode(otk.prekey).decode("utf-8")
                )

            signed_prekey_schema = SignedPrekeySchema(
                key_id=pub_keys.signed_prekey_id,
                key=base64.b64encode(pub_keys.signed_prekey).decode("utf-8"),
                signature=base64.b64encode(pub_keys.signed_prekey_signature).decode("utf-8")
            )

            bundles.append(
                DeviceKeyBundleResponse(
                    device_id=dev.device_id,
                    identity_key=base64.b64encode(pub_keys.identity_key).decode("utf-8"),
                    signed_prekey=signed_prekey_schema,
                    one_time_prekey=otk_schema
                )
            )

        await self.db.commit()
        return UserKeyBundleResponse(user_id=user_id, devices=bundles)

    async def rotate_signed_prekey(
        self,
        user_id: UUID,
        device_id: str,
        spk: SignedPrekeySchema
    ) -> None:
        # 1. Retrieve current public key configuration
        pub_keys = await self.key_repo.get_public_keys(user_id, device_id)
        if not pub_keys:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Public keys configuration for this device not found"
            )

        # 2. Cryptographically verify signature of new SPK against existing identity key
        identity_b64 = base64.b64encode(pub_keys.identity_key).decode("utf-8")
        is_valid = verify_signed_prekey_signature(
            identity_key_b64=identity_b64,
            signed_prekey_b64=spk.key,
            signature_b64=spk.signature
        )
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New signed prekey signature verification failed"
            )

        # 3. Save new values
        pub_keys.signed_prekey = base64.b64decode(spk.key)
        pub_keys.signed_prekey_signature = base64.b64decode(spk.signature)
        pub_keys.signed_prekey_id = spk.key_id

        await self.db.commit()

    async def replenish_one_time_prekeys(
        self,
        user_id: UUID,
        device_id: str,
        prekeys: List[OneTimePrekeySchema]
    ) -> None:
        # Verify device exists and is active
        device = await self.device_repo.get_device(user_id, device_id)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )

        prekey_tuples = [
            (pk.key_id, base64.b64decode(pk.key))
            for pk in prekeys
        ]
        await self.key_repo.add_one_time_prekeys(user_id, device_id, prekey_tuples)
        await self.db.commit()
