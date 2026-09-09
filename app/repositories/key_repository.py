from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List, Optional
from uuid import UUID
from app.models.keys import DevicePublicKey, OneTimePrekey

class KeyRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_public_keys(self, user_id: UUID, device_id: str) -> Optional[DevicePublicKey]:
        result = await self.db.execute(
            select(DevicePublicKey).filter(
                DevicePublicKey.user_id == user_id,
                DevicePublicKey.device_id == device_id
            )
        )
        return result.scalars().first()

    async def save_public_keys(
        self,
        user_id: UUID,
        device_id: str,
        identity_key: bytes,
        signed_prekey: bytes,
        signed_prekey_sig: bytes,
        signed_prekey_id: int
    ) -> DevicePublicKey:
        pub_key = await self.get_public_keys(user_id, device_id)
        if not pub_key:
            pub_key = DevicePublicKey(
                user_id=user_id,
                device_id=device_id,
                identity_key=identity_key,
                signed_prekey=signed_prekey,
                signed_prekey_signature=signed_prekey_sig,
                signed_prekey_id=signed_prekey_id
            )
            self.db.add(pub_key)
        else:
            pub_key.identity_key = identity_key
            pub_key.signed_prekey = signed_prekey
            pub_key.signed_prekey_signature = signed_prekey_sig
            pub_key.signed_prekey_id = signed_prekey_id
        await self.db.flush()
        return pub_key

    async def add_one_time_prekeys(self, user_id: UUID, device_id: str, prekeys: List[tuple]) -> None:
        """prekeys: list of tuples (prekey_id, prekey_bytes)"""
        for pk_id, pk_val in prekeys:
            # Upsert behavior if already exists, otherwise add
            db_pk = OneTimePrekey(
                user_id=user_id,
                device_id=device_id,
                prekey_id=pk_id,
                prekey=pk_val,
                consumed=False
            )
            self.db.add(db_pk)
        await self.db.flush()

    async def get_unused_prekey(self, user_id: UUID, device_id: str) -> Optional[OneTimePrekey]:
        # Lock row for update to prevent concurrent race condition deliveries
        query = (
            select(OneTimePrekey)
            .filter(
                OneTimePrekey.user_id == user_id,
                OneTimePrekey.device_id == device_id,
                OneTimePrekey.consumed == False
            )
            .limit(1)
            .with_for_update()
        )
        result = await self.db.execute(query)
        return result.scalars().first()

    async def count_unused_prekeys(self, user_id: UUID, device_id: str) -> int:
        result = await self.db.execute(
            select(OneTimePrekey).filter(
                OneTimePrekey.user_id == user_id,
                OneTimePrekey.device_id == device_id,
                OneTimePrekey.consumed == False
            )
        )
        return len(result.scalars().all())
