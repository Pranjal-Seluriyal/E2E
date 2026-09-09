from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
from app.database import get_db
from app.security import get_current_user_id, require_service_or_user, AuthContext
from app.security.rate_limit import dynamic_bundle_retrieval_limiter, prekey_ops_limiter
from app.schemas.keys import UserKeyBundleResponse, PrekeyReplenishRequest
from app.schemas.devices import SignedPrekeySchema
from app.services.key_service import KeyService

router = APIRouter()

@router.get("/keys/{user_id}", response_model=UserKeyBundleResponse)
async def get_user_keys(
    user_id: UUID,
    auth_ctx: AuthContext = Depends(require_service_or_user),
    db: AsyncSession = Depends(get_db),
    _limit: None = Depends(dynamic_bundle_retrieval_limiter)
):
    """Retrieves public key bundles of all active devices registered under a given user ID, 
    consuming exactly one one-time prekey per device.
    """
    service = KeyService(db)
    return await service.get_user_key_bundles(user_id)

@router.post("/prekeys", status_code=status.HTTP_200_OK)
async def replenish_prekeys(
    req: PrekeyReplenishRequest,
    user_id: UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
    _limit: None = Depends(prekey_ops_limiter)
):
    """Replenishes the pool of single-use One-Time Prekeys (OPKs) for a specific device."""
    service = KeyService(db)
    await service.replenish_one_time_prekeys(user_id, req.device_id, req.one_time_prekeys)
    return {"status": "success", "message": "Prekeys replenished successfully"}

@router.post("/devices/{device_id}/rotate", status_code=status.HTTP_200_OK)
async def rotate_signed_prekey(
    device_id: str,
    req: SignedPrekeySchema,
    user_id: UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
    _limit: None = Depends(prekey_ops_limiter)
):
    """Rotates the medium-term Signed Prekey (SPK) for a specific device, verifying signatures."""
    service = KeyService(db)
    await service.rotate_signed_prekey(user_id, device_id, req)
    return {"status": "success", "message": "Signed prekey rotated successfully"}
