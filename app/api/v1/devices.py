from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import UUID
from app.database import get_db
from app.security import get_current_user_id
from app.security.rate_limit import register_ip_limiter, register_user_limiter, device_ops_limiter
from app.schemas.devices import DeviceRegisterRequest, DeviceResponse
from app.services.device_service import DeviceService

router = APIRouter()

@router.post("", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def register_device(
    req: DeviceRegisterRequest,
    user_id: UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
    _ip_limit: None = Depends(register_ip_limiter),
    _user_limit: None = Depends(register_user_limiter)
):
    """Registers a new active device and uploads its initial cryptographic public key bundle."""
    service = DeviceService(db)
    device = await service.register_device(user_id, req)
    return device

@router.get("", response_model=List[DeviceResponse])
async def list_devices(
    user_id: UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
    _limit: None = Depends(device_ops_limiter)
):
    """Lists all active devices registered under the authenticated user's profile."""
    service = DeviceService(db)
    return await service.list_user_devices(user_id)

@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: str,
    user_id: UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
    _limit: None = Depends(device_ops_limiter)
):
    """Retrieves details of a specific active device owned by the authenticated user."""
    service = DeviceService(db)
    device = await service.get_device(user_id, device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found or does not belong to you"
        )
    return device

@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_device(
    device_id: str,
    user_id: UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db),
    _limit: None = Depends(device_ops_limiter)
):
    """Deletes a registered device and adds it to the revocation list, invalidating its keys."""
    service = DeviceService(db)
    await service.revoke_device(user_id, device_id)
