from fastapi import APIRouter
from app.api.v1 import devices, keys, chat

api_router = APIRouter()

# Register device endpoints under /devices (will resolve to /e2ee/devices)
api_router.include_router(devices.router, prefix="/devices", tags=["devices"])

# Register keys endpoints. Since they use various root structures like /keys/{user_id} and /prekeys,
# mounting keys.router at prefix="" allows paths to map directly under /e2ee
api_router.include_router(keys.router, prefix="", tags=["keys"])

# Register chat endpoints under prefix "" to allow /conversations and /ws to resolve directly under /e2ee
api_router.include_router(chat.router, prefix="", tags=["chat"])

