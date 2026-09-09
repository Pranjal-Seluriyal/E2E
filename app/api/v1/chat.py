from fastapi import APIRouter, Depends, status, HTTPException, WebSocket, WebSocketDisconnect, Request
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from uuid import UUID
import json
import logging
from app.database import get_db
from app.security import get_current_user_id, get_auth_context
from fastapi.security import HTTPAuthorizationCredentials
from app.schemas.chat import (
    ConversationCreateRequest,
    ConversationResponse,
    MessageSendRequest,
    MessageResponse,
    EnvelopeMessageResponse
)
from app.services.chat_service import ChatService
from app.services.websocket_manager import ws_manager

logger = logging.getLogger("chat-api")
router = APIRouter()

@router.post("/conversations", response_model=ConversationResponse, status_code=status.HTTP_201_CREATED)
async def create_conversation(
    req: ConversationCreateRequest,
    user_id: UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """Creates a new 1-to-1 or group conversation."""
    service = ChatService(db)
    conv = await service.create_conversation(
        creator_id=user_id,
        participant_ids=req.participant_ids,
        name=req.name
    )
    participants = await service.chat_repo.get_conversation_participants(conv.id)
    return ConversationResponse(
        conversation_id=conv.id,
        is_group=conv.is_group,
        name=conv.name,
        created_at=conv.created_at,
        participants=participants
    )

@router.get("/conversations", response_model=List[ConversationResponse])
async def list_conversations(
    user_id: UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """Lists all conversations the authenticated user is a participant of."""
    service = ChatService(db)
    convs = await service.list_user_conversations(user_id)
    return [
        ConversationResponse(
            conversation_id=c["conversation_id"],
            is_group=c["is_group"],
            name=c["name"],
            created_at=c["created_at"],
            participants=c["participants"]
        )
        for c in convs
    ]

@router.post("/conversations/{conversation_id}/messages", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def send_message(
    conversation_id: UUID,
    req: MessageSendRequest,
    request: Request,
    user_id: UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """Sends an E2EE message by uploading ciphertext envelopes for all target participant devices."""
    service = ChatService(db)
    sender_device_id = request.headers.get("X-Device-Id", "unknown-device")
    
    msg = await service.send_message(
        sender_id=user_id,
        sender_device_id=sender_device_id,
        conversation_id=conversation_id,
        envelopes=req.envelopes
    )
    
    # Real-time WebSocket delivery broadcast
    participants = await service.chat_repo.get_conversation_participants(conversation_id)
    for p_id in participants:
        for uid, dev_id in list(ws_manager.active_connections.keys()):
            if uid == p_id and dev_id in req.envelopes:
                payload = req.envelopes[dev_id]
                event = {
                    "type": "message",
                    "message_id": str(msg.id),
                    "conversation_id": str(conversation_id),
                    "sender_id": str(user_id),
                    "sender_device_id": sender_device_id,
                    "recipient_device_id": dev_id,
                    "encrypted_payload": payload,
                    "created_at": msg.created_at.isoformat()
                }
                sent = await ws_manager.send_to_device(uid, dev_id, event)
                if sent:
                    # Update envelope status to delivered
                    await service.chat_repo.mark_envelope_status_by_device(msg.id, dev_id, "delivered")
    
    # Commit any status updates made during realtime delivery
    await db.commit()
    return MessageResponse(
        message_id=msg.id,
        conversation_id=msg.conversation_id,
        sender_id=msg.sender_id,
        sender_device_id=msg.sender_device_id,
        created_at=msg.created_at
    )

@router.get("/conversations/{conversation_id}/messages", response_model=List[EnvelopeMessageResponse])
async def get_messages(
    conversation_id: UUID,
    request: Request,
    user_id: UUID = Depends(get_current_user_id),
    db: AsyncSession = Depends(get_db)
):
    """Retrieves all message envelopes addressed to the caller's specific device for a conversation."""
    service = ChatService(db)
    device_id = request.headers.get("X-Device-Id")
    if not device_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Device-Id header is required"
        )
    
    envelopes = await service.get_device_envelopes(user_id, device_id, unread_only=False)
    # Filter envelopes to only this conversation
    conversation_envelopes = [
        EnvelopeMessageResponse(
            envelope_id=env["envelope_id"],
            message_id=env["message_id"],
            conversation_id=env["conversation_id"],
            sender_id=env["sender_id"],
            sender_device_id=env["sender_device_id"],
            recipient_device_id=env["recipient_device_id"],
            encrypted_payload=env["encrypted_payload"],
            status=env["status"],
            created_at=env["created_at"],
            delivered_at=env["delivered_at"],
            read_at=env["read_at"]
        )
        for env in envelopes if env["conversation_id"] == conversation_id
    ]
    return conversation_envelopes

@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: Optional[str] = None,
    device_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    # Retrieve query params if not provided as dependency arguments
    if not token:
        token = websocket.query_params.get("token")
    if not device_id:
        device_id = websocket.query_params.get("device_id")

    if not token or not device_id:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Authenticate token
    try:
        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        ctx = await get_auth_context(creds)
        if not ctx.user_id:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        user_id = ctx.user_id
    except Exception as e:
        logger.error(f"WebSocket auth failed: {str(e)}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    service = ChatService(db)
    
    # Check that device is registered under this user
    device = await service.device_repo.get_device(user_id, device_id)
    if not device:
        logger.warning(f"WebSocket connect blocked: Device {device_id} not registered for user {user_id}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Establish connection
    await ws_manager.connect(user_id, device_id, websocket)

    # Deliver pending offline messages
    try:
        offline_envs = await service.get_device_envelopes(user_id, device_id, unread_only=True)
        for env in offline_envs:
            event = {
                "type": "message",
                "message_id": str(env["message_id"]),
                "conversation_id": str(env["conversation_id"]),
                "sender_id": str(env["sender_id"]),
                "sender_device_id": env["sender_device_id"],
                "recipient_device_id": env["recipient_device_id"],
                "encrypted_payload": env["encrypted_payload"],
                "created_at": env["created_at"].isoformat()
            }
            sent = await ws_manager.send_to_device(user_id, device_id, event)
            if sent:
                await service.chat_repo.mark_envelope_status(env["envelope_id"], "delivered")
        await db.commit()
    except Exception as e:
        logger.error(f"Error flushing offline envelopes for user {user_id} device {device_id}: {str(e)}")

    # Main event loop
    try:
        while True:
            data = await websocket.receive_text()
            event = json.loads(data)
            
            event_type = event.get("type")
            if event_type == "typing":
                conv_id_str = event.get("conversation_id")
                is_typing = event.get("is_typing", False)
                if conv_id_str:
                    await ws_manager.broadcast_typing(UUID(conv_id_str), user_id, is_typing)
            
            elif event_type == "read_receipt":
                env_id = event.get("envelope_id")
                if env_id:
                    await service.mark_envelope_read(user_id, device_id, int(env_id))
            
            elif event_type == "conversation_read":
                conv_id_str = event.get("conversation_id")
                if conv_id_str:
                    await service.mark_conversation_read(user_id, device_id, UUID(conv_id_str))

    except WebSocketDisconnect:
        await ws_manager.disconnect(user_id, device_id)
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id} device {device_id}: {str(e)}")
        await ws_manager.disconnect(user_id, device_id)
