from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from uuid import UUID
from typing import Optional, List
from pydantic import BaseModel
from app.config import settings
from cryptography.hazmat.primitives.serialization import load_pem_public_key

security = HTTPBearer()

class ServiceIdentity(BaseModel):
    service_name: str
    scopes: List[str]

class AuthContext(BaseModel):
    user_id: Optional[UUID] = None
    service: Optional[ServiceIdentity] = None

async def get_auth_context(credentials: HTTPAuthorizationCredentials = Depends(security)) -> AuthContext:
    """Decodes incoming authorization token. 
    Attempts user JWT validation (symmetric) first, then falls back to service JWT validation (asymmetric Ed25519).
    """
    token = credentials.credentials
    
    # 1. Attempt decoding as a standard user JWT
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        user_id_str = payload.get("sub") or payload.get("user_id")
        if user_id_str:
            return AuthContext(user_id=UUID(user_id_str))
    except jwt.PyJWTError:
        pass  # If user token decoding fails, fall back to service token validation

    # 2. Attempt decoding as a service JWT using Ed25519 public key
    try:
        public_key = load_pem_public_key(settings.CHAT_SERVICE_PUBLIC_KEY.encode("utf-8"))
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["EdDSA"],
            options={"require": ["exp", "iss", "sub"]}
        )
        
        issuer = payload.get("iss")
        if issuer != settings.SERVICE_JWT_ISSUER:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid service token issuer"
            )
            
        sub = payload.get("sub")
        if not sub or not sub.startswith("service:"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid service token subject format"
            )
            
        service_name = sub.split("service:", 1)[1]
        scopes = payload.get("scopes", [])
        return AuthContext(service=ServiceIdentity(service_name=service_name, scopes=scopes))
        
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token verification failed: {str(e)}"
        )

async def get_current_user_id(credentials: HTTPAuthorizationCredentials = Depends(security)) -> UUID:
    """Helper to enforce user-only context on endpoints. Backward compatible."""
    context = await get_auth_context(credentials)
    if not context.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User context required for this operation"
        )
    return context.user_id

async def require_service_or_user(context: AuthContext = Depends(get_auth_context)) -> AuthContext:
    """Enforces that the caller is either an authenticated user or a service with keys:read scope."""
    if context.service:
        if "keys:read" not in context.service.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Service unauthorized. Required scope: keys:read"
            )
    return context
