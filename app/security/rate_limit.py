import time
import logging
import inspect
import asyncio
from fastapi import Request, HTTPException, status, Depends
from app.config import settings
from app.security.authentication import get_auth_context
from fastapi.security import HTTPBearer
import redis.asyncio as redis
from typing import Callable, Optional

logger = logging.getLogger("rate-limiter")
token_extractor = HTTPBearer(auto_error=False)

# Lazy-loaded Redis client
redis_client: Optional[redis.Redis] = None

def get_redis_client() -> redis.Redis:
    global redis_client
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    if redis_client is not None:
        client_loop = getattr(redis_client.connection_pool, "_loop", None) or getattr(redis_client.connection_pool, "loop", None)
        if client_loop is None or client_loop.is_closed() or (current_loop and client_loop != current_loop):
            redis_client = None

    if redis_client is None:
        redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    return redis_client

class RateLimiter:
    def __init__(
        self,
        limit: int,
        window_seconds: int,
        key_prefix: str,
        identifier_extractor: Callable[[Request], str]
    ):
        self.limit = limit
        self.window_seconds = window_seconds
        self.key_prefix = key_prefix
        self.identifier_extractor = identifier_extractor

    async def __call__(self, request: Request):
        # 1. Resolve the unique identifier for rate limiting
        try:
            res = self.identifier_extractor(request)
            if inspect.isawaitable(res):
                identifier = await res
            else:
                identifier = res
        except Exception as e:
            logger.warning(f"Identifier extraction failed: {str(e)}. Falling back to IP.")
            identifier = request.client.host if request.client else "unknown"

        key = f"rate_limit:{self.key_prefix}:{identifier}"
        
        # 2. Execute sliding window check in Redis
        try:
            r = get_redis_client()
            now_ms = int(time.time() * 1000)
            clear_before_ms = now_ms - (self.window_seconds * 1000)
            
            pipe = r.pipeline()
            # Clean old expired requests
            pipe.zremrangebyscore(key, 0, clear_before_ms)
            # Count requests in window
            pipe.zcard(key)
            _, count = await pipe.execute()
            
            if count >= self.limit:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error": "Too Many Requests",
                        "retry_after": self.window_seconds,
                        "message": f"Rate limit exceeded. Maximum of {self.limit} requests per {self.window_seconds} seconds."
                    }
                )
            
            # Record current request with expiration
            pipe = r.pipeline()
            pipe.zadd(key, {str(now_ms): now_ms})
            pipe.expire(key, self.window_seconds)
            await pipe.execute()
            
        except HTTPException:
            raise
        except Exception as e:
            # Fail open in production to prevent Redis outage from blocking application traffic
            logger.error(f"Redis rate limiter failed: {str(e)}. Failing open.")
            return

# ----------------- Identifier Extractors -----------------

def get_ip_identifier(request: Request) -> str:
    """Extracts IP address from client request."""
    return request.client.host if request.client else "unknown"

async def get_user_or_ip_identifier(request: Request) -> str:
    """Extracts User ID or Service name if authenticated; falls back to IP address."""
    creds = await token_extractor(request)
    if creds:
        try:
            ctx = await get_auth_context(creds)
            if ctx.user_id:
                return f"user:{str(ctx.user_id)}"
            elif ctx.service:
                return f"service:{ctx.service.service_name}"
        except Exception:
            pass
    return get_ip_identifier(request)

async def get_user_device_identifier(request: Request) -> str:
    """Extracts User ID and Device ID (from path parameters if available)."""
    device_id = request.path_params.get("device_id")
    device_suffix = f":device:{device_id}" if device_id else ""
    
    creds = await token_extractor(request)
    if creds:
        try:
            ctx = await get_auth_context(creds)
            if ctx.user_id:
                return f"user:{str(ctx.user_id)}{device_suffix}"
        except Exception:
            pass
            
    return get_ip_identifier(request) + device_suffix

# ----------------- Predefined Limiter Instances -----------------

# Device Registration: Limit per User (3/min) and IP (5/min)
register_ip_limiter = RateLimiter(limit=5, window_seconds=60, key_prefix="register_device_ip", identifier_extractor=get_ip_identifier)
register_user_limiter = RateLimiter(limit=3, window_seconds=60, key_prefix="register_device_user", identifier_extractor=get_user_or_ip_identifier)

# Key bundle retrieval: Limit per user (100/min) or service (10000/min)
async def dynamic_bundle_retrieval_limiter(request: Request):
    """Dynamic rate limit based on identity (Service vs User)."""
    creds = await token_extractor(request)
    limit = 100
    prefix = "bundle_user"
    
    if creds:
        try:
            ctx = await get_auth_context(creds)
            if ctx.service:
                limit = 10000  # High limit for backend services
                prefix = "bundle_service"
        except Exception:
            pass
            
    limiter = RateLimiter(limit=limit, window_seconds=60, key_prefix=prefix, identifier_extractor=get_user_or_ip_identifier)
    await limiter(request)

# Prekey operations (Replenish & Rotate): Limit per User-Device (10/min)
prekey_ops_limiter = RateLimiter(limit=10, window_seconds=60, key_prefix="prekey_ops", identifier_extractor=get_user_device_identifier)

# Device operations (Get, List, Revoke): Limit per User (20/min)
device_ops_limiter = RateLimiter(limit=20, window_seconds=60, key_prefix="device_ops", identifier_extractor=get_user_or_ip_identifier)
