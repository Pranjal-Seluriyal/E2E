from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlalchemy import text
from app.config import settings
from app.api import api_router
from app.database import engine
import logging

# Basic logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("e2ee-service")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing E2EE Microservice startup tasks...")
    # Verify DB connectivity
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("Database connection established successfully.")
    except Exception as e:
        logger.error(f"Database connection failed: {str(e)}")
    
    yield
    
    logger.info("Disposing E2EE Microservice database connection engine...")
    await engine.dispose()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Dedicated E2EE Cryptographic Identity & Prekey microservice for Reddit/Instagram platform.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS configuration
cors_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
allow_credentials = True
if cors_origins == ["*"] or "*" in cors_origins:
    allow_credentials = False

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security headers and CSP middleware
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    path = request.url.path
    if path in ["/docs", "/redoc", "/openapi.json"]:
        csp_directives = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.jsdelivr.net; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self';"
        )
    else:
        csp_directives = (
            "default-src 'none'; "
            "script-src 'self'; "
            "connect-src 'self' ws: wss:; "
            "img-src 'self' data:; "
            "style-src 'self' 'unsafe-inline'; "
            "frame-ancestors 'none'; "
            "base-uri 'self';"
        )
    response.headers["Content-Security-Policy"] = csp_directives
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return response

# Include main router under prefix /e2ee
app.include_router(api_router, prefix="/e2ee")

@app.get("/health", tags=["health"])
async def health_check():
    """Liveness and readiness check endpoint for service status verification."""
    return {"status": "healthy", "service": settings.PROJECT_NAME}
