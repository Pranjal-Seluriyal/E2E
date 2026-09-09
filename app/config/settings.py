from pydantic_settings import BaseSettings
from pydantic import Field

class Settings(BaseSettings):
    PROJECT_NAME: str = "Reddit-Insta E2EE Service"
    DEBUG: bool = True
    API_V1_STR: str = "/api/v1"

    # Database Settings
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://postgres:postgres@localhost:5432/e2e_db",
        description="Database URL for asynchronous SQLAlchemy connection"
    )

    # JWT Settings (shares configuration with the existing Auth Service)
    JWT_SECRET_KEY: str = Field(
        default="supersecretjwtkeyforverifyingincomingusers",
        description="Secret key to verify user authorization tokens"
    )
    ALGORITHM: str = "HS256"

    # Service-to-Service Authentication Settings
    CHAT_SERVICE_PUBLIC_KEY: str = Field(
        default="-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6gWWEtMAuxgbcHstK1dXYXcH27Ji3RCxo=\n-----END PUBLIC KEY-----",
        description="PEM-encoded Ed25519 public key of the Chat Service for validating service-to-service JWTs"
    )
    SERVICE_JWT_ISSUER: str = Field(
        default="chat-identity-provider",
        description="Expected issuer claim for service tokens"
    )

    # Redis Settings
    REDIS_URL: str = "redis://localhost:6379/0"

    # CORS Settings
    CORS_ORIGINS: str = "*"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
