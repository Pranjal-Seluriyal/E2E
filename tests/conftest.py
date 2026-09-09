import pytest
import asyncio
from typing import AsyncGenerator
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.main import app
from app.database import get_db
from app.models.base import Base
from app.security import get_current_user_id
import uuid

TEST_DATABASE_URL = "sqlite+aiosqlite:///test_temp.db"

@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"

@pytest.fixture(scope="session", autouse=True)
def test_engine():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    # Rebind global async_session_maker to SQLite for testing
    from app.database.session import async_session_maker
    async_session_maker.configure(bind=engine)
    
    async def setup_db():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            
    asyncio.run(setup_db())
    yield engine
    
    async def teardown_db():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()
        
    asyncio.run(teardown_db())
    
    import os
    try:
        if os.path.exists("test_temp.db"):
            os.remove("test_temp.db")
    except Exception:
        pass

async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
    from app.database.session import async_session_maker
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()

@pytest.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    from app.database.session import async_session_maker
    async with async_session_maker() as session:
        yield session
        await session.rollback()
        await session.close()


# Mock user uuid for test routes
MOCK_USER_ID = uuid.uuid4()

async def override_get_current_user_id() -> uuid.UUID:
    return MOCK_USER_ID

@pytest.fixture(autouse=True)
def reset_redis_state(monkeypatch):
    """Resets lazy client state and disables rate limiting before each test."""
    from app.security import rate_limit
    import redis.asyncio as redis
    rate_limit.redis_client = None

    def mock_redis():
        raise redis.RedisError("Rate limiter disabled for testing")

    monkeypatch.setattr("app.security.rate_limit.get_redis_client", mock_redis)
    app.dependency_overrides[get_db] = override_get_db

@pytest.fixture
async def client() -> AsyncGenerator[AsyncClient, None]:
    app.dependency_overrides[get_current_user_id] = override_get_current_user_id
    
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver"
    ) as ac:
        yield ac
        
    app.dependency_overrides.clear()
