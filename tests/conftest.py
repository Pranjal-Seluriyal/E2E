import pytest
from typing import AsyncGenerator
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.main import app
from app.database import get_db
from app.models.base import Base
from app.security import get_current_user_id
import uuid

# SQLite test database file for local testing
TEST_DATABASE_URL = "sqlite+aiosqlite:///test_temp.db"

@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"

@pytest.fixture(scope="session")
async def test_engine():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    # Rebind the global session maker to SQLite for testing
    from app.database.session import async_session_maker
    async_session_maker.configure(bind=engine)
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()
    
    import os
    try:
        if os.path.exists("test_temp.db"):
            os.remove("test_temp.db")
    except Exception:
        pass

@pytest.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    async_session_maker = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with async_session_maker() as session:
        yield session
        await session.rollback()
        await session.close()

# Mock mock user uuid for test routes
MOCK_USER_ID = uuid.uuid4()

async def override_get_current_user_id() -> uuid.UUID:
    return MOCK_USER_ID

@pytest.fixture(autouse=True)
def reset_redis_state():
    """Resets lazy client state before each test."""
    from app.security import rate_limit
    rate_limit.redis_client = None

@pytest.fixture
async def client(db_session) -> AsyncGenerator[AsyncClient, None]:
    # Override dependencies
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_user_id] = override_get_current_user_id
    
    # Create Async HTTP Client
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver"
    ) as ac:
        yield ac
        
    app.dependency_overrides.clear()
