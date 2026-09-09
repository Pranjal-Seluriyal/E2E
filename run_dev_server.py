import asyncio
import os
import uvicorn
from sqlalchemy.ext.asyncio import create_async_engine

# Set SQLite fallback if no custom DB URL is provided
if "DATABASE_URL" not in os.environ:
    os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///dev_app.db"

from app.database import engine
from app.models.base import Base
from app.main import app

async def init_tables():
    print("Initializing database tables...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Database tables initialized successfully!")

if __name__ == "__main__":
    asyncio.run(init_tables())
    print("Starting E2E Backend Server at http://0.0.0.0:8000...")
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=False)
