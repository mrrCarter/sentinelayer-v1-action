from typing import AsyncGenerator, Optional
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base
import redis.asyncio as redis

from ..config import get_settings

Base = declarative_base()

_engine = None
_timescale_engine = None
_session_local = None
_timescale_session_local = None
_redis_client: Optional[redis.Redis] = None


async def init_db() -> None:
    global _engine, _timescale_engine, _session_local, _timescale_session_local, _redis_client

    settings = get_settings()

    if _engine is None:
        _engine = create_async_engine(
            settings.database_url,
            pool_pre_ping=True,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_timeout=settings.db_pool_timeout_seconds,
        )
        _session_local = async_sessionmaker(
            _engine, expire_on_commit=False, class_=AsyncSession
        )

    if _timescale_engine is None:
        _timescale_engine = create_async_engine(
            settings.timescale_url,
            pool_pre_ping=True,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_timeout=settings.db_pool_timeout_seconds,
        )
        _timescale_session_local = async_sessionmaker(
            _timescale_engine, expire_on_commit=False, class_=AsyncSession
        )

    if _redis_client is None:
        _redis_client = redis.from_url(settings.redis_url, decode_responses=True)


async def close_db() -> None:
    if _engine is not None:
        await _engine.dispose()
    if _timescale_engine is not None:
        await _timescale_engine.dispose()
    if _redis_client is not None:
        await _redis_client.close()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    if _session_local is None:
        await init_db()

    async with _session_local() as session:
        yield session


async def get_timescale_db() -> AsyncGenerator[AsyncSession, None]:
    if _timescale_session_local is None:
        await init_db()

    async with _timescale_session_local() as session:
        yield session


async def get_redis() -> redis.Redis:
    if _redis_client is None:
        await init_db()
    return _redis_client
