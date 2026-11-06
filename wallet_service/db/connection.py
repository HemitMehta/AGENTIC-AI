"""
wallet_service/db/connection.py
───────────────────────────────
Async database connection pool and migration runner.


"""

import asyncpg
import logging
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from config import DATABASE_URL, ENVIRONMENT

logger = logging.getLogger(__name__)

_engine = None
_session_factory = None


async def init_db():
    """Initialize database pool."""
    global _engine, _session_factory

    _engine = create_async_engine(
        DATABASE_URL,
        echo=(ENVIRONMENT == "development"),
        pool_size=10,
        max_overflow=20,
    )

    
   
    _session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    logger.info("Database pool initialized")


async def close_db():
    """Close database pool."""
    global _engine

    if _engine:
        await _engine.dispose()
        logger.info("Database pool closed")


async def get_session():
    """
    Return an async session context manager.

    FIX (combined Layer 1 + Layer 2 integration): every caller in this
    service (services/wallet_service.py, query_service.py, store_service.py,
    selective_disclosure.py, presentation_builder.py) does
    `session = await get_session()`. This function was previously a plain
    `def`, so it returned the AsyncSession object synchronously -- and
    `await`-ing a plain AsyncSession instance (not a coroutine) raised
    "object AsyncSession can't be used in 'await' expression" on every
    single wallet operation, including POST /wallets/{did}/init. Making
    this function itself `async def` (it doesn't need to actually await
    anything internally -- `_session_factory()` returns the session
    object immediately either way) makes it a real coroutine, so every
    existing `await get_session()` call site now works unmodified.
    """
    if not _session_factory:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _session_factory()


async def run_migration():
    """Run SQL migrations."""
    logger.info("Running database migrations...")

    with open("db/migrations/001_create_tables.sql", "r") as f:
        migration_sql = f.read()

    # Execute via raw asyncpg connection (bypasses ORM for DDL)
    conn = await asyncpg.connect(DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://"))
    try:
        statements = [stmt.strip() for stmt in migration_sql.split(";") if stmt.strip()]
        for statement in statements:
            await conn.execute(statement)
        logger.info("Migration completed")
    finally:
        await conn.close()