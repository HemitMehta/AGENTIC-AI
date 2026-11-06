"""
status_list_service/db/connection.py
────────────────────────────────────
Async database connection pool using asyncpg.
"""

import asyncpg
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
import logging

from config import DATABASE_URL

logger = logging.getLogger(__name__)

# Singleton pool
_pool = None
_engine = None
_session_maker = None


async def init_db():
    """Initialize database connection pool and engine."""
    global _pool, _engine, _session_maker

    _engine = create_async_engine(
        DATABASE_URL,
        echo=False,
        pool_size=20,
        max_overflow=10,
        pool_recycle=3600
    )

    _session_maker = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False
    )

    logger.info("Database connection pool initialized")


async def close_db():
    """Close database connection pool."""
    global _engine

    if _engine:
        await _engine.dispose()
        logger.info("Database connection pool closed")


def get_session():
    """Get a database session."""
    if _session_maker is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _session_maker()


async def execute_query(query: str, *args):
    """Execute a raw SQL query."""
    async with get_session() as session:
        result = await session.execute(query, args)
        return result


async def run_migration():
    from sqlalchemy import text

    async with get_session() as session:
        with open("db/migrations/001_create_tables.sql", "r") as f:
            migration_sql = f.read()

        statements = [
            s.strip()
            for s in migration_sql.split(";")
            if s.strip()
        ]

        for statement in statements:
            try:
                print("\n==============================")
                print(statement)
                print("==============================\n")
                await session.execute(text(statement))
            except Exception:
                print("\nFAILED STATEMENT:")
                print(statement)
                raise

        await session.commit()