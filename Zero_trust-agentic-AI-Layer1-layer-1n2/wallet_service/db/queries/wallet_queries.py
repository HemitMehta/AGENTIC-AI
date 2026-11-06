"""
wallet_service/db/queries/wallet_queries.py
────────────────────────────────────────────
SQL queries for wallets table.
"""

import logging
from sqlalchemy import text

logger = logging.getLogger(__name__)


async def get_wallet(session, agent_did: str):
    """Fetch wallet by agent DID."""
    result = await session.execute(
        text("""
        SELECT agent_did, kms_key_id, created_at, deleted_at, deletion_reason
        FROM wallets
        WHERE agent_did = :did AND deleted_at IS NULL
        """),
        {"did": agent_did}
    )
    return result.fetchone()


async def create_wallet(session, agent_did: str, kms_key_id: str):
    """Create a new wallet."""
    await session.execute(
        text("""
        INSERT INTO wallets (agent_did, kms_key_id)
        VALUES (:did, :key_id)
        ON CONFLICT (agent_did) DO NOTHING
        """),
        {"did": agent_did, "key_id": kms_key_id}
    )
    await session.commit()
    logger.info(f"Wallet created for {agent_did}")


async def soft_delete_wallet(session, agent_did: str, reason: str):
    """Soft-delete a wallet."""
    await session.execute(
        text("""
        UPDATE wallets
        SET deleted_at = NOW(), deletion_reason = :reason
        WHERE agent_did = :did
        """),
        {"did": agent_did, "reason": reason}
    )
    await session.commit()
    logger.info(f"Wallet soft-deleted: {agent_did}")
