"""
status_list_service/db/queries/revocation_queries.py
───────────────────────────────────────────────────
Database queries for revocation operations.
"""

from sqlalchemy import text, insert
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime
import json
import uuid


async def get_entry_by_vc_id(session: AsyncSession, vc_id: str) -> dict:
    """Get status list entry by VC ID."""
    result = await session.execute(
        text("""
            SELECT vc_id, issuer_did, status_list_id, bit_index, status_list_url, allocated_at, revoked_at
            FROM status_list_entries
            WHERE vc_id = :vc_id
        """).bindparams(vc_id=vc_id)
    )
    row = result.fetchone()
    if not row:
        return None
    return {
        "vc_id": row[0],
        "issuer_did": row[1],
        "status_list_id": str(row[2]),
        "bit_index": row[3],
        "status_list_url": row[4],
        "allocated_at": row[5],
        "revoked_at": row[6]
    }


async def mark_entry_revoked(session: AsyncSession, vc_id: str, reason: str) -> bool:
    """Mark a status list entry as revoked."""
    result = await session.execute(
        text("""
            UPDATE status_list_entries
            SET revoked_at = NOW(), revocation_reason = :reason
            WHERE vc_id = :vc_id
        """).bindparams(vc_id=vc_id, reason=reason)
    )
    await session.commit()
    return result.rowcount > 0


async def get_entries_for_agent(session: AsyncSession, agent_did: str) -> list:
    """Get all unrevoked VCs for an agent."""
    result = await session.execute(
        text("""
            SELECT vc_id, issuer_did, status_list_id, bit_index, status_list_url
            FROM status_list_entries
            WHERE issuer_did = :agent_did AND revoked_at IS NULL
        """).bindparams(agent_did=agent_did)
    )
    rows = result.fetchall()
    return [
        {
            "vc_id": row[0],
            "issuer_did": row[1],
            "status_list_id": str(row[2]),
            "bit_index": row[3],
            "status_list_url": row[4]
        }
        for row in rows
    ]


async def log_revocation(session: AsyncSession, vc_id: str, agent_did: str, authority_did: str,
                         reason: str, bit_index: int, status_list_id: str, kafka_event_id: str,
                         cascade_steps: dict = None) -> str:
    """
    Log a revocation event.

    FIX (combined Layer 1 + Layer 2 integration): same bug as
    status_list_queries.py::create_status_list -- raw SQL was wrapped in
    `insert(text(...))`, which sqlalchemy.insert() doesn't accept (it
    wants a Table/mapped class, not a TextClause). Removed the erroneous
    wrapper; every other query in this file already calls
    `session.execute(text(...).bindparams(...))` directly.
    """
    log_id = str(uuid.uuid4())
    await session.execute(
        text("""
            INSERT INTO revocation_log
            (id, vc_id, agent_did, authority_did, reason, bit_index, status_list_id, kafka_event_id, cascade_steps)
            VALUES (CAST(:id AS UUID), :vc_id, :agent_did, :authority_did, :reason, :bit_index,
                    CAST(:status_list_id AS UUID), :kafka_event_id, CAST(:cascade_steps AS JSONB))
        """).bindparams(
            id=log_id,
            vc_id=vc_id,
            agent_did=agent_did,
            authority_did=authority_did,
            reason=reason,
            bit_index=bit_index,
            status_list_id=status_list_id,
            kafka_event_id=kafka_event_id,
            cascade_steps=json.dumps(cascade_steps) if cascade_steps else None
        )
    )
    await session.commit()
    return log_id
