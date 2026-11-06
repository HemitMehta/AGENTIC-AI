"""
status_list_service/db/queries/status_list_queries.py
──────────────────────────────────────────────────────
Database queries for status_list table operations.
"""

from sqlalchemy import text, select, update, insert
from sqlalchemy.ext.asyncio import AsyncSession
import uuid


async def create_status_list(session: AsyncSession, issuer_did: str, bitstring: bytes) -> dict:
    """
    Create a new status list.

    FIX (combined Layer 1 + Layer 2 integration): this wrapped raw SQL in
    `insert(text(...))` -- but sqlalchemy.insert() expects a Table or
    mapped class, not a TextClause, and raises at runtime when given one.
    Every other query in this same file (get_status_list,
    get_active_status_list_for_issuer, claim_status_list_index,
    update_bitstring) correctly calls `session.execute(text(...)
    .bindparams(...))` directly with no insert() wrapper -- this was the
    one outlier, and since POST /status-lists/allocate calls this
    function on every brand-new issuer's first VC, it's also why nothing
    ever caught this until a real client (vc_issuance, via the newly
    fixed status_list.py) first actually exercised this codepath.
    """
    result = await session.execute(
        text("""
            INSERT INTO status_lists (id, issuer_did, bitstring, total_bits, next_free_index)
            VALUES (gen_random_uuid(), :issuer_did, :bitstring, 131072, 0)
            RETURNING id
        """).bindparams(issuer_did=issuer_did, bitstring=bitstring)
    )
    row = result.fetchone()
    await session.commit()
    return {"id": str(row[0])}


async def get_status_list(session: AsyncSession, status_list_id: str) -> dict:
    """Fetch status list by ID."""
    result = await session.execute(
        text("""
            SELECT id, issuer_did, bitstring, total_bits, next_free_index, updated_at
            FROM status_lists
            WHERE id = CAST(:id AS UUID)
        """).bindparams(id=status_list_id)
    )
    row = result.fetchone()
    if not row:
        return None
    return {
        "id": str(row[0]),
        "issuer_did": row[1],
        "bitstring": row[2],
        "total_bits": row[3],
        "next_free_index": row[4],
        "updated_at": row[5]
    }


async def get_active_status_list_for_issuer(session: AsyncSession, issuer_did: str) -> dict:
    """Get the active status list for an issuer (with space available)."""
    result = await session.execute(
        text("""
            SELECT id, issuer_did, bitstring, total_bits, next_free_index
            FROM status_lists
            WHERE issuer_did = :issuer_did AND next_free_index < total_bits
            ORDER BY created_at DESC
            LIMIT 1
        """).bindparams(issuer_did=issuer_did)
    )
    row = result.fetchone()
    if not row:
        return None
    return {
        "id": str(row[0]),
        "issuer_did": row[1],
        "bitstring": row[2],
        "total_bits": row[3],
        "next_free_index": row[4]
    }


async def claim_status_list_index(session: AsyncSession, status_list_id: str, bit_index: int) -> bool:
    """Atomically claim an index in a status list (increment next_free_index)."""
    result = await session.execute(
        text("""
            UPDATE status_lists
            SET next_free_index = next_free_index + 1, updated_at = NOW()
            WHERE id = CAST(:id AS UUID) AND next_free_index = :expected_index
            RETURNING next_free_index
        """).bindparams(id=status_list_id, expected_index=bit_index)
    )
    row = result.fetchone()
    await session.commit()
    return row is not None


async def update_bitstring(session: AsyncSession, status_list_id: str, bitstring: bytes) -> bool:
    """Update the bitstring for a status list."""
    result = await session.execute(
        text("""
            UPDATE status_lists
            SET bitstring = :bitstring, updated_at = NOW()
            WHERE id = CAST(:id AS UUID)
        """).bindparams(bitstring=bitstring, id=status_list_id)
    )
    await session.commit()
    return result.rowcount > 0