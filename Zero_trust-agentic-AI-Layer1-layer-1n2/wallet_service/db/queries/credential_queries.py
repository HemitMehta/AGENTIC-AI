"""
wallet_service/db/queries/credential_queries.py
────────────────────────────────────────────────
SQL queries for wallet_credentials table.
"""

import logging
from sqlalchemy import text
from typing import List, Optional

logger = logging.getLogger(__name__)


async def store_credential(
    session,
    agent_did: str,
    vc_id: str,
    credential_type: List[str],
    issuer_did: str,
    issued_at: str,
    expires_at: Optional[str],
    encrypted_vc: bytes,
    iv: bytes,
    proof_type: str,
    bbs_binding: Optional[dict] = None
):
    """Store an encrypted credential."""
    await session.execute(
        text("""
        INSERT INTO wallet_credentials
        (agent_did, vc_id, credential_type, issuer_did, issued_at, expires_at,
         encrypted_vc, iv, proof_type, bbs_binding, status)
        VALUES (:agent_did, :vc_id, :cred_type, :issuer_did, :issued_at, :expires_at,
                :enc_vc, :iv, :proof_type, :bbs_binding, :status)
        """),
        {
            "agent_did": agent_did,
            "vc_id": vc_id,
            "cred_type": credential_type,
            "issuer_did": issuer_did,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "enc_vc": encrypted_vc,
            "iv": iv,
            "proof_type": proof_type,
            "bbs_binding": bbs_binding,
            "status": "active"
        }
    )
    await session.commit()
    logger.info(f"Credential stored for {agent_did}: {vc_id}")


async def get_credentials_by_type(
    session,
    agent_did: str,
    credential_types: Optional[List[str]] = None,
    issuer_did: Optional[str] = None
):
    """
    Query credentials by type and issuer.

    FIX (combined Layer 1 + Layer 2 integration): this SELECT previously
    stopped at `proof_type, status` (8 columns, indices 0-7). That's fine
    for query_service.py's own metadata listing (it only reads indices
    0-5 and 7), but this same function's result rows are also passed
    straight into presentation_builder.py's build_presentation(), which
    reads `row[7]` as encrypted_vc and `row[8]` as iv to decrypt the VC
    for inclusion in a VP -- columns that were never selected at all, so
    every presentation attempt failed (either an IndexError, or silently
    reading the wrong column, since count changes below shifted nothing
    but the old max valid index was 7 = status).

    Appending `encrypted_vc, iv` as new columns 8 and 9 (rather than
    inserting them earlier) fixes presentation_builder.py's indices
    without disturbing query_service.py's existing 0-7 indices at all.
    """
    query = """
    SELECT id, vc_id, credential_type, issuer_did, issued_at, expires_at, proof_type, status,
           encrypted_vc, iv
    FROM wallet_credentials
    WHERE agent_did = :agent_did
    """
    params = {"agent_did": agent_did}

    if credential_types:
        query += " AND credential_type && :types"
        params["types"] = credential_types

    if issuer_did:
        query += " AND issuer_did = :issuer_did"
        params["issuer_did"] = issuer_did

    result = await session.execute(text(query), params)
    return result.fetchall()


async def get_credential_by_vc_id(session, vc_id: str):
    """Fetch a credential by VC ID."""
    result = await session.execute(
        text("""
        SELECT id, agent_did, vc_id, credential_type, issuer_did, issued_at, expires_at,
               encrypted_vc, iv, proof_type, bbs_binding, status
        FROM wallet_credentials
        WHERE vc_id = :vc_id
        """),
        {"vc_id": vc_id}
    )
    return result.fetchone()