"""
wallet_service/services/query_service.py

Query credentials by type, issuer, and status.

--------------------------------------------------------------------------
FIX (combined Layer 1 + Layer 2 integration): this called
datetime.fromisoformat(expires_at) assuming row[5] came back from the DB
as an ISO string. Once store_service.py's DataError bug is fixed (it now
stores real datetime objects instead of raw strings -- asyncpg requires
this), asyncpg/SQLAlchemy return row[5] as an actual datetime.datetime
object on SELECT, not a string, so fromisoformat() would crash with
"argument must be str". Compare the datetime object directly instead, and
convert to an ISO string only at the point of building the response dict
(matching how issued_at / row[4] was already, correctly, handled below).
--------------------------------------------------------------------------
"""

import logging
from datetime import datetime, timezone
from typing import Optional, List
from db.connection import get_session
from db.queries.credential_queries import get_credentials_by_type

logger = logging.getLogger(__name__)


async def list_credentials(
    agent_did: str,
    credential_types: Optional[List[str]] = None,
    issuer_did: Optional[str] = None
) -> List[dict]:
    """
    Query credentials without decryption.

    Returns metadata only: vcId, type[], issuer, issuedAt, expiresAt, status
    """
    session = await get_session()

    try:
        rows = await get_credentials_by_type(session, agent_did, credential_types, issuer_did)

        result = []
        for row in rows:
            issued_at_dt = row[4]
            expires_at_dt = row[5]
            status = row[7]  # existing status from DB

            if expires_at_dt and expires_at_dt < datetime.now(timezone.utc):
                status = "expired"

            result.append({
                "vcId": row[1],
                "type": list(row[2]),
                "issuer": row[3],
                "issuedAt": issued_at_dt.isoformat() if issued_at_dt else None,
                "expiresAt": expires_at_dt.isoformat() if expires_at_dt else None,
                "status": status
            })

        logger.info(f"Listed {len(result)} credentials for {agent_did}")
        return result

    finally:
        await session.close()