"""
wallet_service/services/selective_disclosure.py
Enforce strict credential inclusion per verifier request.
"""

import logging
from typing import List
from db.connection import get_session
from db.queries.credential_queries import get_credentials_by_type

logger = logging.getLogger(__name__)


async def get_credentials_for_presentation(
    agent_did: str,
    required_types: List[str],
    credential_ids: List[str] | None = None,
) -> List[dict]:
    """
    Select credentials matching required types.

    STRICT RULE: Only include requested types. Never include extra.
    Reject if any required type has no matching credential.

    Returns: List of row dicts [{ id, agent_did, vc_id, ... encrypted_vc, iv, ... }]
    """
    session = await get_session()

    try:
        rows = await get_credentials_by_type(session, agent_did, required_types)
        if credential_ids is not None:
            wanted = set(credential_ids)
            if len(wanted) != len(credential_ids):
                raise ValueError("Duplicate credential IDs")
            rows = [row for row in rows if row[1] in wanted]
            if {row[1] for row in rows} != wanted:
                raise ValueError("Selected credentials are missing from this wallet or do not match required types")

        if not rows:
            raise ValueError(f"No credentials found matching required types: {required_types}")

        # Verify all required types are present
        found_types = set()
        for row in rows:
            cred_types = row[2]  # credential_type array
            found_types.update(cred_types)

        missing = set(required_types) - found_types
        if missing:
            logger.warning(f"Missing credential types for {agent_did}: {missing}")
            raise ValueError(f"Missing credential types: {missing}")

        logger.info(f"Selected {len(rows)} credentials for presentation")
        return rows

    finally:
        await session.close()
