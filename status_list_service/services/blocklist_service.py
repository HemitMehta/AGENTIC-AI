"""
status_list_service/services/blocklist_service.py

Manage the ephemeral blocklist for did:key DIDs.
"""

import logging
from datetime import datetime, timezone

from cache import redis_client

logger = logging.getLogger(__name__)


async def add_to_blocklist(did: str, reason: str = None, expires_at: str = None) -> dict:
    """
    Add a did:key to the blocklist.

    Validates DID format, stores in Redis, publishes to pub/sub.
    """

    if not did.startswith("did:key:"):
        raise ValueError(f"Blocklist only supports did:key DIDs: {did}")

    added_at = datetime.now(timezone.utc).isoformat()

    # Add to Redis
    await redis_client.add_to_blocklist(did, reason, expires_at)

    # Publish to pub/sub
    await redis_client.publish_blocklist_update(
        action="add",
        did=did,
        reason=reason,
        added_at=added_at
    )

    logger.info(f"Added {did} to blocklist")

    return {"added_at": added_at}


async def check_blocklist(did: str) -> dict:
    """
    Check if a DID is blocklisted.

    Returns: { blocklisted: bool, addedAt?, reason? }
    """

    is_blocked = await redis_client.is_blocklisted(did)

    if not is_blocked:
        return {"blocklisted": False}

    # Get metadata
    metadata = await redis_client.get_blocklist_reason(did)

    return {
        "blocklisted": True,
        "added_at": metadata.get("addedAt") if metadata else None,
        "reason": metadata.get("reason") if metadata else None
    }


async def remove_from_blocklist(did: str) -> dict:
    """Remove a DID from the blocklist."""

    await redis_client.remove_from_blocklist(did)

    # Publish to pub/sub
    await redis_client.publish_blocklist_update(action="remove", did=did)

    logger.info(f"Removed {did} from blocklist")

    return {"removed": True}
