"""
status_list_service/cache/redis_client.py
─────────────────────────────────────────
Async Redis client for status list caching and blocklist management.

Key namespaces:
- statuslist:{id} — Cached signed status list VC (TTL)
- blocklist — Set of revoked did:key DIDs (no TTL)
- blocklist_meta:{did} — Metadata per blocklisted DID (optional TTL)
"""

import redis.asyncio
import json
import logging
from typing import Optional

from config import REDIS_URL, STATUS_CACHE_TTL

logger = logging.getLogger(__name__)

_redis_pool = None


async def init_redis():
    """Initialize Redis connection pool."""
    global _redis_pool
    _redis_pool = await redis.asyncio.from_url(REDIS_URL, decode_responses=True)
    logger.info("Redis connection pool initialized")


async def close_redis():
    """Close Redis connection pool."""
    global _redis_pool
    if _redis_pool:
        await _redis_pool.close()
        logger.info("Redis connection pool closed")


def get_redis():
    """Get Redis client."""
    if _redis_pool is None:
        raise RuntimeError("Redis not initialized. Call init_redis() first.")
    return _redis_pool


# ─ Status List Caching ─────────────────────────────────────────────────────

async def cache_status_list(status_list_id: str, signed_vc_json: str) -> bool:
    """Cache a signed status list VC."""
    redis = get_redis()
    key = f"statuslist:{status_list_id}"
    await redis.setex(key, STATUS_CACHE_TTL, signed_vc_json)
    return True


async def get_cached_status_list(status_list_id: str) -> Optional[str]:
    """Get cached status list VC."""
    redis = get_redis()
    key = f"statuslist:{status_list_id}"
    return await redis.get(key)


async def invalidate_status_list(status_list_id: str) -> bool:
    """Invalidate cached status list."""
    redis = get_redis()
    key = f"statuslist:{status_list_id}"
    await redis.delete(key)
    return True


async def cache_bitstring(status_list_id: str, bitstring_bytes: bytes) -> bool:
    """Cache compressed bitstring for revocation checking."""
    redis = get_redis()
    key = f"bitstring:{status_list_id}"
    await redis.set(key, bitstring_bytes)
    return True


async def get_cached_bitstring(status_list_id: str) -> Optional[bytes]:
    """Get cached bitstring."""
    redis = get_redis()
    key = f"bitstring:{status_list_id}"
    return await redis.getex(key, ex=STATUS_CACHE_TTL)


async def update_cached_bitstring(status_list_id: str, bitstring_bytes: bytes) -> bool:
    """Update cached bitstring (e.g., after bit flip)."""
    redis = get_redis()
    key = f"bitstring:{status_list_id}"
    await redis.setex(key, STATUS_CACHE_TTL, bitstring_bytes)
    return True


# ─ Blocklist Management ───────────────────────────────────────────────────

async def add_to_blocklist(did: str, reason: str = None, expires_at: str = None) -> bool:
    """Add a DID to the ephemeral blocklist."""
    redis = get_redis()

    # Add to set (no expiry on the set itself)
    await redis.sadd("blocklist", did)

    # Store metadata
    metadata = {
        "reason": reason or "security incident",
        "addedAt": None,  # Will be set by caller
    }
    if expires_at:
        metadata["expiresAt"] = expires_at

    meta_key = f"blocklist_meta:{did}"
    if expires_at:
        # Parse ISO timestamp to get seconds
        from datetime import datetime
        exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        ttl = int((exp_dt.timestamp() - datetime.now().timestamp()))
        if ttl > 0:
            await redis.setex(meta_key, ttl, json.dumps(metadata))
        else:
            await redis.set(meta_key, json.dumps(metadata))
    else:
        await redis.set(meta_key, json.dumps(metadata))

    return True


async def is_blocklisted(did: str) -> bool:
    """Check if a DID is blocklisted."""
    redis = get_redis()
    return await redis.sismember("blocklist", did)


async def get_blocklist_reason(did: str) -> Optional[dict]:
    """Get blocklist metadata for a DID."""
    redis = get_redis()
    meta_key = f"blocklist_meta:{did}"
    data = await redis.get(meta_key)
    if data:
        return json.loads(data)
    return None


async def remove_from_blocklist(did: str) -> bool:
    """Remove a DID from the blocklist."""
    redis = get_redis()
    await redis.srem("blocklist", did)
    meta_key = f"blocklist_meta:{did}"
    await redis.delete(meta_key)
    return True


# ─ Pub/Sub for Blocklist Updates ───────────────────────────────────────────

async def publish_blocklist_update(action: str, did: str, reason: str = None, added_at: str = None):
    """Publish blocklist update to all subscribers."""
    redis = get_redis()
    payload = {
        "action": action,  # "add" or "remove"
        "did": did,
        "reason": reason,
        "addedAt": added_at
    }
    await redis.publish("blocklist.updates", json.dumps(payload))


async def subscribe_to_blocklist_updates(callback):
    """Subscribe to blocklist updates (blocking call)."""
    redis = get_redis()
    pubsub = redis.pubsub()
    await pubsub.subscribe("blocklist.updates")

    async for message in pubsub.listen():
        if message["type"] == "message":
            payload = json.loads(message["data"])
            await callback(payload)
