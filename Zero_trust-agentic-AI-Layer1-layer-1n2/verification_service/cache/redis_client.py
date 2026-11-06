"""
cache/redis_client.py
Async Redis connection and cache operations.

Namespaces:
  - nonce:{value}          → { verifierDID, purpose, used: false }
  - statuslist:{url_hash}  → compressed bitstring bytes
  - trustanchor:root       → root trust document JSON
"""

import redis.asyncio as aioredis
import json
import logging
from typing import Optional, Dict, Any

import config

logger = logging.getLogger(__name__)

# Global Redis connection pool
_redis_pool: Optional[aioredis.Redis] = None


async def init_redis() -> None:
    """Initialize Redis connection pool at startup."""
    global _redis_pool
    _redis_pool = await aioredis.from_url(config.REDIS_URL, decode_responses=True)
    logger.info(f"Redis connected: {config.REDIS_URL}")


async def close_redis() -> None:
    """Close Redis connection pool at shutdown."""
    global _redis_pool
    if _redis_pool:
        await _redis_pool.close()
        logger.info("Redis connection closed")


def get_redis() -> aioredis.Redis:
    """Get the Redis connection pool."""
    if _redis_pool is None:
        raise RuntimeError("Redis not initialized. Call init_redis() at startup.")
    return _redis_pool


# ── Nonce Operations ───────────────────────────────────────────────────────────

async def store_nonce(nonce_value: str, verifier_did: str, purpose: str) -> None:
    """
    Store a nonce in Redis.
    
    Args:
        nonce_value:  The nonce hex string
        verifier_did: DID of the verifier
        purpose:      Purpose of the nonce
    """
    redis = get_redis()
    key = f"nonce:{nonce_value}"
    value = {
        "verifierDID": verifier_did,
        "purpose": purpose,
        "used": False
    }
    await redis.setex(
        key,
        config.NONCE_TTL_SECONDS,
        json.dumps(value)
    )
    logger.debug(f"Nonce stored: {key}")


async def get_nonce(nonce_value: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a nonce from Redis.
    
    Args:
        nonce_value: The nonce hex string
        
    Returns:
        Dict with verifierDID, purpose, used — or None if not found
    """
    redis = get_redis()
    key = f"nonce:{nonce_value}"
    value = await redis.get(key)
    if value:
        return json.loads(value)
    return None


async def delete_nonce(nonce_value: str) -> None:
    """
    Delete a nonce from Redis (atomic, final — not just mark used).
    
    Args:
        nonce_value: The nonce hex string
    """
    redis = get_redis()
    key = f"nonce:{nonce_value}"
    await redis.delete(key)
    logger.debug(f"Nonce deleted: {key}")


# ── Status List Operations ─────────────────────────────────────────────────────

async def cache_status_list(status_list_url: str, bitstring_bytes: bytes) -> None:
    """
    Cache a status list bitstring in Redis.
    
    Args:
        status_list_url:  The URL of the status list
        bitstring_bytes:  The compressed bitstring
    """
    redis = get_redis()
    key = f"statuslist:{_hash_url(status_list_url)}"
    # Store as bytes (Redis will handle encoding)
    await redis.setex(
        key,
        config.STATUS_CACHE_TTL,
        bitstring_bytes
    )
    logger.debug(f"Status list cached: {key} (TTL={config.STATUS_CACHE_TTL}s)")


async def get_status_list(status_list_url: str) -> Optional[bytes]:
    """
    Retrieve a cached status list bitstring.
    
    Args:
        status_list_url: The URL of the status list
        
    Returns:
        Bitstring bytes or None if not cached
    """
    redis = get_redis()
    key = f"statuslist:{_hash_url(status_list_url)}"
    value = await redis.get(key)
    if value:
        # If returned as string, encode back to bytes
        if isinstance(value, str):
            return value.encode()
        return value
    return None


# ── Trust Anchor Operations ────────────────────────────────────────────────────

async def cache_trust_anchor(document: Dict[str, Any]) -> None:
    """
    Cache the root trust anchor document.
    
    Args:
        document: The trust anchor document dict
    """
    redis = get_redis()
    key = "trustanchor:root"
    await redis.setex(
        key,
        config.TRUST_ANCHOR_CACHE_TTL,
        json.dumps(document)
    )
    logger.debug(f"Trust anchor cached (TTL={config.TRUST_ANCHOR_CACHE_TTL}s)")


async def get_trust_anchor() -> Optional[Dict[str, Any]]:
    """
    Retrieve the cached trust anchor document.
    
    Returns:
        Trust anchor document dict or None if not cached
    """
    redis = get_redis()
    key = "trustanchor:root"
    value = await redis.get(key)
    if value:
        return json.loads(value)
    return None


# ── Utilities ──────────────────────────────────────────────────────────────────

def _hash_url(url: str) -> str:
    """
    Hash a URL for use as a cache key.
    Uses SHA256 first 16 chars to keep key short.
    """
    import hashlib
    return hashlib.sha256(url.encode()).hexdigest()[:16]
