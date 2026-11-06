"""
services/nonce_service.py

Nonce generation and management.
"""

import secrets
import logging
from datetime import datetime, timezone, timedelta

from cache import redis_client

logger = logging.getLogger(__name__)


async def generate_nonce(verifier_did: str, purpose: str) -> tuple[str, str]:
    """
    Generate a cryptographically random nonce and store it in Redis.

    Args:
        verifier_did: DID of the verifier requesting the nonce
        purpose:      Purpose of the nonce

    Returns:
        (nonce_hex, expires_at_iso)
    """
    # Generate 32 bytes of randomness, hex-encoded
    nonce_bytes = secrets.token_bytes(32)
    nonce_hex = nonce_bytes.hex()

    # Store in Redis
    await redis_client.store_nonce(nonce_hex, verifier_did, purpose)

    # Calculate expiration time
    import config
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=config.NONCE_TTL_SECONDS)
    expires_at_iso = expires_at.isoformat()

    logger.info(f"Nonce generated for {verifier_did} (purpose: {purpose})")

    return nonce_hex, expires_at_iso
