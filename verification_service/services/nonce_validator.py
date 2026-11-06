"""
services/nonce_validator.py

Step 2 of verification pipeline: Nonce validation.

Validates nonce has not been replayed, checking:
- Nonce exists
- Nonce has not expired
- Nonce has not been used
- Nonce verifierDID matches
"""

import logging
from typing import Dict, Any

from cache import redis_client

logger = logging.getLogger(__name__)


async def validate_nonce(
    nonce_value: str,
    verifier_did: str,
    vp_payload: Dict[str, Any]
) -> None:
    """
    Validate the nonce.

    Args:
        nonce_value:   The nonce hex string (from request)
        verifier_did:  The verifier DID (from request)
        vp_payload:    The decoded VP JWT payload

    Raises:
        ValueError if nonce validation fails
    """
    # Extract challenge from VP proof
    proof = vp_payload.get("proof", {})
    if isinstance(proof, list):
        proof = proof[0] if proof else {}
    
    challenge = proof.get("challenge")
    if not challenge:
        raise ValueError("VP proof has no challenge claim")

    # Verify challenge matches the provided nonce
    if challenge != nonce_value:
        raise ValueError("Nonce mismatch: challenge does not match provided nonce")

    # Look up nonce in Redis
    nonce_data = await redis_client.get_nonce(nonce_value)
    if not nonce_data:
        raise ValueError("Replay attack or stale presentation: nonce not found or expired")

    # Check verifier DID matches
    if nonce_data["verifierDID"] != verifier_did:
        raise ValueError("Replay attack: nonce issued for different verifier")

    # Check if already used
    if nonce_data.get("used"):
        raise ValueError("Replay attack: nonce already used")

    # Delete nonce from Redis (atomic, final — not just mark used)
    await redis_client.delete_nonce(nonce_value)

    logger.info(f"Nonce validated and deleted: {nonce_value}")
