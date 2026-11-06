"""
wallet_service/clients/kms_client.py

HTTP client for KMS (Person A).

--------------------------------------------------------------------------
FIX (audit finding #4):
  - generate_key() sent {"agentDID", "keyPurpose"} (camelCase), but
    kms_service.py's Pydantic model expects {"agent_did", "key_purpose"}
    (snake_case). FastAPI does not auto-alias between the two, so every
    call here would have been rejected with 422 Unprocessable Entity.
    Fixed to send snake_case, matching kms_service.py exactly.

  - sign_payload() called POST /keys/sign with key_id in the JSON body,
    but kms_service.py exposes POST /keys/{key_id}/sign with key_id in
    the path (matching status_list_service's client, which already used
    this shape). Fixed to use the path-based route.

get_public_key() and revoke_key() already matched the real kms_service.py
routes and needed no changes.
--------------------------------------------------------------------------
"""

import httpx
import logging
from config import KMS_URL, HTTP_CLIENT_TIMEOUT

logger = logging.getLogger(__name__)

_kms_client = None


async def init_kms_client():
    """Initialize KMS HTTP client."""
    global _kms_client
    _kms_client = httpx.AsyncClient(base_url=KMS_URL, timeout=HTTP_CLIENT_TIMEOUT)
    logger.info(f"KMS client initialized: {KMS_URL}")


async def close_kms_client():
    """Close KMS HTTP client."""
    global _kms_client
    if _kms_client:
        await _kms_client.aclose()
        logger.info("KMS client closed")


async def get_kms_client():
    """Get KMS HTTP client."""
    if not _kms_client:
        await init_kms_client()
    return _kms_client


async def generate_key(agent_did: str, key_purpose: str = "wallet-encryption") -> dict:
    """
    Generate a new key in Vault.

    Returns: { keyId, publicKey, algorithm }
    """
    client = await get_kms_client()
    response = await client.post("/keys/generate", json={
        "agent_did": agent_did,
        "key_purpose": key_purpose,
    })
    response.raise_for_status()
    return response.json()


async def sign_payload(key_id: str, payload_bytes: bytes) -> str:
    """
    Sign a payload using a KMS key.

    Args:
        key_id: Key ID in Vault
        payload_bytes: Raw bytes to sign

    Returns:
        Base64-encoded signature
    """
    import base64
    client = await get_kms_client()
    response = await client.post(f"/keys/{key_id}/sign", json={
        "payload": base64.b64encode(payload_bytes).decode()
    })
    response.raise_for_status()
    return response.json()["signature"]


async def get_public_key(key_id: str) -> str:
    """
    Fetch public key material from Vault.

    Returns:
        Public key bytes as base64 string
    """
    client = await get_kms_client()
    response = await client.get(f"/keys/{key_id}/public")
    response.raise_for_status()
    return response.json()["publicKey"]


async def revoke_key(key_id: str):
    """Revoke a key in Vault."""
    client = await get_kms_client()
    response = await client.post(f"/keys/{key_id}/revoke")
    response.raise_for_status()
    logger.info(f"Key revoked in Vault: {key_id}")
