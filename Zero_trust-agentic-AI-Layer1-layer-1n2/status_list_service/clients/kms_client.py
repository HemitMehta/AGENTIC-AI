"""
status_list_service/clients/kms_client.py
────────────────────────────────────────
HTTP client for KMS (Key Management Service) on Person A.

--------------------------------------------------------------------------
FIX: sign_payload() encoded the payload with base64.urlsafe_b64encode(),
but kms_service.py decodes incoming payloads with the standard
base64.b64decode() (standard alphabet: +/, not urlsafe's -_). For any
payload whose encoded form happens to contain '+' or '/', urlsafe
encoding would emit '-'/'_' instead -- characters the standard decoder
either rejects or silently mishandles, corrupting the signed payload.

Fixed to use standard base64.b64encode(), matching kms_service.py's
decode side exactly. Routes were already correct and needed no changes.
--------------------------------------------------------------------------
"""

import httpx
import logging

from config import KMS_URL, HTTP_CLIENT_TIMEOUT

logger = logging.getLogger(__name__)

_client = None


def get_kms_client() -> httpx.AsyncClient:
    """Get or create KMS HTTP client."""
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            base_url=KMS_URL,
            timeout=HTTP_CLIENT_TIMEOUT
        )
    return _client


async def close_kms_client():
    """Close KMS client."""
    global _client
    if _client:
        await _client.aclose()
        _client = None


async def sign_payload(key_id: str, payload: bytes) -> str:
    """
    Sign a payload using KMS.

    POST {KMS_URL}/keys/{keyId}/sign
    Request: { "payload": base64_payload }
    Response: { "signature": base64_signature, "algorithm": "Ed25519", "status": "success" }
    """
    client = get_kms_client()

    import base64
    payload_b64 = base64.b64encode(payload).decode()

    try:
        response = await client.post(
            f"/keys/{key_id}/sign",
            json={"payload": payload_b64}
        )
        response.raise_for_status()
        result = response.json()
        return result["signature"]
    except httpx.HTTPError as e:
        logger.error(f"KMS sign failed: {e}")
        raise


async def get_public_key(key_id: str) -> dict:
    """
    Get public key from KMS.

    GET {KMS_URL}/keys/{keyId}/public
    Response: { "publicKey": multibase_key, "algorithm": "Ed25519", "status": "active" }
    """
    client = get_kms_client()

    try:
        response = await client.get(f"/keys/{key_id}/public")
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError as e:
        logger.error(f"KMS get_public_key failed: {e}")
        raise
