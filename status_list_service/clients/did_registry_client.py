"""
status_list_service/clients/did_registry_client.py
HTTP client for DID Registry on Person A.
"""

import httpx
import logging
from config import DID_REGISTRY_URL, HTTP_CLIENT_TIMEOUT
logger = logging.getLogger(__name__)
_client = None

def get_did_registry_client() -> httpx.AsyncClient:
    """Get or create DID Registry HTTP client."""
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            base_url=DID_REGISTRY_URL,
            timeout=HTTP_CLIENT_TIMEOUT
        )
    return _client

async def close_did_registry_client():
    """Close DID Registry client."""
    global _client
    if _client:
        await _client.aclose()
        _client = None

async def resolve_did(did: str) -> dict:
    """
    Resolve a DID to get its document.
    GET {DID_REGISTRY_URL}/dids/{did}
    Response: { "didDocument": {...}, "version": 1, "validFrom": "...", "validUntil": "..." }
    """
    client = get_did_registry_client()

    try:
        response = await client.get(f"/dids/{did}")
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError as e:
        logger.error(f"DID resolution failed for {did}: {e}")
        raise


async def update_did(did: str, updates: dict, authority_signature: str) -> dict:
    """
    Update a DID document (e.g., set lifecycleStatus to 'revoked').
    PUT {DID_REGISTRY_URL}/dids/{did}
    Request: { "updates": {...}, "authoritySignature": "..." }
    Response: { "updated": true, "version": 2, "updatedAt": "..." }
    """
    client = get_did_registry_client()

    try:
        response = await client.put(
            f"/dids/{did}",
            json={
                "updates": updates,
                "authoritySignature": authority_signature
            }
        )
        response.raise_for_status()
        return response.json()
    except httpx.HTTPError as e:
        logger.error(f"DID update failed for {did}: {e}")
        raise
