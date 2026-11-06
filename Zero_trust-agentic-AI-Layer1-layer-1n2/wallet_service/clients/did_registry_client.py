"""
wallet_service/clients/did_registry_client.py

HTTP client for DID Registry (Person A).
"""

import httpx
import logging
from config import DID_REGISTRY_URL, HTTP_CLIENT_TIMEOUT

logger = logging.getLogger(__name__)

_did_client = None


async def init_did_client():
    """Initialize DID Registry HTTP client."""
    global _did_client
    _did_client = httpx.AsyncClient(base_url=DID_REGISTRY_URL, timeout=HTTP_CLIENT_TIMEOUT)
    logger.info(f"DID Registry client initialized: {DID_REGISTRY_URL}")


async def close_did_client():
    """Close DID Registry HTTP client."""
    global _did_client
    if _did_client:
        await _did_client.aclose()
        logger.info("DID Registry client closed")


async def get_did_client():
    """Get DID Registry HTTP client."""
    if not _did_client:
        await init_did_client()
    return _did_client


async def resolve_did(did: str) -> dict:
    """
    Resolve a DID to its document.

    Returns: { didDocument, version, validFrom, validUntil, lifecycleStatus }
    """
    client = await get_did_client()
    response = await client.get(f"/dids/{did}")
    response.raise_for_status()
    body = response.json()
    return body.get("data", body)


async def get_did_controllers(did: str) -> list:
    """Get the list of controller DIDs for a DID."""
    did_data = await resolve_did(did)
    did_document = did_data.get("didDocument", did_data)
    return did_document.get("controllerDIDs", did_document.get("controller", []))
