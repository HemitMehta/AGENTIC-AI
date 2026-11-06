"""
clients/did_registry_client.py

HTTP client for DID Registry (Person A's DID resolution service).

Calls:
  - GET {DID_REGISTRY_URL}/dids/{did}
  - GET {DID_REGISTRY_URL}/dids/{did}?at={iso_timestamp}  (for historical resolution)
"""

import httpx
import logging
from typing import Optional, Dict, Any

import config

logger = logging.getLogger(__name__)


class VerificationError(Exception):
    """Raised when external service call fails."""
    pass


class DIDRegistryClient:
    """HTTP client for DID resolution."""

    def __init__(self):
        self.base_url = config.DID_REGISTRY_URL
        self.timeout = config.HTTP_CLIENT_TIMEOUT

    async def resolve_did(
        self,
        did: str,
        at_iso: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Resolve a DID Document.

        Args:
            did:      DID string to resolve
            at_iso:   Optional ISO timestamp for historical resolution

        Returns:
            { didDocument, version, validFrom, validUntil }

        Raises:
            VerificationError if DID Registry call fails
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                url = f"{self.base_url}/dids/{did}"
                params = {}
                if at_iso:
                    params["at"] = at_iso

                response = await client.get(url, params=params)
                response.raise_for_status()
                body = response.json()
                # FIX (combined Layer 1 + Layer 2 integration): the real
                # did_registry response envelope is
                #   { "status": "success", "did": ..., "data": {"didDocument": ..., ...} }
                # (see did_registry_service.py's GET /dids/{did_id} handler
                # and did.py's resolve_did_at_time() / _resolve_did_key(),
                # which both build the {didDocument, ...} dict that ends up
                # under "data"). This method's own docstring already
                # promises callers a flat {didDocument, version, ...} dict
                # -- and vc_sig_verifier.py / vp_sig_verifier.py (3 call
                # sites total) all correctly rely on exactly that -- but it
                # was returning the raw, still-wrapped envelope, so every
                # `did_result["didDocument"]` lookup raised KeyError:
                # 'didDocument'. Unwrap "data" here so the documented
                # contract is what actually comes back.
                return body.get("data", body)
        except Exception as e:
            logger.error(f"DID resolution failed for {did}: {e}")
            raise VerificationError(f"DID_RESOLUTION_FAILED: {e}")


# Global singleton
_did_client: Optional[DIDRegistryClient] = None


def get_did_registry_client() -> DIDRegistryClient:
    """Get or create the DID Registry client."""
    global _did_client
    if _did_client is None:
        _did_client = DIDRegistryClient()
    return _did_client