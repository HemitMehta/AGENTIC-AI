"""
clients/trust_anchor_client.py

HTTP client for Trust Anchor Service (Person A).

Calls:
  - GET {TRUST_ANCHOR_URL}/trust-anchor         (fetch root document)
  - POST {TRUST_ANCHOR_URL}/trust-anchor/validate  (validate issuer authorization)
"""

import httpx
import logging
from typing import Optional, Dict, Any

import config

logger = logging.getLogger(__name__)


class VerificationError(Exception):
    """Raised when external service call fails."""
    pass


class TrustAnchorClient:
    """HTTP client for Trust Anchor Service."""

    def __init__(self):
        self.base_url = config.TRUST_ANCHOR_URL
        self.timeout = config.HTTP_CLIENT_TIMEOUT

    async def get_trust_anchor(self) -> Dict[str, Any]:
        """
        Fetch the current root trust anchor document.

        Returns:
            Root trust document with signed issuer authorizations

        Raises:
            VerificationError if call fails
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                url = f"{self.base_url}/trust-anchor"
                response = await client.get(url)
                response.raise_for_status()
                return response.json()
        except Exception as e:
            logger.error(f"Failed to fetch trust anchor: {e}")
            raise VerificationError(f"TRUST_ANCHOR_FETCH_FAILED: {e}")

    async def validate_issuer(
        self,
        issuer_did: str,
        credential_type: str,
        trust_domain: str
    ) -> Dict[str, Any]:
        """
        Validate whether an issuer is authorized to issue a credential type.

        Args:
            issuer_did:       DID of the issuer
            credential_type:  Type of credential (e.g., "RoleVC")
            trust_domain:     Trust domain (e.g., "enterprise")

        Returns:
            { authorised: bool, reason: str, validUntil: str|None, conditions: dict|None }

        Raises:
            VerificationError if call fails
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                url = f"{self.base_url}/trust-anchor/validate"
                payload = {
                    "issuerDID": issuer_did,
                    "credentialType": credential_type,
                    "trustDomain": trust_domain
                }
                response = await client.post(url, json=payload)
                response.raise_for_status()
                return response.json()
        except Exception as e:
            logger.error(f"Issuer validation failed for {issuer_did}: {e}")
            raise VerificationError(f"ISSUER_VALIDATION_FAILED: {e}")


# Global singleton
_trust_anchor_client: Optional[TrustAnchorClient] = None


def get_trust_anchor_client() -> TrustAnchorClient:
    """Get or create the Trust Anchor client."""
    global _trust_anchor_client
    if _trust_anchor_client is None:
        _trust_anchor_client = TrustAnchorClient()
    return _trust_anchor_client
