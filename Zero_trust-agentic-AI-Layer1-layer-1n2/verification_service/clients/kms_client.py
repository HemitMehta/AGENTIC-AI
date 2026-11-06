"""
clients/kms_client.py

HTTP client for KMS (Person A's Key Management Service).

Calls: GET {KMS_URL}/keys/{keyId}/public
"""

import httpx
import logging
from typing import Optional, Dict, Any

import config

logger = logging.getLogger(__name__)


class VerificationError(Exception):
    """Raised when external service call fails."""
    pass


class KMSClient:
    """HTTP client for KMS public key retrieval."""

    def __init__(self):
        self.base_url = config.KMS_URL
        self.timeout = config.HTTP_CLIENT_TIMEOUT

    async def get_public_key(self, key_id: str) -> Dict[str, Any]:
        """
        Retrieve public key from KMS.

        Args:
            key_id: Key identifier

        Returns:
            { publicKey, algorithm, status }

        Raises:
            VerificationError if KMS call fails
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                url = f"{self.base_url}/keys/{key_id}/public"
                response = await client.get(url)
                response.raise_for_status()
                return response.json()
        except Exception as e:
            logger.error(f"KMS public key retrieval failed: {e}")
            raise VerificationError(f"KMS_UNAVAILABLE: {e}")


# Global singleton
_kms_client: Optional[KMSClient] = None


def get_kms_client() -> KMSClient:
    """Get or create the KMS client."""
    global _kms_client
    if _kms_client is None:
        _kms_client = KMSClient()
    return _kms_client
