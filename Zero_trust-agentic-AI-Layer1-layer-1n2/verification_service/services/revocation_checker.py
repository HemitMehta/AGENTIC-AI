"""
services/revocation_checker.py

Step 5 of verification pipeline: Revocation status check.

Fetches status list bitstrings, checks if credentials are revoked.
Caches status lists in Redis with configurable TTL.
"""

import logging
import base64
import gzip
import json
import httpx
from typing import Dict, Any, List
from urllib.parse import urlsplit
from uuid import UUID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from clients.kms_client import get_kms_client

from cache import redis_client
import config

logger = logging.getLogger(__name__)


async def check_revocation_status(vcs: List[Dict[str, Any]], fresh: bool = False) -> None:
    """
    Check revocation status for all VCs.

    Args:
        vcs: List of VC dictionaries

    Raises:
        ValueError if any VC is revoked
    """
    for vc in vcs:
        await _check_single_revocation_status(vc, fresh=fresh)


async def _check_single_revocation_status(vc: Dict[str, Any], fresh: bool = False) -> None:
    """
    Check revocation status for a single VC.

    Args:
        vc: VC dictionary

    Raises:
        ValueError if VC is revoked
    """
    vc_id = vc.get("id", "unknown")
    credential_status = vc.get("credentialStatus")
    if not credential_status:
        logger.warning(f"VC {vc_id} has no credentialStatus block")
        return

    # Extract status list URL and bit index
    status_list_url = credential_status.get("statusListCredential")
    bit_index = credential_status.get("statusListIndex")

    if not status_list_url or bit_index is None:
        raise ValueError(f"VC {vc_id} credentialStatus missing URL or index")

    try:
        bit_index = int(bit_index)
    except (ValueError, TypeError):
        raise ValueError(f"VC {vc_id} credentialStatus has invalid statusListIndex")

    # Fetch or retrieve cached status list
    bitstring = await _get_status_list_bitstring(status_list_url, fresh=fresh)

    # Check if the bit is set (revoked)
    byte_index = bit_index // 8
    bit_offset = 7 - (bit_index % 8)

    if bit_index < 0 or byte_index >= len(bitstring):
        raise ValueError(
            f"VC {vc_id} statusListIndex {bit_index} out of range for status list"
        )

    # Extract bit: 1 = revoked, 0 = not revoked
    bit_value = (bitstring[byte_index] >> bit_offset) & 1

    if bit_value == 1:
        raise ValueError(f"Credential {vc_id} has been revoked")

    logger.info(f"VC {vc_id} revocation status OK (bit {bit_index} = 0)")


async def _get_status_list_bitstring(status_list_url: str, fresh: bool = False) -> bytes:
    """
    Fetch or retrieve cached status list bitstring.

    Args:
        status_list_url: URL of the status list

    Returns:
        Raw bitstring bytes (after GZIP decompression)

    Raises:
        ValueError if fetch or decode fails
    """
    if fresh:
        # Layer 3 only accepts our configured status authority, not arbitrary credential URLs.
        base = config.STATUS_LIST_BASE_URL.rstrip("/") + "/status-lists/"
        if not status_list_url.startswith(base) or urlsplit(status_list_url).query or urlsplit(status_list_url).fragment:
            raise ValueError("Untrusted status list authority")
        UUID(status_list_url[len(base):])
    # Check Redis cache first
    cached = None if fresh else await redis_client.get_status_list(status_list_url)
    if cached:
        logger.debug(f"Status list served from cache: {status_list_url}")
        return cached

    # Fetch from the URL
    try:
        async with httpx.AsyncClient(timeout=config.HTTP_CLIENT_TIMEOUT) as client:
            response = await client.get(status_list_url, params={"fresh": "true"} if fresh else None)
            response.raise_for_status()

            # Expecting a VC with a `credentialSubject.encodedList` field
            data = response.json()
            if fresh:
                await _verify_status_signature(data, status_list_url)
            credential_subject = data.get("credentialSubject", {})
            encoded_list_b64url = credential_subject.get("encodedList")

            if not encoded_list_b64url:
                raise ValueError("Status list VC has no credentialSubject.encodedList")

            # Decode base64url
            padding = 4 - len(encoded_list_b64url) % 4
            if padding != 4:
                encoded_list_b64url += "=" * padding

            compressed_bitstring = base64.urlsafe_b64decode(encoded_list_b64url)

            # GZIP decompress
            bitstring = gzip.decompress(compressed_bitstring)

            # Cache in Redis
            await redis_client.cache_status_list(status_list_url, bitstring)

            logger.info(f"Status list fetched and cached: {status_list_url}")
            return bitstring

    except Exception as e:
        logger.error(f"Failed to fetch/decode status list from {status_list_url}: {e}")
        raise ValueError(f"Status list fetch failed: {e}")


async def _verify_status_signature(data: dict, expected_url: str):
    if data.get("id") != expected_url or data.get("credentialSubject", {}).get("statusPurpose") != "revocation":
        raise ValueError("Status list identity or purpose mismatch")
    proof = data.get("proof", {})
    key_data = await get_kms_client().get_public_key(config.KMS_STATUS_LIST_KEY_ID)
    if key_data.get("keyStatus") != "active":
        raise ValueError("Status list signing key is not active")
    encoded = key_data["publicKey"]
    key = (serialization.load_pem_public_key(encoded.encode()) if encoded.startswith("-----BEGIN")
           else Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded)))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Unexpected status list key algorithm")
    unsigned = {k: v for k, v in data.items() if k != "proof"}
    key.verify(base64.b64decode(proof["proofValue"], validate=True),
               json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode())
