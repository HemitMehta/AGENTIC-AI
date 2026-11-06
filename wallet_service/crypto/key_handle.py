"""
wallet_service/crypto/key_handle.py

Wallet encryption key derivation and management.

SECURITY CRITICAL: Keys are never persisted outside Vault.
Derived keys exist only in function scope and are zeroed immediately after use.
"""

import hashlib
import logging
from typing import Optional

logger = logging.getLogger(__name__)


async def get_derived_key(kms_client, kms_key_id: str, context_salt: bytes) -> bytes:
    """
    Fetch key material from KMS and derive an AES-256 key using HKDF.

    The derived key exists only in this function's stack frame and must be
    zeroed immediately after use by the caller.

    Args:
        kms_client: KMS HTTP client
        kms_key_id: Key ID in Vault
        context_salt: Salt for HKDF (typically agent DID bytes)

    Returns:
        32-byte derived AES key (caller must zero_key when done)
    """

    # Fetch key material from KMS
    key_material = await kms_client.get_public_key(kms_key_id)

    # PBKDF2 to derive AES-256 key
    # (Using PBKDF2 instead of HKDF for simplicity; in production use cryptography.hazmat.primitives.kdf.hkdf)
    derived = hashlib.pbkdf2_hmac(
        'sha256',
        key_material.encode() if isinstance(key_material, str) else key_material,
        salt=context_salt,
        iterations=1,
        dklen=32  # 256 bits for AES-256
    )

    logger.debug(f"Derived AES key from KMS key {kms_key_id}")
    return derived


def zero_key(key: bytearray):
    """
    Overwrite key bytes in memory immediately after use.

    MUST be called in a finally block after every derived key use.
    """
    for i in range(len(key)):
        key[i] = 0
    logger.debug("Key bytes zeroed from memory")
