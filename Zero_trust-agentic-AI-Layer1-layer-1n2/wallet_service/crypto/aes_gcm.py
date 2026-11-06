"""
wallet_service/crypto/aes_gcm.py

AES-256-GCM encryption/decryption.
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging

logger = logging.getLogger(__name__)


def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypt plaintext using AES-256-GCM.

    Args:
        plaintext: Data to encrypt
        key: 32-byte AES-256 key
        iv: 12-byte nonce

    Returns:
        ciphertext (without IV)
    """
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(iv, plaintext, None)
    return ciphertext


def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-256-GCM.

    Args:
        ciphertext: Data to decrypt
        key: 32-byte AES-256 key
        iv: 12-byte nonce

    Returns:
        plaintext
    """
    cipher = AESGCM(key)
    plaintext = cipher.decrypt(iv, ciphertext, None)
    return plaintext
