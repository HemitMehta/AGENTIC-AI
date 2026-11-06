"""
tests/test_nonce.py

Tests for nonce generation and validation.
"""

import pytest
import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from services.nonce_service import generate_nonce
from services.nonce_validator import validate_nonce


@pytest.mark.asyncio
async def test_generate_nonce():
    """Nonce should be 32 bytes of randomness, hex-encoded."""
    with patch("services.nonce_service.redis_client.store_nonce", new_callable=AsyncMock) as mock_store:
        nonce, expires_at = await generate_nonce("did:web:test.com:verifier", "test")

        # Nonce should be 64 hex chars (32 bytes)
        assert len(nonce) == 64
        assert all(c in "0123456789abcdef" for c in nonce)

        # Should have called store
        mock_store.assert_called_once()

        # expires_at should be an ISO timestamp
        dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        assert dt > datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_validate_nonce_success():
    """Nonce validation should succeed for valid nonce."""
    nonce_value = "a" * 64
    verifier_did = "did:web:test.com:verifier"

    with patch("services.nonce_validator.redis_client.get_nonce", new_callable=AsyncMock) as mock_get:
        with patch("services.nonce_validator.redis_client.delete_nonce", new_callable=AsyncMock) as mock_delete:
            mock_get.return_value = {
                "verifierDID": verifier_did,
                "purpose": "test",
                "used": False
            }

            vp_payload = {
                "proof": {
                    "challenge": nonce_value
                }
            }

            # Should not raise
            await validate_nonce(nonce_value, verifier_did, vp_payload)

            mock_delete.assert_called_once_with(nonce_value)


@pytest.mark.asyncio
async def test_validate_nonce_replay():
    """Nonce validation should fail for expired/missing nonce."""
    nonce_value = "a" * 64

    with patch("services.nonce_validator.redis_client.get_nonce", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = None  # Not found

        vp_payload = {
            "proof": {
                "challenge": nonce_value
            }
        }

        with pytest.raises(ValueError, match="Replay attack"):
            await validate_nonce(nonce_value, "did:web:test.com:verifier", vp_payload)


@pytest.mark.asyncio
async def test_validate_nonce_wrong_verifier():
    """Nonce validation should fail if verifier DID doesn't match."""
    nonce_value = "a" * 64

    with patch("services.nonce_validator.redis_client.get_nonce", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = {
            "verifierDID": "did:web:different.com:verifier",
            "purpose": "test",
            "used": False
        }

        vp_payload = {
            "proof": {
                "challenge": nonce_value
            }
        }

        with pytest.raises(ValueError, match="Replay attack"):
            await validate_nonce(nonce_value, "did:web:test.com:verifier", vp_payload)
