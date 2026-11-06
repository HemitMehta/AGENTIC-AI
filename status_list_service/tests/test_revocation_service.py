"""
status_list_service/tests/test_revocation_service.py

Tests for revocation orchestration.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

from services.revocation_service import revoke_credential


@pytest.mark.asyncio
async def test_revoke_credential_success():
    """Test successful credential revocation."""
    
    with patch('services.revocation_service.get_session') as mock_get_session, \
         patch('services.revocation_service.get_entry_by_vc_id') as mock_get_entry, \
         patch('services.revocation_service.get_status_list') as mock_get_status_list, \
         patch('services.revocation_service.redis_client') as mock_redis, \
         patch('services.revocation_service.update_bitstring') as mock_update_bits, \
         patch('services.revocation_service.mark_entry_revoked') as mock_mark_revoked, \
         patch('services.revocation_service.log_revocation') as mock_log, \
         patch('services.revocation_service.producer') as mock_producer:

        # Setup mocks
        mock_session = AsyncMock()
        selected = MagicMock()
        selected.first.return_value = (bytes(16384),)
        mock_session.execute.return_value = selected
        mock_get_session.return_value = mock_session

        mock_entry = {
            "vc_id": "urn:uuid:123",
            "status_list_id": "list-123",
            "bit_index": 42,
            "status_list_url": "http://localhost:8005/status-lists/list-123",
            "revoked_at": None
        }
        mock_get_entry.return_value = mock_entry

        mock_status_list = {
            "bitstring": b'\x00' * 16384
        }
        mock_get_status_list.return_value = mock_status_list

        mock_redis.get_cached_bitstring = AsyncMock(return_value=None)
        mock_redis.update_cached_bitstring = AsyncMock()
        mock_redis.invalidate_status_list = AsyncMock()

        mock_producer.publish_credential_revoked = AsyncMock()

        # Execute
        result = await revoke_credential("urn:uuid:123", "testing", "did:web:authority")

        # Verify
        assert result["bit_index"] == 42
        assert result["kafka_event_id"] is not None
        assert mock_redis.update_cached_bitstring.called
        assert mock_session.execute.await_count == 3
        assert mock_redis.invalidate_status_list.called
        assert mock_producer.publish_credential_revoked.called


@pytest.mark.asyncio
async def test_revoke_credential_already_revoked():
    """Test revoking an already-revoked credential."""

    with patch('services.revocation_service.get_session') as mock_get_session, \
         patch('services.revocation_service.get_entry_by_vc_id') as mock_get_entry:

        mock_session = AsyncMock()
        mock_get_session.return_value = mock_session

        mock_entry = {
            "vc_id": "urn:uuid:123",
            "status_list_id": "list-123",
            "bit_index": 42,
            "status_list_url": "http://localhost:8005/status-lists/list-123",
            "revoked_at": datetime.now(timezone.utc).isoformat()
        }
        mock_get_entry.return_value = mock_entry

        # Execute
        result = await revoke_credential("urn:uuid:123", "testing", "did:web:authority")

        # Should return existing revocation info without re-revoking
        assert result["bit_index"] == 42
        assert result["kafka_event_id"] is None
