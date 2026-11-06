"""
status_list_service/tests/test_cascade_coordinator.py

Tests for agent revocation cascade.
"""

import pytest
from unittest.mock import AsyncMock, patch

from services.cascade_coordinator import revoke_agent_cascade


@pytest.mark.asyncio
async def test_revoke_agent_cascade_success():
    """Test successful agent revocation cascade."""

    with patch('services.cascade_coordinator.get_session') as mock_get_session, \
         patch('services.cascade_coordinator.get_entries_for_agent') as mock_get_entries, \
         patch('services.cascade_coordinator.revoke_credential') as mock_revoke, \
         patch('services.cascade_coordinator.did_registry_client') as mock_did_client, \
         patch('services.cascade_coordinator.add_to_blocklist') as mock_blocklist, \
         patch('services.cascade_coordinator.producer') as mock_producer, \
         patch('services.cascade_coordinator.ans_client') as mock_ans, \
         patch('services.cascade_coordinator.log_revocation') as mock_log:

        # Setup
        mock_session = AsyncMock()
        mock_get_session.return_value = mock_session

        mock_entries = [
            {"vc_id": "vc1", "status_list_id": "list1", "bit_index": 0},
            {"vc_id": "vc2", "status_list_id": "list1", "bit_index": 1}
        ]
        mock_get_entries.return_value = mock_entries

        mock_revoke.return_value = {"revoked_at": "2026-05-29T00:00:00Z", "bit_index": 0}
        mock_did_client.update_did = AsyncMock()
        mock_blocklist.return_value = {"added_at": "2026-05-29T00:00:00Z"}
        mock_producer.publish_agent_revoked = AsyncMock()
        mock_ans.deactivate_agent = AsyncMock()

        # Execute
        result = await revoke_agent_cascade("did:key:agent123", "security incident", "did:web:authority")

        # Verify
        assert result["cascade_complete"] == True
        assert len(result["steps"]) == 6
        assert result["kafka_event_id"] is not None

        # Check step statuses
        step_names = [s["step"] for s in result["steps"]]
        assert "REVOKE_VCS" in step_names
        assert "UPDATE_DID_DOCUMENT" in step_names
        assert "EPHEMERAL_BLOCKLIST" in step_names
        assert "KAFKA_EVENT" in step_names
        assert "ANS_DEACTIVATE" in step_names


@pytest.mark.asyncio
async def test_revoke_agent_cascade_partial_failure():
    """Test agent cascade with some steps failing."""

    with patch('services.cascade_coordinator.get_session') as mock_get_session, \
         patch('services.cascade_coordinator.get_entries_for_agent') as mock_get_entries, \
         patch('services.cascade_coordinator.revoke_credential') as mock_revoke, \
         patch('services.cascade_coordinator.did_registry_client') as mock_did_client, \
         patch('services.cascade_coordinator.producer') as mock_producer:

        mock_session = AsyncMock()
        mock_get_session.return_value = mock_session

        mock_entries = [
            {"vc_id": "vc1", "status_list_id": "list1", "bit_index": 0}
        ]
        mock_get_entries.return_value = mock_entries

        mock_revoke.return_value = {"revoked_at": "2026-05-29T00:00:00Z", "bit_index": 0}
        
        # Make DID update fail
        mock_did_client.update_did = AsyncMock(side_effect=Exception("DID Registry unavailable"))
        mock_producer.publish_agent_revoked = AsyncMock()

        # Execute
        result = await revoke_agent_cascade("did:web:agent123", "testing", "did:web:authority")

        # Cascade still completes but has failures
        steps_by_name = {s["step"]: s for s in result["steps"]}
        assert steps_by_name["UPDATE_DID_DOCUMENT"]["status"] == "failed"
