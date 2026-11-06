"""
wallet_service/tests/test_store_service.py
Tests for credential storage.
"""

import pytest
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_store_vc_success(sample_agent_did, sample_signed_vc_jwt):
    """Test successful credential storage."""
    
    with patch('services.store_service.get_session') as mock_session, \
         patch('services.store_service.get_wallet') as mock_get_wallet, \
         patch('services.store_service.store_credential') as mock_store_cred, \
         patch('services.store_service.key_handle') as mock_key_handle:
        
        mock_session_obj = AsyncMock()
        mock_session.return_value = mock_session_obj
        mock_get_wallet.return_value = (sample_agent_did, "key-id", None, None, None)
        mock_key_handle.get_derived_key = AsyncMock(return_value=b'0' * 32)
        mock_key_handle.zero_key = lambda x: None
        
        from services.store_service import store_vc
        vc_id = await store_vc(sample_agent_did, sample_signed_vc_jwt)
        
        assert vc_id == "urn:uuid:123"
        mock_store_cred.assert_called_once()
