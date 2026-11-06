"""
wallet_service/tests/test_wallet_lifecycle.py
Tests for wallet initialization and deletion.
"""

import pytest
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_init_wallet_new(sample_agent_did, mock_kms_client):
    """Test wallet initialization for a new agent."""
    
    with patch('services.wallet_service.get_session') as mock_session, \
         patch('services.wallet_service.get_wallet') as mock_get_wallet, \
         patch('services.wallet_service.create_wallet') as mock_create_wallet, \
         patch('services.wallet_service.kms_client', mock_kms_client):
        
        mock_session_obj = AsyncMock()
        mock_session.return_value = mock_session_obj
        mock_get_wallet.return_value = None
        
        from services.wallet_service import init_wallet
        result = await init_wallet(sample_agent_did)
        
        assert result == True
        mock_create_wallet.assert_called_once()


@pytest.mark.asyncio
async def test_init_wallet_idempotent(sample_agent_did):
    """Test wallet initialization is idempotent."""
    
    with patch('services.wallet_service.get_session') as mock_session, \
         patch('services.wallet_service.get_wallet') as mock_get_wallet:
        
        mock_session_obj = AsyncMock()
        mock_session.return_value = mock_session_obj
        mock_get_wallet.return_value = (sample_agent_did, "key-id", None, None, None)
        
        from services.wallet_service import init_wallet
        result = await init_wallet(sample_agent_did)
        
        assert result == False
