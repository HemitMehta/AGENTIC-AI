"""
status_list_service/tests/conftest.py

Shared fixtures for SS6 tests.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import uuid


@pytest.fixture
def mock_db_session():
    """Mock database session."""
    session = AsyncMock()
    session.close = AsyncMock()
    session.commit = AsyncMock()
    return session


@pytest.fixture
def mock_redis_client():
    """Mock Redis client."""
    return AsyncMock()


@pytest.fixture
def mock_kms_client():
    """Mock KMS client."""
    client = AsyncMock()
    client.sign_payload = AsyncMock(return_value="mock_signature_base64url")
    client.get_public_key = AsyncMock(return_value={
        "publicKey": "mock_key",
        "algorithm": "Ed25519",
        "status": "active"
    })
    return client


@pytest.fixture
def mock_kafka_producer():
    """Mock Kafka producer."""
    return AsyncMock()


@pytest.fixture
def sample_status_list_id():
    """Sample status list UUID."""
    return str(uuid.uuid4())


@pytest.fixture
def sample_vc_id():
    """Sample VC ID."""
    return "urn:uuid:" + str(uuid.uuid4())


@pytest.fixture
def sample_issuer_did():
    """Sample issuer DID."""
    return "did:web:issuer.example.com"


@pytest.fixture
def sample_agent_did():
    """Sample agent DID."""
    return "did:web:agent.example.com"
