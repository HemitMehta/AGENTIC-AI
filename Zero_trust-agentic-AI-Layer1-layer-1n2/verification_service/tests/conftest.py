"""
tests/conftest.py
─────────────────
Pytest configuration and shared fixtures.
"""

import pytest
from unittest.mock import AsyncMock, patch


@pytest.fixture
def mock_redis_client():
    """Mock Redis client for all tests."""
    with patch("cache.redis_client.get_redis") as mock:
        yield mock


@pytest.fixture
def mock_did_registry():
    """Mock DID Registry client."""
    with patch("clients.did_registry_client.get_did_registry_client") as mock:
        client = AsyncMock()
        mock.return_value = client
        yield client


@pytest.fixture
def mock_trust_anchor():
    """Mock Trust Anchor client."""
    with patch("clients.trust_anchor_client.get_trust_anchor_client") as mock:
        client = AsyncMock()
        mock.return_value = client
        yield client


@pytest.fixture
def mock_kms():
    """Mock KMS client."""
    with patch("clients.kms_client.get_kms_client") as mock:
        client = AsyncMock()
        mock.return_value = client
        yield client


@pytest.fixture
def sample_vp_payload():
    """Sample decoded VP JWT payload."""
    return {
        "iss": "did:web:agents.example.com:agents:agent-123",
        "proof": {
            "challenge": "a" * 64,
            "created": "2024-09-15T10:00:00Z"
        },
        "verifiableCredential": [
            {
                "id": "urn:uuid:12345",
                "type": ["VerifiableCredential", "RoleVC"],
                "issuer": {
                    "id": "did:web:hr.example.com:hr-authority"
                },
                "issuanceDate": "2024-09-15T00:00:00Z",
                "expirationDate": "2025-09-15T00:00:00Z",
                "credentialSubject": {
                    "id": "did:web:agents.example.com:agents:agent-123",
                    "roleName": "FinancialAnalyst"
                },
                "credentialStatus": {
                    "statusListCredential": "https://status.example.com/lists/1",
                    "statusListIndex": 42
                },
                "proof": {
                    "type": "Ed25519Signature2020",
                    "created": "2024-09-15T00:00:00Z",
                    "verificationMethod": "did:web:hr.example.com:hr-authority#key-1",
                    "proofPurpose": "assertionMethod",
                    "proofValue": "mocksignature=="
                }
            }
        ]
    }


@pytest.fixture
def sample_did_document():
    """Sample DID Document."""
    return {
        "id": "did:web:agents.example.com:agents:agent-123",
        "lifecycleStatus": "active",
        "verificationMethod": [
            {
                "id": "did:web:agents.example.com:agents:agent-123#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": "did:web:agents.example.com:agents:agent-123",
                "publicKeyMultibase": "z6MkhaXgBZDvotzL8V6N7Eum6eoKahPtQDaSEUqEhBJvkc"
            }
        ],
        "toolset": [
            "did:web:tools.example.com:tools:data-processor",
            "did:web:tools.example.com:tools:ml-inference"
        ],
        "modelHash": "sha3-256-mockmodelhashabcdef1234567890"
    }
