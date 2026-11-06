"""
wallet_service/tests/conftest.py
────────────────────────────────
Shared fixtures for Wallet Service tests.
"""

import pytest
from unittest.mock import AsyncMock, patch


@pytest.fixture
def mock_kms_client():
    """Mock KMS client."""
    client = AsyncMock()
    client.generate_key = AsyncMock(return_value={"keyId": "key-123", "publicKey": "pk-123", "algorithm": "Ed25519"})
    client.sign_payload = AsyncMock(return_value="signature_base64url")
    client.get_public_key = AsyncMock(return_value="pk_material_base64")
    client.revoke_key = AsyncMock()
    return client


@pytest.fixture
def mock_did_client():
    """Mock DID Registry client."""
    client = AsyncMock()
    client.resolve_did = AsyncMock(return_value={
        "didDocument": {"controller": ["did:web:controller"]},
        "lifecycleStatus": "active"
    })
    client.get_did_controllers = AsyncMock(return_value=["did:web:controller"])
    return client


@pytest.fixture
def mock_vc_client():
    """Mock VC Issuance client."""
    client = AsyncMock()
    client.log_reputation_vc = AsyncMock(return_value={"logged": True})
    return client


@pytest.fixture
def sample_agent_did():
    return "did:web:agent.example.com"


@pytest.fixture
def sample_verifier_did():
    return "did:web:verifier.example.com"


@pytest.fixture
def sample_signed_vc_jwt():
    import json
    import base64
    
    vc = {
        "id": "urn:uuid:123",
        "type": ["VerifiableCredential", "RoleCredential"],
        "issuer": "did:web:issuer.example.com",
        "issuanceDate": "2026-05-29T00:00:00Z",
        "credentialSubject": {"id": "did:web:subject"},
        "proof": {"type": "Ed25519Signature2020", "proofValue": "sig123"}
    }
    
    header = {"alg": "EdDSA", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(json.dumps(vc).encode()).decode().rstrip('=')
    
    return f"{header_b64}.{payload_b64}.signature123"
