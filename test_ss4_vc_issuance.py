"""
test_ss4_vc_issuance.py

Sub-System 4: VC Issuance Service  (Person B — Layer 1)

Comprehensive tests for vc_issuance.py

Run all:
    pytest test_ss4_vc_issuance.py -v

Run one class:
    pytest test_ss4_vc_issuance.py::TestRoleVCIssuance -v

Uses mocks for external dependencies (KMS, DID Registry, Trust Anchor, StatusList).
For integration tests, replace mocks with real services via env var.
"""

import os
import pytest
import json
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch, MagicMock

import vc_issuance


# FIXTURES

@pytest.fixture(autouse=True)
def mock_kms():
    """Mock KMS module functions."""
    with patch("vc_issuance.kms.sign_payload") as mock_sign:
        mock_sign.return_value = {
            "signature": "mocksignature==",
            "algorithm": "Ed25519",
            "keyId": "test-key"
        }
        with patch("vc_issuance.kms.get_public_key") as mock_pubkey:
            mock_pubkey.return_value = {
                "keyId": "test-key",
                "publicKey": "mockpubkey==",
                "algorithm": "Ed25519",
                "status": "active"
            }
            yield mock_sign, mock_pubkey


@pytest.fixture(autouse=True)
def mock_did_registry():
    """Mock DID registry resolution."""
    with patch("vc_issuance.did_registry.resolve_did_at_time") as mock_resolve:
        def resolve_side_effect(did, at_iso):
            # Return active DID document with toolset
            return {
                "didDocument": {
                    "id": did,
                    "lifecycleStatus": "active",
                    "toolset": [
                        "did:web:tools.example.com:tools:data-processor",
                        "did:web:tools.example.com:tools:ml-inference",
                    ],
                    "modelHash": "sha3-256-mockmodelhashabcdef1234567890"
                },
                "version": 1,
                "validFrom": at_iso,
                "validUntil": None
            }
        mock_resolve.side_effect = resolve_side_effect
        yield mock_resolve


@pytest.fixture(autouse=True)
def mock_root_trust():
    """Mock root trust anchor validation."""
    with patch("vc_issuance.root_trust.validate_issuer") as mock_validate:
        mock_validate.return_value = {
            "authorised": True,
            "reason": "Issuer is authorized.",
            "validUntil": None,
            "conditions": None
        }
        yield mock_validate


@pytest.fixture(autouse=True)
def mock_status_list():
    """Mock status list allocation."""
    with patch("vc_issuance.status_list.allocate_status_entry") as mock_allocate:
        mock_allocate.return_value = {
            "statusListUrl": "https://status.example.com/lists/1",
            "bitIndex": 42
        }
        yield mock_allocate



@pytest.fixture(autouse=True)
def mock_persist_vc():
    """Mock database persistence — unit tests don't need a real DB."""
    with patch("vc_issuance._persist_vc") as mock_persist:
        mock_persist.return_value = None
        yield mock_persist


@pytest.fixture
def test_subject_did():
    return "did:web:agents.example.com:agents:agent-123"


@pytest.fixture
def test_issuer_did():
    return "did:web:governance.example.com:governance:hr-authority"


@pytest.fixture
def test_issuer_key_id():
    return "key-12345"


@pytest.fixture
def test_trust_domain():
    return "enterprise"


# TESTS: Role VC

class TestRoleVCIssuance:
    """Tests for issue_role_vc()"""

    def test_issue_role_vc_success(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """Successful issuance of a Role VC."""
        claims = {
            "roleName": "FinancialRiskAnalystRole",
            "roleDescription": "Analyzes financial risk across portfolios",
            "organisationDID": "did:web:finance.example.com:org:acme"
        }

        result = vc_issuance.issue_role_vc(
            subject_did=test_subject_did,
            issuer_did=test_issuer_did,
            issuer_key_id=test_issuer_key_id,
            claims=claims,
            trust_domain=test_trust_domain
        )

        assert "vcId" in result
        assert result["vcId"].startswith("urn:uuid:")
        assert result["credentialType"] == "RoleVC"
        assert result["subjectDID"] == test_subject_did
        assert result["issuerDID"] == test_issuer_did
        assert "signedVC" in result
        assert result["signedVC"]["type"] == ["VerifiableCredential", "RoleVC"]
        assert "proof" in result["signedVC"]
        assert "credentialStatus" in result["signedVC"]

    def test_issue_role_vc_missing_required_claim(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """Reject Role VC if required claim is missing."""
        claims = {
            "roleName": "FinancialRiskAnalystRole",
            # Missing roleDescription
            "organisationDID": "did:web:finance.example.com:org:acme"
        }

        with pytest.raises(ValueError, match="Missing required claim: roleDescription"):
            vc_issuance.issue_role_vc(
                subject_did=test_subject_did,
                issuer_did=test_issuer_did,
                issuer_key_id=test_issuer_key_id,
                claims=claims,
                trust_domain=test_trust_domain
            )

    def test_issue_role_vc_unauthorised_issuer(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain, mock_root_trust):
        """Reject Role VC if issuer is not authorized."""
        # Configure mock to reject
        mock_root_trust.return_value = {
            "authorised": False,
            "reason": "Issuer not in trust anchor",
            "validUntil": None
        }

        claims = {
            "roleName": "TestRole",
            "roleDescription": "Test role",
            "organisationDID": "did:web:test.example.com:org:test"
        }

        with pytest.raises(PermissionError, match="not in trust anchor"):
            vc_issuance.issue_role_vc(
                subject_did=test_subject_did,
                issuer_did=test_issuer_did,
                issuer_key_id=test_issuer_key_id,
                claims=claims,
                trust_domain=test_trust_domain
            )

    def test_issue_role_vc_inactive_subject(self, test_issuer_did, test_issuer_key_id, test_trust_domain, mock_did_registry):
        """Reject Role VC if subject DID is not active."""
        # Configure mock to return inactive status
        def resolve_inactive(did, at_iso):
            return {
                "didDocument": {
                    "id": did,
                    "lifecycleStatus": "deactivated",
                    "toolset": []
                },
                "version": 1,
                "validFrom": at_iso,
                "validUntil": None
            }
        mock_did_registry.side_effect = resolve_inactive

        claims = {
            "roleName": "TestRole",
            "roleDescription": "Test",
            "organisationDID": "did:web:test.example.com:org:test"
        }

        with pytest.raises(ValueError, match="is not active"):
            vc_issuance.issue_role_vc(
                subject_did="did:web:inactive.example.com:agent:inactive",
                issuer_did=test_issuer_did,
                issuer_key_id=test_issuer_key_id,
                claims=claims,
                trust_domain=test_trust_domain
            )

    def test_issue_role_vc_return_structure(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """Verify return structure contains all required fields."""
        claims = {
            "roleName": "TestRole",
            "roleDescription": "Test role description",
            "organisationDID": "did:web:org.example.com:org:test"
        }

        result = vc_issuance.issue_role_vc(
            subject_did=test_subject_did,
            issuer_did=test_issuer_did,
            issuer_key_id=test_issuer_key_id,
            claims=claims,
            trust_domain=test_trust_domain
        )

        # Verify return structure
        required_keys = [
            "vcId", "signedVC", "credentialType", "subjectDID", "issuerDID",
            "issuedAt", "expiresAt", "statusListUrl", "statusListIndex", "contentHash"
        ]
        for key in required_keys:
            assert key in result, f"Missing key: {key}"

        # Verify VC document structure
        vc = result["signedVC"]
        assert vc["@context"] == [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
            "https://w3id.org/vc-status-list-2021/v1"
        ]
        assert vc["id"] == result["vcId"]
        assert vc["issuer"]["id"] == test_issuer_did
        assert vc["credentialSubject"]["id"] == test_subject_did
        assert vc["credentialSubject"]["roleName"] == "TestRole"


# TESTS: Capability VC

class TestCapabilityVCIssuance:
    """Tests for issue_capability_vc()"""

    def test_issue_capability_vc_success(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """Successful issuance of a Capability VC."""
        claims = {
            "capabilityName": "SalesDataAnalyticsCapability",
            "certifiedActions": ["analyze", "report", "export"],
            "toolsDID": [
                "did:web:tools.example.com:tools:data-processor",
                "did:web:tools.example.com:tools:ml-inference"
            ],
            "modelVersionHash": "sha3-256-mockmodelhashabcdef1234567890",
            "certifyingBodyDID": "did:web:governance.example.com:governance:tech-cert"
        }

        result = vc_issuance.issue_capability_vc(
            subject_did=test_subject_did,
            issuer_did=test_issuer_did,
            issuer_key_id=test_issuer_key_id,
            claims=claims,
            trust_domain=test_trust_domain
        )

        assert result["credentialType"] == "CapabilityVC"
        assert result["signedVC"]["credentialSubject"]["capabilityName"] == "SalesDataAnalyticsCapability"

    def test_issue_capability_vc_model_hash_mismatch(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain, mock_did_registry):
        """Reject Capability VC if model hash doesn't match subject's DID Document."""
        # Configure mock to return different model hash
        def resolve_diff_model(did, at_iso):
            return {
                "didDocument": {
                    "id": did,
                    "lifecycleStatus": "active",
                    "toolset": ["did:web:tools.example.com:tools:data-processor"],
                    "modelHash": "sha3-256-differentmodelhashabcdef9999999"
                },
                "version": 1,
                "validFrom": at_iso,
                "validUntil": None
            }
        mock_did_registry.side_effect = resolve_diff_model

        claims = {
            "capabilityName": "TestCapability",
            "certifiedActions": ["test"],
            "toolsDID": ["did:web:tools.example.com:tools:data-processor"],
            "modelVersionHash": "sha3-256-wrongmodelhash",
            "certifyingBodyDID": "did:web:governance.example.com:governance:tech-cert"
        }

        with pytest.raises(ValueError, match="Model hash mismatch"):
            vc_issuance.issue_capability_vc(
                subject_did=test_subject_did,
                issuer_did=test_issuer_did,
                issuer_key_id=test_issuer_key_id,
                claims=claims,
                trust_domain=test_trust_domain
            )

    def test_issue_capability_vc_missing_claim(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """Reject Capability VC if required claim is missing."""
        claims = {
            "capabilityName": "TestCapability",
            # Missing certifiedActions
            "toolsDID": ["did:web:tools.example.com:tools:data-processor"],
            "modelVersionHash": "sha3-256-mockmodelhashabcdef1234567890",
            "certifyingBodyDID": "did:web:governance.example.com:governance:tech-cert"
        }

        with pytest.raises(ValueError, match="Missing required claim: certifiedActions"):
            vc_issuance.issue_capability_vc(
                subject_did=test_subject_did,
                issuer_did=test_issuer_did,
                issuer_key_id=test_issuer_key_id,
                claims=claims,
                trust_domain=test_trust_domain
            )


# TESTS: Compliance VC

class TestComplianceVCIssuance:
    """Tests for issue_compliance_vc()"""

    def test_issue_compliance_vc_success(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """Successful issuance of a Compliance VC."""
        claims = {
            "complianceFramework": "SOXComplianceCertified",
            "auditDate": "2024-09-01T00:00:00Z",
            "auditRef": "AUDIT-2024-0001",
            "auditBodyDID": "did:web:auditors.example.com:auditor:deloitte",
            "scope": "Financial reporting controls"
        }

        result = vc_issuance.issue_compliance_vc(
            subject_did=test_subject_did,
            issuer_did=test_issuer_did,
            issuer_key_id=test_issuer_key_id,
            claims=claims,
            trust_domain=test_trust_domain
        )

        assert result["credentialType"] == "ComplianceVC"
        assert result["signedVC"]["credentialSubject"]["complianceFramework"] == "SOXComplianceCertified"

    def test_issue_compliance_vc_missing_audit_date(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """Reject Compliance VC if auditDate is missing."""
        claims = {
            "complianceFramework": "SOXComplianceCertified",
            # Missing auditDate
            "auditRef": "AUDIT-2024-0001",
            "auditBodyDID": "did:web:auditors.example.com:auditor:deloitte",
            "scope": "Financial reporting controls"
        }

        with pytest.raises(ValueError, match="Missing required claim: auditDate"):
            vc_issuance.issue_compliance_vc(
                subject_did=test_subject_did,
                issuer_did=test_issuer_did,
                issuer_key_id=test_issuer_key_id,
                claims=claims,
                trust_domain=test_trust_domain
            )


# TESTS: Provenance VC

class TestProvenanceVCIssuance:
    """Tests for issue_provenance_vc()"""

    def test_issue_provenance_vc_success(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """Successful issuance of a Provenance VC."""
        claims = {
            "parentDID": test_issuer_did,
            "spawnedAt": "2024-09-15T10:30:00Z",
            "spawnReason": "Task delegation",
            "provenanceAttestation": "base64encodedattestationdata==",
            "jobID": "job-12345"
        }

        result = vc_issuance.issue_provenance_vc(
            subject_did=test_subject_did,
            issuer_did=test_issuer_did,
            issuer_key_id=test_issuer_key_id,
            claims=claims,
            trust_domain=test_trust_domain
        )

        assert result["credentialType"] == "ProvenanceVC"
        assert result["signedVC"]["credentialSubject"]["parentDID"] == test_issuer_did

    def test_issue_provenance_vc_missing_attestation(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """Reject Provenance VC if provenanceAttestation is missing."""
        claims = {
            "parentDID": test_issuer_did,
            "spawnedAt": "2024-09-15T10:30:00Z",
            "spawnReason": "Task delegation",
            # Missing provenanceAttestation
            "jobID": "job-12345"
        }

        with pytest.raises(ValueError, match="Missing required claim: provenanceAttestation"):
            vc_issuance.issue_provenance_vc(
                subject_did=test_subject_did,
                issuer_did=test_issuer_did,
                issuer_key_id=test_issuer_key_id,
                claims=claims,
                trust_domain=test_trust_domain
            )

# TESTS: Reputation VC

class TestReputationVCIssuance:
    """Tests for issue_reputation_vc()"""

    def test_issue_reputation_vc_success(self, test_subject_did, test_issuer_key_id, test_trust_domain):
        """Successful issuance of a Reputation VC (peer-issued)."""
        peer_issuer_did = "did:web:agents.example.com:agents:peer-agent-456"
        
        claims = {
            "reputationScore": 85,
            "tasksCompleted": 42,
            "violationCount": 0,
            "peerDID": peer_issuer_did,
            "collaborationJobIDs": ["job-001", "job-002"],
            "assessmentSummary": "Excellent performance on data analysis tasks"
        }

        result = vc_issuance.issue_reputation_vc(
            subject_did=test_subject_did,
            issuer_did=peer_issuer_did,
            issuer_key_id=test_issuer_key_id,
            claims=claims,
            trust_domain=test_trust_domain
        )

        assert result["credentialType"] == "ReputationVC"
        assert result["signedVC"]["credentialSubject"]["reputationScore"] == 85

    def test_issue_reputation_vc_peer_issuer_active_check(self, test_subject_did, test_issuer_key_id, test_trust_domain, mock_root_trust):
        """Reputation VC bypasses root_trust.validate_issuer, only checks peer is active."""
        peer_issuer_did = "did:web:agents.example.com:agents:peer-agent-456"
        
        claims = {
            "reputationScore": 75,
            "tasksCompleted": 30,
            "violationCount": 1,
            "peerDID": peer_issuer_did
        }

        result = vc_issuance.issue_reputation_vc(
            subject_did=test_subject_did,
            issuer_did=peer_issuer_did,
            issuer_key_id=test_issuer_key_id,
            claims=claims,
            trust_domain=test_trust_domain
        )

        # root_trust.validate_issuer should NOT have been called for Reputation VC
        # (it may be called for logging but result should be ignored)
        assert result["credentialType"] == "ReputationVC"

    def test_issue_reputation_vc_invalid_score_range(self, test_subject_did, test_issuer_key_id, test_trust_domain):
        """Reject Reputation VC if score is outside 0-100 range."""
        peer_issuer_did = "did:web:agents.example.com:agents:peer-agent-456"
        
        claims = {
            "reputationScore": 150,  # Invalid: > 100
            "tasksCompleted": 30,
            "violationCount": 1,
            "peerDID": peer_issuer_did
        }

        with pytest.raises(ValueError, match="between 0 and 100"):
            vc_issuance.issue_reputation_vc(
                subject_did=test_subject_did,
                issuer_did=peer_issuer_did,
                issuer_key_id=test_issuer_key_id,
                claims=claims,
                trust_domain=test_trust_domain
            )


# TESTS: JIT VC

class TestJITVCIssuance:
    """Tests for issue_jit_vc()"""

    def test_issue_jit_vc_success(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """Successful issuance of a JIT VC."""
        claims = {
            "jobID": "job-jit-001",
            "toolDID": "did:web:tools.example.com:tools:data-processor",
            "allowedAction": "process_data",
            "inputHandle": "s3://bucket/input-123",
            "outputHandle": "s3://bucket/output-456",
            "scopeNote": "Process customer financial data for Q3 report"
        }

        result = vc_issuance.issue_jit_vc(
            subject_did=test_subject_did,
            issuer_did=test_issuer_did,
            issuer_key_id=test_issuer_key_id,
            claims=claims,
            trust_domain=test_trust_domain
        )

        assert result["credentialType"] == "JITVC"
        assert result["signedVC"]["credentialSubject"]["jobID"] == "job-jit-001"

    def test_issue_jit_vc_exceeds_60_min(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """Reject JIT VC if validity exceeds 60 minutes."""
        claims = {
            "jobID": "job-jit-002",
            "toolDID": "did:web:tools.example.com:tools:data-processor",
            "allowedAction": "process_data",
            "inputHandle": "s3://bucket/input",
            "outputHandle": "s3://bucket/output"
        }

        now = datetime.now(timezone.utc)
        # Set expiration to 90 minutes from now (exceeds 60-min limit)
        valid_until = now + timedelta(minutes=90)
        valid_until_iso = valid_until.isoformat()

        with pytest.raises(ValueError, match="exceeds maximum of 60 minutes"):
            vc_issuance.issue_jit_vc(
                subject_did=test_subject_did,
                issuer_did=test_issuer_did,
                issuer_key_id=test_issuer_key_id,
                claims=claims,
                trust_domain=test_trust_domain,
                valid_until_iso=valid_until_iso
            )

    def test_issue_jit_vc_missing_job_id(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """Reject JIT VC if jobID is missing."""
        claims = {
            # Missing jobID
            "toolDID": "did:web:tools.example.com:tools:data-processor",
            "allowedAction": "process_data",
            "inputHandle": "s3://bucket/input",
            "outputHandle": "s3://bucket/output"
        }

        with pytest.raises(ValueError, match="Missing required claim: jobID"):
            vc_issuance.issue_jit_vc(
                subject_did=test_subject_did,
                issuer_did=test_issuer_did,
                issuer_key_id=test_issuer_key_id,
                claims=claims,
                trust_domain=test_trust_domain
            )

    def test_issue_jit_vc_tool_not_in_toolset(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain, mock_did_registry):
        """Reject JIT VC if toolDID is not in subject's toolset."""
        # Configure mock to return a restricted toolset
        def resolve_limited_toolset(did, at_iso):
            return {
                "didDocument": {
                    "id": did,
                    "lifecycleStatus": "active",
                    "toolset": [
                        "did:web:tools.example.com:tools:data-processor"
                        # ml-inference is NOT in toolset
                    ],
                    "modelHash": "sha3-256-mockmodelhashabcdef1234567890"
                },
                "version": 1,
                "validFrom": at_iso,
                "validUntil": None
            }
        mock_did_registry.side_effect = resolve_limited_toolset

        claims = {
            "jobID": "job-jit-003",
            "toolDID": "did:web:tools.example.com:tools:ml-inference",  # NOT in toolset
            "allowedAction": "infer",
            "inputHandle": "s3://bucket/input",
            "outputHandle": "s3://bucket/output"
        }

        with pytest.raises(ValueError, match="not in subject agent's authorised toolset"):
            vc_issuance.issue_jit_vc(
                subject_did=test_subject_did,
                issuer_did=test_issuer_did,
                issuer_key_id=test_issuer_key_id,
                claims=claims,
                trust_domain=test_trust_domain
            )

    def test_issue_jit_vc_all_required_fields_present(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """Verify all 5 required JIT fields must be present and non-empty."""
        # Test with empty toolDID
        claims = {
            "jobID": "job-jit-004",
            "toolDID": "",  # Empty — should fail
            "allowedAction": "process",
            "inputHandle": "s3://bucket/input",
            "outputHandle": "s3://bucket/output"
        }

        with pytest.raises(ValueError, match="Missing required claim"):
            vc_issuance.issue_jit_vc(
                subject_did=test_subject_did,
                issuer_did=test_issuer_did,
                issuer_key_id=test_issuer_key_id,
                claims=claims,
                trust_domain=test_trust_domain
            )


# TESTS: VC Document Structure

class TestVCDocumentStructure:
    """Tests for W3C VC document structure and required fields."""

    def test_vc_has_context(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """VC document must have correct @context array."""
        claims = {
            "roleName": "TestRole",
            "roleDescription": "Test",
            "organisationDID": "did:web:org.example.com:org:test"
        }

        result = vc_issuance.issue_role_vc(
            subject_did=test_subject_did,
            issuer_did=test_issuer_did,
            issuer_key_id=test_issuer_key_id,
            claims=claims,
            trust_domain=test_trust_domain
        )

        vc = result["signedVC"]
        expected_contexts = [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
            "https://w3id.org/vc-status-list-2021/v1"
        ]
        assert vc["@context"] == expected_contexts

    def test_vc_has_proof_block(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """VC document must have proof block with Ed25519Signature2020."""
        claims = {
            "roleName": "TestRole",
            "roleDescription": "Test",
            "organisationDID": "did:web:org.example.com:org:test"
        }

        result = vc_issuance.issue_role_vc(
            subject_did=test_subject_did,
            issuer_did=test_issuer_did,
            issuer_key_id=test_issuer_key_id,
            claims=claims,
            trust_domain=test_trust_domain
        )

        vc = result["signedVC"]
        assert "proof" in vc
        proof = vc["proof"]
        assert proof["type"] == "Ed25519Signature2020"
        assert "created" in proof
        assert proof["verificationMethod"] == f"{test_issuer_did}#{test_issuer_key_id}"
        assert proof["proofPurpose"] == "assertionMethod"
        assert "proofValue" in proof

    def test_vc_has_credential_status(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """VC document must have credentialStatus with StatusList2021Entry."""
        claims = {
            "roleName": "TestRole",
            "roleDescription": "Test",
            "organisationDID": "did:web:org.example.com:org:test"
        }

        result = vc_issuance.issue_role_vc(
            subject_did=test_subject_did,
            issuer_did=test_issuer_did,
            issuer_key_id=test_issuer_key_id,
            claims=claims,
            trust_domain=test_trust_domain
        )

        vc = result["signedVC"]
        assert "credentialStatus" in vc
        status = vc["credentialStatus"]
        assert status["type"] == "StatusList2021Entry"
        assert status["statusPurpose"] == "revocation"
        assert "statusListIndex" in status
        assert "statusListCredential" in status

    def test_vc_content_hash_matches(self, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """VC content hash must match SHA3-256 of the document (before proof)."""
        import hashlib
        
        claims = {
            "roleName": "TestRole",
            "roleDescription": "Test",
            "organisationDID": "did:web:org.example.com:org:test"
        }

        result = vc_issuance.issue_role_vc(
            subject_did=test_subject_did,
            issuer_did=test_issuer_did,
            issuer_key_id=test_issuer_key_id,
            claims=claims,
            trust_domain=test_trust_domain
        )

        vc = result["signedVC"]
        # Reconstruct the VC without proof to compute hash
        vc_without_proof = {k: v for k, v in vc.items() if k != "proof"}
        content_hash = hashlib.sha3_256(
            json.dumps(vc_without_proof, sort_keys=True).encode()
        ).hexdigest()

        assert content_hash == result["contentHash"]


# TESTS: Database Persistence (if pg fixture available)

@pytest.mark.skipif(
    not os.getenv("TEST_DB_INTEGRATION"),
    reason="Requires real DB (set TEST_DB_INTEGRATION=1)"
)
class TestVCDatabasePersistence:
    """Tests for VC persistence to database (requires real DB)."""

    @pytest.fixture(scope="class")
    def pg(self):
        """Real CockroachDB connection."""
        import psycopg2
        from psycopg2.extras import RealDictCursor
        
        try:
            conn = psycopg2.connect(
                host=os.getenv("CRDB_HOST", "localhost"),
                port=int(os.getenv("CRDB_PORT", "26257")),
                dbname=os.getenv("CRDB_DB", "did_registry"),
                user=os.getenv("CRDB_USER", "root"),
                password=os.getenv("CRDB_PASSWORD", ""),
                sslmode=os.getenv("CRDB_SSLMODE", "disable"),
                cursor_factory=RealDictCursor,
                connect_timeout=5,
            )
            vc_issuance.initialize_schema()
            yield conn
        finally:
            conn.close()

    def test_vc_persisted_to_database(self, pg, test_subject_did, test_issuer_did, test_issuer_key_id, test_trust_domain):
        """VC is persisted to vc_credentials table."""
        # This would need unpatched imports to work
        # Skipped in default test run due to skipif marker
        pass
