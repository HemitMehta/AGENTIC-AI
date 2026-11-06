"""
tests/test_integration_end_to_end.py

End-to-end scenario tests covering complete workflows.
"""

import pytest
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_complete_workflow_agent_presents_credentials_to_verifier():
    """
    Complete workflow:
    1. Authority issues Role VC to Agent
    2. Authority issues Capability VC to Agent
    3. Agent requests nonce from Verifier
    4. Agent creates VP containing both VCs
    5. Agent signs VP and sends to Verifier
    6. Verifier receives VP and verifies all 6 steps pass
    7. Verifier gets back merged claims from both VCs
    """

    # Setup 

    authority_did = "did:web:hr.example.com:hr-authority"
    agent_did = "did:web:agents.example.com:agents:agent-001"
    verifier_did = "did:web:banking.example.com:verifier:v1"

    #  Phase 1: Issue Role VC 

    role_vc_request = {
        "issuerDID": authority_did,
        "subjectDID": agent_did,
        "credentialType": "RoleVC",
        "trustDomain": "finance",
        "claims": {
            "roleName": "PortfolioManager",
            "department": "Equities"
        }
    }

    with patch("vc_issuance._run_issuance_pipeline") as mock_issue:
        role_vc = {
            "id": "urn:uuid:role-123",
            "type": ["VerifiableCredential", "RoleVC"],
            "issuer": {"id": authority_did},
            "issuanceDate": datetime.now(timezone.utc).isoformat(),
            "expirationDate": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "credentialSubject": {
                "id": agent_did,
                "roleName": "PortfolioManager",
                "department": "Equities"
            },
            "credentialStatus": {
                "statusListCredential": "https://status.example.com/role-list",
                "statusListIndex": 10
            },
            "proof": {
                "type": "Ed25519Signature2020",
                "proofValue": "sig_role_123"
            }
        }
        mock_issue.return_value = (True, role_vc)

        from vc_issuance import issue_credential
        success, issued_role_vc = await issue_credential(role_vc_request)
        assert success

    # Phase 2: Issue Capability VC 

    capability_vc_request = {
        "issuerDID": authority_did,
        "subjectDID": agent_did,
        "credentialType": "CapabilityVC",
        "trustDomain": "finance",
        "claims": {
            "modelHash": "sha3-256-ai-model-hash-xyz"
        }
    }

    with patch("vc_issuance._run_issuance_pipeline") as mock_issue:
        capability_vc = {
            "id": "urn:uuid:capability-456",
            "type": ["VerifiableCredential", "CapabilityVC"],
            "issuer": {"id": authority_did},
            "issuanceDate": datetime.now(timezone.utc).isoformat(),
            "expirationDate": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "credentialSubject": {
                "id": agent_did,
                "modelHash": "sha3-256-ai-model-hash-xyz"
            },
            "credentialStatus": {
                "statusListCredential": "https://status.example.com/capability-list",
                "statusListIndex": 20
            },
            "proof": {
                "type": "Ed25519Signature2020",
                "proofValue": "sig_capability_456"
            }
        }
        mock_issue.return_value = (True, capability_vc)

        from vc_issuance import issue_credential
        success, issued_capability_vc = await issue_credential(capability_vc_request)
        assert success

    #  Phase 3: Agent requests nonce from Verifier 

    nonce_value = secrets.token_hex(32)
    nonce_expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    # In real scenario, this would be: POST /verify/nonce

    #  Phase 4: Agent creates VP 

    import json
    import base64

    vp_payload = {
        "iss": agent_did,
        "proof": {
            "challenge": nonce_value,
            "created": datetime.now(timezone.utc).isoformat()
        },
        "verifiableCredential": [issued_role_vc, issued_capability_vc]
    }

    header = {"alg": "EdDSA", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(vp_payload).encode()).decode().rstrip("=")
    vp_signature_b64 = base64.urlsafe_b64encode(b"agent_signature").decode().rstrip("=")
    vp_jwt = f"{header_b64}.{payload_b64}.{vp_signature_b64}"

    #  Phase 5: Verifier verifies VP 

    with patch("verification_service.services.vp_sig_verifier.verify_vp_signature", new_callable=AsyncMock) as mock_vp_sig:
        with patch("verification_service.services.nonce_validator.validate_nonce", new_callable=AsyncMock):
            with patch("verification_service.services.vc_sig_verifier.verify_vc_signatures", new_callable=AsyncMock):
                with patch("verification_service.services.trust_anchor_checker.validate_issuers", new_callable=AsyncMock):
                    with patch("verification_service.services.revocation_checker.check_revocation_status", new_callable=AsyncMock):
                        with patch("verification_service.services.expiry_checker.check_expiry", new_callable=AsyncMock):
                            mock_vp_sig.return_value = (agent_did, vp_payload)

                            from verification_service.services.pipeline import verify_presentation

                            valid, verified_claims, failed_step, reason = await verify_presentation(
                                vp_jwt,
                                nonce_value,
                                verifier_did
                            )

    #  Phase 6: Verify results 

    assert valid is True, f"Presentation verification failed at {failed_step}: {reason}"
    assert failed_step is None
    assert verified_claims is not None

    # Verifier should see both claims from both VCs
    assert "roleName" in verified_claims
    assert "department" in verified_claims
    assert "modelHash" in verified_claims

    # Claims should have metadata
    assert verified_claims["roleName"]["value"] == "PortfolioManager"
    assert verified_claims["roleName"]["vcId"] == "urn:uuid:role-123"
    assert verified_claims["roleName"]["issuerDID"] == authority_did

    assert verified_claims["modelHash"]["value"] == "sha3-256-ai-model-hash-xyz"
    assert verified_claims["modelHash"]["vcId"] == "urn:uuid:capability-456"


@pytest.mark.asyncio
async def test_workflow_with_peer_reputation_vc():
    """
    Workflow where another agent issues a Reputation VC.
    
    Reputation VCs are special:
    - Can only be issued by peer agents (lifecycleStatus=="active", not in root_trust)
    - Score must be in range 0-100
    """

    issuer_agent = "did:web:agents.example.com:agents:agent-peer-001"
    subject_agent = "did:web:agents.example.com:agents:agent-subject-001"
    verifier = "did:web:banking.example.com:verifier:v1"

    # Issue Reputation VC from peer
    reputation_vc_request = {
        "issuerDID": issuer_agent,
        "subjectDID": subject_agent,
        "credentialType": "ReputationVC",
        "trustDomain": "peer-network",
        "claims": {
            "score": 85,
            "dimension": "data_quality"
        }
    }

    with patch("vc_issuance._run_issuance_pipeline") as mock_issue:
        reputation_vc = {
            "id": "urn:uuid:reputation-789",
            "type": ["VerifiableCredential", "ReputationVC"],
            "issuer": {"id": issuer_agent},
            "issuanceDate": datetime.now(timezone.utc).isoformat(),
            "expirationDate": (datetime.now(timezone.utc) + timedelta(days=180)).isoformat(),
            "credentialSubject": {
                "id": subject_agent,
                "score": 85,
                "dimension": "data_quality"
            },
            "credentialStatus": {
                "statusListCredential": "https://status.example.com/reputation-list",
                "statusListIndex": 30
            },
            "proof": {
                "type": "Ed25519Signature2020",
                "proofValue": "peer_signature_789"
            }
        }
        mock_issue.return_value = (True, reputation_vc)

        from vc_issuance import issue_credential
        success, issued_vc = await issue_credential(reputation_vc_request)
        assert success

    # Verify the reputation VC
    nonce = secrets.token_hex(32)

    import json
    import base64

    vp_payload = {
        "iss": subject_agent,
        "proof": {"challenge": nonce},
        "verifiableCredential": [issued_vc]
    }

    header = {"alg": "EdDSA", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(vp_payload).encode()).decode().rstrip("=")
    sig_b64 = base64.urlsafe_b64encode(b"sig").decode().rstrip("=")
    vp_jwt = f"{header_b64}.{payload_b64}.{sig_b64}"

    with patch("verification_service.services.vp_sig_verifier.verify_vp_signature", new_callable=AsyncMock) as mock_vp_sig:
        with patch("verification_service.services.nonce_validator.validate_nonce", new_callable=AsyncMock):
            with patch("verification_service.services.vc_sig_verifier.verify_vc_signatures", new_callable=AsyncMock):
                with patch("verification_service.services.trust_anchor_checker.validate_issuers", new_callable=AsyncMock):
                    with patch("verification_service.services.revocation_checker.check_revocation_status", new_callable=AsyncMock):
                        with patch("verification_service.services.expiry_checker.check_expiry", new_callable=AsyncMock):
                            mock_vp_sig.return_value = (subject_agent, vp_payload)

                            from verification_service.services.pipeline import verify_presentation

                            valid, verified_claims, failed_step, reason = await verify_presentation(
                                vp_jwt,
                                nonce,
                                verifier
                            )

    assert valid is True
    assert "score" in verified_claims
    assert verified_claims["score"]["value"] == 85


@pytest.mark.asyncio
async def test_workflow_failure_unauthorized_issuer():
    """
    Negative test: Issuer is not authorized to issue this credential type.
    
    Should fail at trust anchor validation step.
    """

    unauthorized_issuer = "did:web:random-service.example.com:issuer"
    subject = "did:web:agents.example.com:agents:agent-test"
    verifier = "did:web:verifier.example.com:verifier:v1"

    # Try to issue credential (would fail in real scenario)
    with patch("vc_issuance._run_issuance_pipeline") as mock_issue:
        vc = {
            "id": "urn:uuid:unauthorized-001",
            "type": ["VerifiableCredential", "RoleVC"],
            "issuer": {"id": unauthorized_issuer},
            "credentialSubject": {"id": subject, "roleName": "Executive"},
            "proof": {"type": "Ed25519Signature2020", "proofValue": "sig"}
        }
        mock_issue.return_value = (True, vc)

        from vc_issuance import issue_credential
        success, issued_vc = await issue_credential({
            "issuerDID": unauthorized_issuer,
            "subjectDID": subject,
            "credentialType": "RoleVC",
            "trustDomain": "finance",
            "claims": {"roleName": "Executive"}
        })

    # Create VP
    import json
    import base64

    nonce = secrets.token_hex(32)
    vp_payload = {
        "iss": subject,
        "proof": {"challenge": nonce},
        "verifiableCredential": [issued_vc]
    }

    header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "EdDSA"}).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(vp_payload).encode()).decode().rstrip("=")
    vp_jwt = f"{header_b64}.{payload_b64}.sig"

    # Verify should fail at trust anchor step
    with patch("verification_service.services.vp_sig_verifier.verify_vp_signature", new_callable=AsyncMock) as mock_vp_sig:
        with patch("verification_service.services.nonce_validator.validate_nonce", new_callable=AsyncMock):
            with patch("verification_service.services.vc_sig_verifier.verify_vc_signatures", new_callable=AsyncMock):
                with patch("verification_service.services.trust_anchor_checker.validate_issuers", new_callable=AsyncMock) as mock_ta:
                    from verification_service.services.pipeline import VerificationError
                    mock_vp_sig.return_value = (subject, vp_payload)
                    mock_ta.side_effect = VerificationError("Issuer not authorized for RoleVC in finance domain")

                    from verification_service.services.pipeline import verify_presentation

                    valid, verified_claims, failed_step, reason = await verify_presentation(
                        vp_jwt,
                        nonce,
                        verifier
                    )

    assert valid is False
    assert failed_step == "TRUST_ANCHOR"
    assert "authorized" in reason.lower()
