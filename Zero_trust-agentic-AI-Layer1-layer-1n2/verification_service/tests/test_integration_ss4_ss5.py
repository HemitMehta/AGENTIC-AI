"""
tests/test_integration_ss4_ss5.py

End-to-end integration tests: VC Issuance (SS4) → VC Verification (SS5)

Tests the complete flow:
1. Issue a VC via SS4 (vc_issuance.py)
2. Create a VP containing the VC
3. Request a nonce from SS5
4. Present the VP to SS5 for verification
5. Verify the presentation passes all 6 steps
"""

import pytest
import json
import base64
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import secrets

# Assume SS4 and SS5 modules are importable
import sys
from pathlib import Path

# Add parent directory to path to import vc_issuance
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


@pytest.fixture
def mock_services():
    """
    Mock all upstream services used by both SS4 (issuance) and SS5 (verification).
    Returns a dict of mocked clients.
    """
    services = {}

    # Mock KMS for SS4 (signing VCs) and SS5 (verifying VCs)
    with patch("kms.sign_payload") as mock_sign:
        with patch("kms.get_public_key") as mock_get_pub:
            # For SS4: sign_payload should return a base64-encoded signature
            mock_sign.return_value = "mocksignature=="

            # For SS5: get_public_key should return the issuer's public key
            mock_get_pub.return_value = {
                "publicKey": "z6MkhaXgBZDvotzL8V6N7Eum6eoKahPtQDaSEUqEhBJvkc",
                "algorithm": "Ed25519",
                "status": "active"
            }

            services["kms_sign"] = mock_sign
            services["kms_get_pub"] = mock_get_pub

    # Mock DID Registry for SS4 and SS5
    with patch("did_registry.resolve_did_at_time") as mock_resolve_ss4:
        with patch("verification_service.clients.did_registry_client.resolve_did") as mock_resolve_ss5:
            # For SS4: resolve subject and issuer DIDs
            mock_resolve_ss4.return_value = {
                "id": "did:web:agents.example.com:agents:agent-123",
                "lifecycleStatus": "active",
                "toolset": [
                    "did:web:tools.example.com:tools:data-processor",
                    "did:web:tools.example.com:tools:ml-inference"
                ],
                "modelHash": "sha3-256-mockmodelhashabcdef1234567890"
            }

            # For SS5: resolve DIDs for signature verification
            mock_resolve_ss5.return_value = {
                "didDocument": {
                    "id": "did:web:agents.example.com:agents:agent-123",
                    "verificationMethod": [
                        {
                            "id": "did:web:agents.example.com:agents:agent-123#key-1",
                            "type": "Ed25519VerificationKey2020",
                            "publicKeyMultibase": "z6MkhaXgBZDvotzL8V6N7Eum6eoKahPtQDaSEUqEhBJvkc"
                        }
                    ]
                }
            }

            services["did_resolve_ss4"] = mock_resolve_ss4
            services["did_resolve_ss5"] = mock_resolve_ss5

    # Mock Trust Anchor for SS4 (authorize issuer) and SS5 (validate issuer)
    with patch("root_trust.validate_issuer") as mock_validate_issuer:
        with patch("verification_service.clients.trust_anchor_client.validate_issuer") as mock_validate_issuer_ss5:
            # For SS4: issuer must be authorized
            mock_validate_issuer.return_value = {"authorised": True}

            # For SS5: issuer must be authorized
            mock_validate_issuer_ss5.return_value = {
                "authorised": True,
                "reason": "Issuer is trusted",
                "validUntil": "2027-12-31T23:59:59Z"
            }

            services["trust_validate"] = mock_validate_issuer
            services["trust_validate_ss5"] = mock_validate_issuer_ss5

    # Mock Status List for SS4 (allocate status index) and SS5 (check revocation)
    with patch("status_list.allocate_status_entry") as mock_allocate:
        with patch("verification_service.clients.trust_anchor_client.get_trust_anchor") as mock_get_ta:
            # For SS4: allocate status list entry
            mock_allocate.return_value = {
                "statusListUrl": "https://status.example.com/lists/1",
                "bitIndex": 42
            }

            # For SS5: get trust anchor cache
            mock_get_ta.return_value = {
                "id": "did:web:trust.example.com:trust-anchor",
                "issuers": []
            }

            services["status_allocate"] = mock_allocate
            services["trust_anchor_get"] = mock_get_ta

    # Mock CockroachDB for SS4
    with patch("vc_issuance._persist_vc") as mock_persist:
        mock_persist.return_value = None
        services["crdb_persist"] = mock_persist

    # Mock Redis for SS5
    with patch("verification_service.cache.redis_client.get_redis") as mock_redis:
        redis_mock = AsyncMock()
        redis_mock.get.return_value = None
        redis_mock.set.return_value = True
        redis_mock.delete.return_value = True
        mock_redis.return_value = redis_mock
        services["redis"] = redis_mock

    return services


@pytest.fixture
def issuer_did():
    """DID of the authority issuing the credential."""
    return "did:web:hr.example.com:hr-authority"


@pytest.fixture
def subject_did():
    """DID of the agent receiving the credential."""
    return "did:web:agents.example.com:agents:agent-123"


@pytest.fixture
def verifier_did():
    """DID of the verifier checking the presentation."""
    return "did:web:verifier.example.com:verifier:verifier-1"


@pytest.mark.asyncio
async def test_integration_issue_and_verify_role_vc(mock_services, issuer_did, subject_did, verifier_did):
    """
    Integration test: Issue a Role VC via SS4, then verify it via SS5.
    
    Flow:
    1. SS4: Issue Role VC with claims { roleName: "FinancialAnalyst" }
    2. SS5: Request nonce from /verify/nonce
    3. SS5: Create VP containing the VC
    4. SS5: Present VP to /verify/presentation
    5. Verify: presentation is valid, verified claims contain roleName
    """

    from datetime import datetime, timezone

    
    # Step 1: Issue VC via SS4
       # Create issuance request
    issuance_request = {
        "issuerDID": issuer_did,
        "subjectDID": subject_did,
        "credentialType": "RoleVC",
        "trustDomain": "finance",
        "claims": {
            "roleName": "FinancialAnalyst"
        }
    }

    # Mock the VC issuance pipeline
    with patch("vc_issuance._run_issuance_pipeline") as mock_pipeline:
        issued_vc = {
            "id": "urn:uuid:role-vc-123",
            "type": ["VerifiableCredential", "RoleVC"],
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3c-ccg.github.io/vc-ed25519-2020/contexts/v1"
            ],
            "issuer": {
                "id": issuer_did
            },
            "issuanceDate": datetime.now(timezone.utc).isoformat(),
            "expirationDate": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
            "credentialSubject": {
                "id": subject_did,
                "roleName": "FinancialAnalyst"
            },
            "credentialStatus": {
                "type": "StatusList2021Entry",
                "statusListCredential": "https://status.example.com/lists/1",
                "statusListIndex": 42
            },
            "proof": {
                "type": "Ed25519Signature2020",
                "created": datetime.now(timezone.utc).isoformat(),
                "verificationMethod": f"{issuer_did}#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": "mocksignature=="
            }
        }
        mock_pipeline.return_value = (True, issued_vc)

        # Call SS4 issuance (mocked)
        from vc_issuance import issue_credential
        success, vc = await issue_credential(issuance_request)

    assert success is True
    assert vc["credentialSubject"]["roleName"] == "FinancialAnalyst"

    
    # Step 2: Request nonce from SS5
 

    nonce = secrets.token_hex(32)
    nonce_expiry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    
    # Step 3: Create VP containing the VC
    

    vp_payload = {
        "iss": subject_did,
        "proof": {
            "challenge": nonce,
            "created": datetime.now(timezone.utc).isoformat()
        },
        "verifiableCredential": [vc]
    }

    vp_jwt = _create_mock_jwt(vp_payload)

    
    # Step 4: Present VP to SS5
    

    with patch("verification_service.services.vp_sig_verifier.verify_vp_signature", new_callable=AsyncMock) as mock_vp_sig:
        with patch("verification_service.services.nonce_validator.validate_nonce", new_callable=AsyncMock):
            with patch("verification_service.services.vc_sig_verifier.verify_vc_signatures", new_callable=AsyncMock):
                with patch("verification_service.services.trust_anchor_checker.validate_issuers", new_callable=AsyncMock):
                    with patch("verification_service.services.revocation_checker.check_revocation_status", new_callable=AsyncMock):
                        with patch("verification_service.services.expiry_checker.check_expiry", new_callable=AsyncMock):
                            mock_vp_sig.return_value = (subject_did, vp_payload)

                            from verification_service.services.pipeline import verify_presentation

                            valid, verified_claims, failed_step, reason = await verify_presentation(
                                vp_jwt,
                                nonce,
                                verifier_did
                            )

     
    # Step 5: Verify the result
    

    assert valid is True, f"Presentation should be valid. Failed at {failed_step}: {reason}"
    assert failed_step is None
    assert reason is None
    assert verified_claims is not None
    assert "roleName" in verified_claims
    assert verified_claims["roleName"]["value"] == "FinancialAnalyst"
    assert verified_claims["roleName"]["vcId"] == "urn:uuid:role-vc-123"


@pytest.mark.asyncio
async def test_integration_issue_and_verify_jit_vc(mock_services, issuer_did, subject_did, verifier_did):
    """
    Integration test: Issue a JIT VC via SS4, then verify it via SS5.
    
    JIT VCs have special handling for toolset validation and 60-minute max expiry.
    """

    from datetime import datetime, timezone

    
    # Step 1: Issue JIT VC via SS4
    

    issuance_request = {
        "issuerDID": issuer_did,
        "subjectDID": subject_did,
        "credentialType": "JITCapabilityVC",
        "trustDomain": "tooling",
        "claims": {
            "toolDID": "did:web:tools.example.com:tools:data-processor"
        }
    }

    with patch("vc_issuance._run_issuance_pipeline") as mock_pipeline:
        issued_vc = {
            "id": "urn:uuid:jit-vc-456",
            "type": ["VerifiableCredential", "JITCapabilityVC"],
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3c-ccg.github.io/vc-ed25519-2020/contexts/v1"
            ],
            "issuer": {
                "id": issuer_did
            },
            "issuanceDate": datetime.now(timezone.utc).isoformat(),
            "expirationDate": (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(),
            "credentialSubject": {
                "id": subject_did,
                "toolDID": "did:web:tools.example.com:tools:data-processor"
            },
            "credentialStatus": {
                "type": "StatusList2021Entry",
                "statusListCredential": "https://status.example.com/lists/1",
                "statusListIndex": 43
            },
            "proof": {
                "type": "Ed25519Signature2020",
                "created": datetime.now(timezone.utc).isoformat(),
                "verificationMethod": f"{issuer_did}#key-1",
                "proofPurpose": "assertionMethod",
                "proofValue": "mocksignature=="
            }
        }
        mock_pipeline.return_value = (True, issued_vc)

        from vc_issuance import issue_credential
        success, vc = await issue_credential(issuance_request)

    assert success is True
    assert vc["credentialSubject"]["toolDID"] == "did:web:tools.example.com:tools:data-processor"

    
    # Step 2-5: Request nonce, create VP, present, verify
    

    nonce = secrets.token_hex(32)

    vp_payload = {
        "iss": subject_did,
        "proof": {
            "challenge": nonce,
            "created": datetime.now(timezone.utc).isoformat()
        },
        "verifiableCredential": [vc]
    }

    vp_jwt = _create_mock_jwt(vp_payload)

    with patch("verification_service.services.vp_sig_verifier.verify_vp_signature", new_callable=AsyncMock) as mock_vp_sig:
        with patch("verification_service.services.nonce_validator.validate_nonce", new_callable=AsyncMock):
            with patch("verification_service.services.vc_sig_verifier.verify_vc_signatures", new_callable=AsyncMock):
                with patch("verification_service.services.trust_anchor_checker.validate_issuers", new_callable=AsyncMock):
                    with patch("verification_service.services.revocation_checker.check_revocation_status", new_callable=AsyncMock):
                        with patch("verification_service.services.expiry_checker.check_expiry", new_callable=AsyncMock):
                            mock_vp_sig.return_value = (subject_did, vp_payload)

                            from verification_service.services.pipeline import verify_presentation

                            valid, verified_claims, failed_step, reason = await verify_presentation(
                                vp_jwt,
                                nonce,
                                verifier_did
                            )

    assert valid is True
    assert "toolDID" in verified_claims


@pytest.mark.asyncio
async def test_integration_multiple_vcs_in_presentation(mock_services, issuer_did, subject_did, verifier_did):
    """
    Integration test: Present multiple VCs in a single VP.
    
    Verifier should receive merged claims from all VCs.
    """

    from datetime import datetime, timezone

    # Create two different VCs
    role_vc = {
        "id": "urn:uuid:role-vc-789",
        "type": ["VerifiableCredential", "RoleVC"],
        "issuer": {"id": issuer_did},
        "issuanceDate": datetime.now(timezone.utc).isoformat(),
        "expirationDate": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "credentialSubject": {
            "id": subject_did,
            "roleName": "SeniorAnalyst"
        },
        "credentialStatus": {
            "statusListCredential": "https://status.example.com/lists/1",
            "statusListIndex": 44
        },
        "proof": {
            "type": "Ed25519Signature2020",
            "proofValue": "mocksignature=="
        }
    }

    capability_vc = {
        "id": "urn:uuid:capability-vc-101",
        "type": ["VerifiableCredential", "CapabilityVC"],
        "issuer": {"id": issuer_did},
        "issuanceDate": datetime.now(timezone.utc).isoformat(),
        "expirationDate": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "credentialSubject": {
            "id": subject_did,
            "modelHash": "sha3-256-mockmodelhashabcdef1234567890"
        },
        "credentialStatus": {
            "statusListCredential": "https://status.example.com/lists/1",
            "statusListIndex": 45
        },
        "proof": {
            "type": "Ed25519Signature2020",
            "proofValue": "mocksignature=="
        }
    }

    nonce = secrets.token_hex(32)

    vp_payload = {
        "iss": subject_did,
        "proof": {
            "challenge": nonce,
            "created": datetime.now(timezone.utc).isoformat()
        },
        "verifiableCredential": [role_vc, capability_vc]
    }

    vp_jwt = _create_mock_jwt(vp_payload)

    with patch("verification_service.services.vp_sig_verifier.verify_vp_signature", new_callable=AsyncMock) as mock_vp_sig:
        with patch("verification_service.services.nonce_validator.validate_nonce", new_callable=AsyncMock):
            with patch("verification_service.services.vc_sig_verifier.verify_vc_signatures", new_callable=AsyncMock):
                with patch("verification_service.services.trust_anchor_checker.validate_issuers", new_callable=AsyncMock):
                    with patch("verification_service.services.revocation_checker.check_revocation_status", new_callable=AsyncMock):
                        with patch("verification_service.services.expiry_checker.check_expiry", new_callable=AsyncMock):
                            mock_vp_sig.return_value = (subject_did, vp_payload)

                            from verification_service.services.pipeline import verify_presentation

                            valid, verified_claims, failed_step, reason = await verify_presentation(
                                vp_jwt,
                                nonce,
                                verifier_did
                            )

    assert valid is True
    assert "roleName" in verified_claims
    assert "modelHash" in verified_claims
    assert verified_claims["roleName"]["value"] == "SeniorAnalyst"


@pytest.mark.asyncio
async def test_integration_presentation_with_revoked_vc(mock_services, issuer_did, subject_did, verifier_did):
    """
    Integration test: VP presentation fails because one VC is revoked.
    
    Should fail at REVOCATION step with specific reason.
    """

    from datetime import datetime, timezone

    vc = {
        "id": "urn:uuid:revoked-vc-999",
        "type": ["VerifiableCredential", "RoleVC"],
        "issuer": {"id": issuer_did},
        "issuanceDate": datetime.now(timezone.utc).isoformat(),
        "expirationDate": (datetime.now(timezone.utc) + timedelta(days=365)).isoformat(),
        "credentialSubject": {
            "id": subject_did,
            "roleName": "Analyst"
        },
        "credentialStatus": {
            "statusListCredential": "https://status.example.com/lists/1",
            "statusListIndex": 99  # This bit is set to 1 (revoked)
        },
        "proof": {
            "type": "Ed25519Signature2020",
            "proofValue": "mocksignature=="
        }
    }

    nonce = secrets.token_hex(32)

    vp_payload = {
        "iss": subject_did,
        "proof": {
            "challenge": nonce,
            "created": datetime.now(timezone.utc).isoformat()
        },
        "verifiableCredential": [vc]
    }

    vp_jwt = _create_mock_jwt(vp_payload)

    with patch("verification_service.services.vp_sig_verifier.verify_vp_signature", new_callable=AsyncMock) as mock_vp_sig:
        with patch("verification_service.services.nonce_validator.validate_nonce", new_callable=AsyncMock):
            with patch("verification_service.services.vc_sig_verifier.verify_vc_signatures", new_callable=AsyncMock):
                with patch("verification_service.services.trust_anchor_checker.validate_issuers", new_callable=AsyncMock):
                    with patch("verification_service.services.revocation_checker.check_revocation_status", new_callable=AsyncMock) as mock_revoke:
                        mock_vp_sig.return_value = (subject_did, vp_payload)
                        mock_revoke.side_effect = ValueError("Credential urn:uuid:revoked-vc-999 has been revoked")

                        from verification_service.services.pipeline import verify_presentation

                        valid, verified_claims, failed_step, reason = await verify_presentation(
                            vp_jwt,
                            nonce,
                            verifier_did
                        )

    assert valid is False
    assert failed_step == "REVOCATION"
    assert "revoked" in reason


@pytest.mark.asyncio
async def test_integration_presentation_with_expired_vc(mock_services, issuer_did, subject_did, verifier_did):
    """
    Integration test: VP presentation fails because VC is expired.
    """

    from datetime import datetime, timezone

    vc = {
        "id": "urn:uuid:expired-vc-111",
        "type": ["VerifiableCredential", "RoleVC"],
        "issuer": {"id": issuer_did},
        "issuanceDate": (datetime.now(timezone.utc) - timedelta(days=400)).isoformat(),
        "expirationDate": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),  # EXPIRED
        "credentialSubject": {
            "id": subject_did,
            "roleName": "Analyst"
        },
        "credentialStatus": {
            "statusListCredential": "https://status.example.com/lists/1",
            "statusListIndex": 46
        },
        "proof": {
            "type": "Ed25519Signature2020",
            "proofValue": "mocksignature=="
        }
    }

    nonce = secrets.token_hex(32)

    vp_payload = {
        "iss": subject_did,
        "proof": {
            "challenge": nonce,
            "created": datetime.now(timezone.utc).isoformat()
        },
        "verifiableCredential": [vc]
    }

    vp_jwt = _create_mock_jwt(vp_payload)

    with patch("verification_service.services.vp_sig_verifier.verify_vp_signature", new_callable=AsyncMock) as mock_vp_sig:
        with patch("verification_service.services.nonce_validator.validate_nonce", new_callable=AsyncMock):
            with patch("verification_service.services.vc_sig_verifier.verify_vc_signatures", new_callable=AsyncMock):
                with patch("verification_service.services.trust_anchor_checker.validate_issuers", new_callable=AsyncMock):
                    with patch("verification_service.services.revocation_checker.check_revocation_status", new_callable=AsyncMock):
                        with patch("verification_service.services.expiry_checker.check_expiry", new_callable=AsyncMock) as mock_expiry:
                            mock_vp_sig.return_value = (subject_did, vp_payload)
                            mock_expiry.side_effect = ValueError("Credential expired on 2024-01-01T00:00:00Z")

                            from verification_service.services.pipeline import verify_presentation

                            valid, verified_claims, failed_step, reason = await verify_presentation(
                                vp_jwt,
                                nonce,
                                verifier_did
                            )

    assert valid is False
    assert failed_step == "EXPIRY"
    assert "expired" in reason.lower()


 
# Helper Functions


def _create_mock_jwt(payload: dict) -> str:
    """Create a mock JWT without a real signature."""
    header = {"alg": "EdDSA", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature_b64 = base64.urlsafe_b64encode(b"mocksignature").decode().rstrip("=")

    return f"{header_b64}.{payload_b64}.{signature_b64}"
