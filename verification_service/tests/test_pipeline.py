"""
tests/test_pipeline.py
Tests for the verification pipeline.
"""

import pytest
from unittest.mock import AsyncMock, patch
import json
import base64

from services.pipeline import verify_presentation, verify_credential, _decode_vc_jwt, _merge_vc_claims


@pytest.mark.asyncio
async def test_verify_presentation_success(sample_vp_payload):
    """Successful presentation verification."""
    # Create a mock VP JWT
    vp_jwt = _create_mock_jwt(sample_vp_payload)

    with patch("services.vp_sig_verifier.verify_vp_signature", new_callable=AsyncMock) as mock_vp_sig:
        with patch("services.nonce_validator.validate_nonce", new_callable=AsyncMock) as mock_nonce:
            with patch("services.vc_sig_verifier.verify_vc_signatures", new_callable=AsyncMock) as mock_vc_sig:
                with patch("services.trust_anchor_checker.validate_issuers", new_callable=AsyncMock) as mock_ta:
                    with patch("services.revocation_checker.check_revocation_status", new_callable=AsyncMock) as mock_revoke:
                        with patch("services.expiry_checker.check_expiry", new_callable=AsyncMock) as mock_expiry:
                            mock_vp_sig.return_value = ("did:web:agent", sample_vp_payload)

                            valid, claims, failed_step, reason = await verify_presentation(
                                vp_jwt,
                                "a" * 64,
                                "did:web:verifier"
                            )

                            assert valid is True
                            assert failed_step is None
                            assert reason is None
                            assert claims is not None
                            assert "roleName" in claims

                            # Verify all steps were called
                            mock_vp_sig.assert_called_once()
                            mock_nonce.assert_called_once()
                            mock_vc_sig.assert_called_once()
                            mock_ta.assert_called_once()
                            mock_revoke.assert_called_once()
                            mock_expiry.assert_called_once()


@pytest.mark.asyncio
async def test_verify_presentation_fails_at_vp_sig():
    """Presentation verification fails at VP signature step."""
    vp_jwt = "invalid.jwt.here"

    with patch("services.vp_sig_verifier.verify_vp_signature", new_callable=AsyncMock) as mock_vp_sig:
        from services.vp_sig_verifier import VerificationError
        mock_vp_sig.side_effect = VerificationError("Bad signature")

        valid, claims, failed_step, reason = await verify_presentation(
            vp_jwt,
            "a" * 64,
            "did:web:verifier"
        )

        assert valid is False
        assert failed_step == "VP_SIGNATURE"
        assert "Bad signature" in reason


@pytest.mark.asyncio
async def test_verify_presentation_fails_at_revocation():
    """Presentation verification fails at revocation step."""
    sample_vp = {
        "iss": "did:web:agent",
        "proof": {"challenge": "a" * 64},
        "verifiableCredential": [{"id": "urn:uuid:123"}]
    }

    with patch("services.vp_sig_verifier.verify_vp_signature", new_callable=AsyncMock) as mock_vp_sig:
        with patch("services.nonce_validator.validate_nonce", new_callable=AsyncMock):
            with patch("services.vc_sig_verifier.verify_vc_signatures", new_callable=AsyncMock):
                with patch("services.trust_anchor_checker.validate_issuers", new_callable=AsyncMock):
                    with patch("services.revocation_checker.check_revocation_status", new_callable=AsyncMock) as mock_revoke:
                        mock_vp_sig.return_value = ("did:web:agent", sample_vp)
                        mock_revoke.side_effect = ValueError("Credential revoked")

                        valid, claims, failed_step, reason = await verify_presentation(
                            "dummy.jwt.here",
                            "a" * 64,
                            "did:web:verifier"
                        )

                        assert valid is False
                        assert failed_step == "REVOCATION"
                        assert "revoked" in reason


@pytest.mark.asyncio
async def test_verify_credential_success():
    """Successful standalone credential verification."""
    vc = {
        "id": "urn:uuid:123",
        "type": ["VerifiableCredential", "RoleVC"],
        "issuer": {"id": "did:web:issuer"},
        "expirationDate": "2025-09-15T00:00:00Z",
        "credentialSubject": {"id": "did:web:subject", "roleName": "Analyst"}
    }

    vc_jwt = _create_mock_jwt(vc)

    with patch("services.vc_sig_verifier.verify_vc_signatures", new_callable=AsyncMock):
        with patch("services.trust_anchor_checker.validate_issuers", new_callable=AsyncMock):
            with patch("services.revocation_checker.check_revocation_status", new_callable=AsyncMock):
                with patch("services.expiry_checker.check_expiry", new_callable=AsyncMock):
                    valid, claims, issuer_did, expires_at, failed_step, reason = await verify_credential(vc_jwt)

                    assert valid is True
                    assert issuer_did == "did:web:issuer"
                    assert expires_at == "2025-09-15T00:00:00Z"
                    assert claims == {"id": "did:web:subject", "roleName": "Analyst"}
                    assert failed_step is None


@pytest.mark.asyncio
async def test_verify_credential_fails_at_sig():
    """Standalone credential verification fails at signature step."""
    vc = {
        "id": "urn:uuid:123",
        "type": ["VerifiableCredential", "RoleVC"],
        "issuer": {"id": "did:web:issuer"},
        "expirationDate": "2025-09-15T00:00:00Z",
        "credentialSubject": {"id": "did:web:subject", "roleName": "Analyst"}
    }

    vc_jwt = _create_mock_jwt(vc)

    with patch("services.vc_sig_verifier.verify_vc_signatures", new_callable=AsyncMock) as mock_sig:
        from services.vc_sig_verifier import VerificationError
        mock_sig.side_effect = VerificationError("Bad VC signature")

        valid, claims, issuer_did, expires_at, failed_step, reason = await verify_credential(vc_jwt)

        assert valid is False
        assert failed_step == "VC_SIGNATURE"


def test_merge_vc_claims():
    """Test merging claims from multiple VCs."""
    vcs = [
        {
            "id": "urn:uuid:123",
            "issuer": {"id": "did:web:issuer1"},
            "expirationDate": "2025-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:web:subject",
                "roleName": "Analyst",
                "department": "Finance"
            }
        },
        {
            "id": "urn:uuid:456",
            "issuer": {"id": "did:web:issuer2"},
            "expirationDate": "2025-02-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:web:subject",
                "certificationLevel": "Senior"
            }
        }
    ]

    merged = _merge_vc_claims(vcs)

    assert "roleName" in merged
    assert "department" in merged
    assert "certificationLevel" in merged

    assert merged["roleName"]["value"] == "Analyst"
    assert merged["roleName"]["vcId"] == "urn:uuid:123"
    assert merged["roleName"]["issuerDID"] == "did:web:issuer1"

    assert merged["certificationLevel"]["value"] == "Senior"
    assert merged["certificationLevel"]["vcId"] == "urn:uuid:456"


def test_decode_vc_jwt():
    """Test decoding a VC JWT."""
    vc = {
        "id": "urn:uuid:123",
        "type": ["VerifiableCredential", "RoleVC"],
        "issuer": {"id": "did:web:issuer"},
        "credentialSubject": {"roleName": "Analyst"}
    }

    vc_jwt = _create_mock_jwt(vc)
    decoded = _decode_vc_jwt(vc_jwt)

    assert decoded["id"] == "urn:uuid:123"
    assert decoded["issuer"]["id"] == "did:web:issuer"
    assert decoded["credentialSubject"]["roleName"] == "Analyst"


# ── Helper Functions ───────────────────────────────────────────────────────────

def _create_mock_jwt(payload: dict) -> str:
    """Create a mock JWT without a real signature."""
    import json
    import base64

    header = {"alg": "EdDSA", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature_b64 = base64.urlsafe_b64encode(b"mocksignature").decode().rstrip("=")

    return f"{header_b64}.{payload_b64}.{signature_b64}"
