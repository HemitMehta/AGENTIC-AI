"""
services/pipeline.py
Verification Pipeline Orchestrator

Runs all 6 verification steps in sequence. Steps are executed sequentially
with early exit — if any step fails, later steps are not attempted.
"""

import logging
import json
import base64
from typing import Dict, Any, Tuple, Optional, List

from services import vp_sig_verifier, nonce_validator, vc_sig_verifier
from services import trust_anchor_checker, revocation_checker, expiry_checker

logger = logging.getLogger(__name__)


class PipelineError(Exception):
    """Raised when verification pipeline fails at a specific step."""
    
    def __init__(self, failed_step: str, reason: str):
        self.failed_step = failed_step
        self.reason = reason
        super().__init__(f"{failed_step}: {reason}")


async def verify_presentation(
    vp_jwt: str,
    nonce: str,
    verifier_did: str
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    """
    Execute the full 6-step verification pipeline for a VP presentation.

    Pipeline steps (executed in order):
    1. VP Signature Verification
    2. Nonce Validation
    3. Per-VC Signature Verification
    4. Trust Anchor Validation
    5. Revocation Status Check
    6. Expiry Check

    Args:
        vp_jwt:       Signed VP JWT
        nonce:        Nonce value used in presentation
        verifier_did: DID of the verifier

    Returns:
        (valid: bool, verifiedClaims: dict|None, failedStep: str|None, reason: str|None)
        - valid=true: all steps passed, verifiedClaims contains merged claims
        - valid=false: failedStep and reason describe which step failed
    """
    try:
        # Step 1: VP Signature Verification
        logger.info("Pipeline: Step 1 - VP Signature Verification")
        issuer_did, vp_payload = await vp_sig_verifier.verify_vp_signature(vp_jwt)
        logger.info(f"✓ Step 1 passed: VP signed by {issuer_did}")

        # Step 2: Nonce Validation
        logger.info("Pipeline: Step 2 - Nonce Validation")
        await nonce_validator.validate_nonce(nonce, verifier_did, vp_payload)
        logger.info("✓ Step 2 passed: Nonce valid and deleted")

        # Extract VCs from VP
        vcs = _extract_vcs_from_vp(vp_payload)
        logger.info(f"Extracted {len(vcs)} VCs from presentation")

        # Step 3: Per-VC Signature Verification
        logger.info("Pipeline: Step 3 - Per-VC Signature Verification")
        await vc_sig_verifier.verify_vc_signatures(vcs)
        logger.info(f"✓ Step 3 passed: All {len(vcs)} VC signatures verified")

        # Step 4: Trust Anchor Validation
        logger.info("Pipeline: Step 4 - Trust Anchor Validation")
        await trust_anchor_checker.validate_issuers(vcs)
        logger.info("✓ Step 4 passed: All issuers authorized")

        # Step 5: Revocation Status Check
        logger.info("Pipeline: Step 5 - Revocation Status Check")
        await revocation_checker.check_revocation_status(vcs)
        logger.info("✓ Step 5 passed: No VCs revoked")

        # Step 6: Expiry Check
        logger.info("Pipeline: Step 6 - Expiry Check")
        await expiry_checker.check_expiry(vcs)
        logger.info("✓ Step 6 passed: All VCs valid and not expired")

        # All steps passed — merge and return claims
        verified_claims = _merge_vc_claims(vcs)
        logger.info("Pipeline completed successfully")

        return True, verified_claims, None, None

    except PipelineError as e:
        logger.warning(f"Pipeline failed: {e.failed_step} - {e.reason}")
        return False, None, e.failed_step, e.reason
    except Exception as e:
        # Catch any unexpected errors from the service layers
        logger.error(f"Unexpected pipeline error: {e}", exc_info=True)
        return False, None, "UNKNOWN", str(e)


async def verify_credential(vc_jwt, fresh_status: bool = False) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str], Optional[str], Optional[str]]:
    """
    Execute verification for a standalone VC (no VP wrapper).

    Runs steps 3, 4, 5, 6 only (skips VP signature and nonce).

    Args:
        vc_jwt: Signed VC JWT

    Returns:
        (valid: bool, claims: dict|None, issuerDID: str|None, expiresAt: str|None, failedStep: str|None, reason: str|None)
    """
    try:
        # Decode JWT to extract VC
        vc = vc_jwt if isinstance(vc_jwt, dict) else _decode_vc_jwt(vc_jwt)
        vcs = [vc]

        # Step 3: VC Signature Verification
        logger.info("Credential verification: Step 3 - VC Signature Verification")
        await vc_sig_verifier.verify_vc_signatures(vcs)
        logger.info("✓ Step 3 passed: VC signature verified")

        # Step 4: Trust Anchor Validation
        logger.info("Credential verification: Step 4 - Trust Anchor Validation")
        await trust_anchor_checker.validate_issuers(vcs)
        logger.info("✓ Step 4 passed: Issuer authorized")

        # Step 5: Revocation Status Check
        logger.info("Credential verification: Step 5 - Revocation Status Check")
        await revocation_checker.check_revocation_status(vcs, fresh=fresh_status)
        logger.info("✓ Step 5 passed: Not revoked")

        # Step 6: Expiry Check
        logger.info("Credential verification: Step 6 - Expiry Check")
        await expiry_checker.check_expiry(vcs)
        logger.info("✓ Step 6 passed: Not expired")

        # All steps passed
        issuer_did = vc.get("issuer", {}).get("id")
        expires_at = vc.get("expirationDate")
        claims = vc.get("credentialSubject", {})

        logger.info("Credential verification completed successfully")
        return True, claims, issuer_did, expires_at, None, None

    except PipelineError as e:
        logger.warning(f"Credential verification failed: {e.failed_step} - {e.reason}")
        return False, None, None, None, e.failed_step, e.reason
    except Exception as e:
        logger.error(f"Unexpected credential verification error: {e}", exc_info=True)
        return False, None, None, None, "UNKNOWN", str(e)


# ── Internal Helpers ───────────────────────────────────────────────────────────

def _extract_vcs_from_vp(vp_payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract VCs from a VP payload.

    Args:
        vp_payload: Decoded VP JWT payload

    Returns:
        List of VC dictionaries

    Raises:
        PipelineError if extraction fails
    """
    vcs = vp_payload.get("verifiableCredential", [])
    if not vcs:
        raise PipelineError("PRESENTATION", "VP contains no verifiableCredential")

    # VCs may be JWT strings or decoded objects
    decoded_vcs = []
    for vc in vcs:
        if isinstance(vc, str):
            # JWT-encoded VC — decode it
            decoded_vcs.append(_decode_vc_jwt(vc))
        else:
            # Already decoded
            decoded_vcs.append(vc)

    return decoded_vcs


def _decode_vc_jwt(vc_jwt: str) -> Dict[str, Any]:
    """
    Decode a VC JWT (without signature verification — that's done in step 3).

    Args:
        vc_jwt: VC JWT string

    Returns:
        Decoded VC dictionary

    Raises:
        PipelineError if decode fails
    """
    try:
        parts = vc_jwt.split(".")
        if len(parts) != 3:
            raise PipelineError("VC_DECODE", "Invalid JWT format (expected 3 parts)")

        # Decode payload (second part)
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        payload_json = base64.urlsafe_b64decode(payload_b64).decode()
        return json.loads(payload_json)

    except PipelineError:
        raise
    except Exception as e:
        raise PipelineError("VC_DECODE", f"Failed to decode VC JWT: {e}")


def _merge_vc_claims(vcs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Merge claims from all VCs into a flat dictionary.

    Args:
        vcs: List of VC dictionaries

    Returns:
        Flat merged claims dict
    """
    merged = {}

    for vc in vcs:
        vc_id = vc.get("id", "unknown")
        issuer_did = vc.get("issuer", {}).get("id", "unknown")
        expires_at = vc.get("expirationDate")

        credential_subject = vc.get("credentialSubject", {})

        # Merge claims, adding metadata
        for key, value in credential_subject.items():
            if key != "id":  # Skip the subject ID
                merged[key] = {
                    "value": value,
                    "vcId": vc_id,
                    "issuerDID": issuer_did,
                    "expiresAt": expires_at
                }

    return merged
