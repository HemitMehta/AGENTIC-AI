"""
routers/credential.py

Standalone credential verification endpoint: POST /verify/credential
"""

import logging
from fastapi import APIRouter

from models.requests import CredentialRequest
from models.responses import CredentialVerifyResponse
from services.pipeline import verify_credential

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/verify", tags=["verification"])


@router.post("/credential", response_model=CredentialVerifyResponse)
async def verify_vc(request: CredentialRequest) -> CredentialVerifyResponse:
    """
    Verify a standalone Verifiable Credential (without VP wrapper).

    Runs steps 3–6 of the pipeline (skips VP signature and nonce checks):
    3. VC signature verification
    4. Trust anchor validation
    5. Revocation status check
    6. Expiry check

    Args:
        request: { vc_jwt }

    Returns:
        { valid, claims|null, issuerDID|null, expiresAt|null, failedStep|null, reason|null }
    """
    try:
        valid, claims, issuer_did, expires_at, failed_step, reason = await verify_credential(
            request.credential if request.credential is not None else request.vc_jwt,
            fresh_status=request.fresh_status,
        )

        return CredentialVerifyResponse(
            valid=valid,
            claims=claims,
            issuerDID=issuer_did,
            expiresAt=expires_at,
            failedStep=failed_step,
            reason=reason
        )

    except Exception as e:
        logger.error(f"Unexpected error in credential verification: {e}", exc_info=True)
        return CredentialVerifyResponse(
            valid=False,
            claims=None,
            issuerDID=None,
            expiresAt=None,
            failedStep="INTERNAL_ERROR",
            reason=str(e)
        )
