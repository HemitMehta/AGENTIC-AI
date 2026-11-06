"""
routers/presentation.py

Presentation verification endpoint: POST /verify/presentation
"""

import logging
from fastapi import APIRouter

from models.requests import PresentationRequest
from models.responses import VerificationResponse
from services.pipeline import verify_presentation

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/verify", tags=["verification"])


@router.post("/presentation", response_model=VerificationResponse)
async def verify_vp(request: PresentationRequest) -> VerificationResponse:
    """
    Verify a Verifiable Presentation and all credentials within it.

    Runs the full 6-step pipeline:
    1. VP signature verification
    2. Nonce validation
    3. Per-VC signature verification
    4. Trust anchor validation
    5. Revocation status check
    6. Expiry check

    Args:
        request: { vp_jwt, nonce, verifierDID }

    Returns:
        { valid, verifiedClaims|null, failedStep|null, reason|null }
    """
    try:
        valid, claims, failed_step, reason = await verify_presentation(
            request.vp_jwt,
            request.nonce,
            request.verifierDID
        )

        return VerificationResponse(
            valid=valid,
            verifiedClaims=claims,
            failedStep=failed_step,
            reason=reason
        )

    except Exception as e:
        logger.error(f"Unexpected error in presentation verification: {e}", exc_info=True)
        return VerificationResponse(
            valid=False,
            verifiedClaims=None,
            failedStep="INTERNAL_ERROR",
            reason=str(e)
        )
