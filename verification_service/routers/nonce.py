"""
routers/nonce.py

Nonce generation endpoint: POST /verify/nonce
"""

import logging
from fastapi import APIRouter, Depends

from models.requests import NonceRequest
from models.responses import NonceResponse
from services.nonce_service import generate_nonce

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/verify", tags=["verification"])


@router.post("/nonce", response_model=NonceResponse)
async def get_nonce(request: NonceRequest) -> NonceResponse:
    """
    Generate a new nonce for use in a presentation verification.

    The nonce is stored in Redis with a configurable TTL (default 300s).
    The verifier must include the nonce in the presentation's proof.challenge.

    Args:
        request: { verifierDID, purpose }

    Returns:
        { nonce, expiresAt }
    """
    nonce, expires_at = await generate_nonce(request.verifierDID, request.purpose)
    return NonceResponse(nonce=nonce, expiresAt=expires_at)
