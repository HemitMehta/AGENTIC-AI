"""
wallet_service/routers/present.py

POST /wallets/:did/present
"""

from fastapi import APIRouter, HTTPException
import logging

from models.requests import PresentRequest
from models.responses import PresentResponse
from services.selective_disclosure import get_credentials_for_presentation
from services.presentation_builder import build_presentation

router = APIRouter(prefix="/wallets", tags=["presentation"])
logger = logging.getLogger(__name__)


@router.post("/{did}/present", response_model=PresentResponse)
async def present(did: str, request: PresentRequest):
    """Present credentials to a verifier."""
    if did != request.agent_did:
        raise HTTPException(400, "Wallet path does not match agent_did")
    try:
        # Selective inclusion
        credentials = await get_credentials_for_presentation(did, request.required_types, request.credential_ids)

        # Build and sign VP
        vp_jwt = await build_presentation(
            did,
            request.required_types,
            request.verifier_did,
            request.nonce,
            credentials
        )

        return PresentResponse(vp_jwt=vp_jwt)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Presentation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
