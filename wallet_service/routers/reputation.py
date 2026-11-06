"""
wallet_service/routers/reputation.py

POST /wallets/:did/issue-reputation
"""

from fastapi import APIRouter, HTTPException
import logging

from models.requests import ReputationRequest
from models.responses import ReputationVCResponse
from services.reputation_issuer import issue_reputation_vc

router = APIRouter(tags=["reputation"])
logger = logging.getLogger(__name__)


@router.post("/reputation/issue", response_model=ReputationVCResponse)
async def issue_reputation(request: ReputationRequest):
    """Issue a peer-signed reputation VC."""
    try:
        signed_vc = await issue_reputation_vc(
            request.issuer_did,
            request.target_did,
            request.task_context,
            request.claims
        )

        return ReputationVCResponse(signed_reputation_vc=signed_vc)
    except Exception as e:
        logger.error(f"Reputation issuance failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
