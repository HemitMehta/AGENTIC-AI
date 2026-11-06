"""
status_list_service/routers/revoke.py

POST /status-lists/revoke
"""

from fastapi import APIRouter, HTTPException
import logging

from models.requests import RevokeRequest
from models.responses import RevokeResponse
from services.revocation_service import revoke_credential

router = APIRouter(prefix="/status-lists", tags=["revocation"])
logger = logging.getLogger(__name__)


@router.post("/revoke", response_model=RevokeResponse)
async def revoke(request: RevokeRequest):
    """
    Revoke a credential.

    Called by security team or SS4.

    Revocation order (strict):
    1. Redis (immediate verifier visibility)
    2. Postgres (durability)
    3. Kafka (event log)
    """

    try:
        result = await revoke_credential(request.vc_id, request.reason, request.authority_did)

        logger.info(f"Credential revoked: {request.vc_id}")

        return RevokeResponse(
            revoked_at=result["revoked_at"],
            bit_index=result["bit_index"],
            kafka_event_id=result.get("kafka_event_id") or ""
        )

    except ValueError as e:
        logger.error(f"Revocation validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Revocation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
