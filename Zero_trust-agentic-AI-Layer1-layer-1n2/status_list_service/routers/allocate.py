"""
status_list_service/routers/allocate.py

POST /status-lists/allocate
"""

from fastapi import APIRouter, HTTPException
import logging

from models.requests import AllocateRequest
from models.responses import AllocateResponse
from services.bitstring_manager import allocate_status_entry
from db.connection import get_session
from db.queries.revocation_queries import log_revocation

router = APIRouter(prefix="/status-lists", tags=["status-list"])
logger = logging.getLogger(__name__)


@router.post("/allocate", response_model=AllocateResponse)
async def allocate(request: AllocateRequest):
    """
    Allocate a new status list entry for a VC.

    Called by SS4 (VC Issuance) on every credential issuance.
    """

    try:
        status_list_url, bit_index = await allocate_status_entry(request.issuer_did, request.vc_id)

        logger.info(f"Allocated status entry: vc_id={request.vc_id}, index={bit_index}")

        return AllocateResponse(
            status_list_url=status_list_url,
            bit_index=bit_index
        )

    except Exception as e:
        logger.error(f"Allocation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
