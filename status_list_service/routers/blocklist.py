"""
status_list_service/routers/blocklist.py

POST /blocklist/:did (add)
GET /blocklist/:did (check)
"""

from fastapi import APIRouter, HTTPException
import logging

from models.requests import BlocklistAddRequest
from models.responses import BlocklistResponse
from services.blocklist_service import add_to_blocklist, check_blocklist, remove_from_blocklist

router = APIRouter(prefix="/blocklist", tags=["blocklist"])
logger = logging.getLogger(__name__)


@router.post("/{did}", response_model=BlocklistResponse)
async def add_to_list(did: str, request: BlocklistAddRequest):
    """Add a did:key to the ephemeral blocklist."""

    try:
        result = await add_to_blocklist(did, request.reason, request.expires_at)
        logger.info(f"Added {did} to blocklist")

        return BlocklistResponse(
            blocklisted=True,
            added_at=result["added_at"],
            reason=request.reason
        )

    except ValueError as e:
        logger.error(f"Blocklist validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Blocklist add failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{did}", response_model=BlocklistResponse)
async def check(did: str):
    """Check if a DID is blocklisted."""

    try:
        result = await check_blocklist(did)
        return BlocklistResponse(**result)

    except Exception as e:
        logger.error(f"Blocklist check failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{did}")
async def remove(did: str):
    """Remove a DID from the blocklist."""

    try:
        await remove_from_blocklist(did)
        logger.info(f"Removed {did} from blocklist")
        return {"removed": True}

    except Exception as e:
        logger.error(f"Blocklist remove failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
