"""
status_list_service/routers/status_list.py

GET /status-lists/:id
"""

from fastapi import APIRouter, HTTPException
import logging

from services.status_list_vc_builder import build_status_list_vc

router = APIRouter(prefix="/status-lists", tags=["status-list"])
logger = logging.getLogger(__name__)


@router.get("/{status_list_id}")
async def get_status_list(status_list_id: str, fresh: bool = False):
    """
    Get a signed Status List 2021 VC.

    Called by verifiers (SS5) on every credential check. Must be fast.
    Cache hit returns immediately. Cache miss fetches from DB, signs, caches.
    """

    try:
        vc = await build_status_list_vc(status_list_id, None, fresh=fresh)
        logger.info(f"Served status list {status_list_id}")
        return vc

    except ValueError as e:
        logger.error(f"Status list not found: {status_list_id}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to serve status list: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
