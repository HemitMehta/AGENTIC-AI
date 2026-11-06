"""
wallet_service/routers/credential_store.py

POST /wallets/:did/store
"""

from fastapi import APIRouter, HTTPException
import logging

from models.requests import StoreRequest
from models.responses import StoreResponse
from services.store_service import store_vc

router = APIRouter(prefix="/wallets", tags=["credentials"])
logger = logging.getLogger(__name__)


@router.post("/{did}/store", response_model=StoreResponse)
async def store(did: str, request: StoreRequest):
    """Store a credential in the wallet."""
    try:
        vc_id = await store_vc(did, request.signed_vc)
        return StoreResponse(stored=True, vc_id=vc_id)
    except Exception as e:
        logger.error(f"Credential store failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
