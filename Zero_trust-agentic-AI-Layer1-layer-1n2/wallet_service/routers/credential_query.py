"""
wallet_service/routers/credential_query.py

GET /wallets/:did/credentials
"""

from fastapi import APIRouter, HTTPException, Query
import logging
from typing import Optional, List

from models.responses import CredentialListResponse
from services.query_service import list_credentials

router = APIRouter(prefix="/wallets", tags=["credentials"])
logger = logging.getLogger(__name__)


@router.get("/{did}/credentials", response_model=CredentialListResponse)
async def query(
    did: str,
    type: Optional[List[str]] = Query(None),
    issuer: Optional[str] = None,
    status: Optional[str] = "active"
):
    """Query credentials by type, issuer, and status."""
    try:
        credentials = await list_credentials(did, type, issuer)
        return CredentialListResponse(agent_did=did, credentials=credentials)
    except Exception as e:
        logger.error(f"Credential query failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
