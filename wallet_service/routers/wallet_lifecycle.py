"""
wallet_service/routers/wallet_lifecycle.py
POST /wallets/:did/init, DELETE /wallets/:did
"""

from fastapi import APIRouter, HTTPException
import logging

from models.requests import WalletInitRequest, DeleteWalletRequest
from models.responses import WalletInitResponse
from services.wallet_service import init_wallet, delete_wallet

router = APIRouter(prefix="/wallets", tags=["lifecycle"])
logger = logging.getLogger(__name__)


@router.post("/{did}/init", response_model=WalletInitResponse)
async def init(did: str):
    """Initialize a wallet for an agent."""
    try:
        created = await init_wallet(did)
        return WalletInitResponse(wallet_created=created, agent_did=did)
    except Exception as e:
        logger.error(f"Wallet init failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{did}")
async def delete(did: str, request: DeleteWalletRequest):
    """Delete a wallet (soft delete)."""
    try:
        result = await delete_wallet(did, request.controller_signature, request.reason)
        return result
    except Exception as e:
        logger.error(f"Wallet delete failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
