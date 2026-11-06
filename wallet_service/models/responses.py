"""
wallet_service/models/responses.py
Pydantic response models.
"""

from pydantic import BaseModel
from typing import Optional, List


class WalletInitResponse(BaseModel):
    """Response from wallet initialization."""
    wallet_created: bool
    agent_did: str


class StoreResponse(BaseModel):
    """Response from credential storage."""
    stored: bool
    vc_id: str


class CredentialListResponse(BaseModel):
    """Credential listing response."""
    agent_did: str
    credentials: List[dict]  # { vcId, type[], issuer, expiresAt, status }


class PresentResponse(BaseModel):
    """Response from presentation request."""
    vp_jwt: str


class ZKPResponse(BaseModel):
    """Response from ZKP presentation."""
    zkp_proof: dict
    public_inputs: dict


class ReputationVCResponse(BaseModel):
    """Response from reputation VC issuance."""
    signed_reputation_vc: str
