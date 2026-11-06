"""
status_list_service/models/requests.py
Pydantic request models.
"""

from pydantic import BaseModel
from typing import Optional


class AllocateRequest(BaseModel):
    """Request to allocate a new status list entry for a VC."""
    issuer_did: str
    vc_id: str


class RevokeRequest(BaseModel):
    """Request to revoke a credential."""
    vc_id: str
    reason: str
    authority_did: str


class BlocklistAddRequest(BaseModel):
    """Request to add a DID to the ephemeral blocklist."""
    did: str
    reason: Optional[str] = None
    expires_at: Optional[str] = None  # ISO timestamp


class BlocklistCheckRequest(BaseModel):
    """Request to check if a DID is blocklisted."""
    did: str


class AgentRevokeRequest(BaseModel):
    """Request to revoke all credentials for an agent."""
    agent_did: str
    reason: str
    authority_did: str
    vc_ids: Optional[list] = None  # Optional override list
