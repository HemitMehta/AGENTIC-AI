"""
status_list_service/models/responses.py
Pydantic response models.
"""

from pydantic import BaseModel
from typing import Optional, List, Dict


class AllocateResponse(BaseModel):
    """Response from status list allocation."""
    status_list_url: str
    bit_index: int


class StatusListVCResponse(BaseModel):
    """Signed Status List VC."""
    id: str
    type: List[str]
    issuer: Dict
    issued_at: str
    credential_subject: Dict


class RevokeResponse(BaseModel):
    """Response from revocation."""
    revoked_at: str
    bit_index: int
    kafka_event_id: str


class BlocklistResponse(BaseModel):
    """Response from blocklist operations."""
    blocklisted: bool
    added_at: Optional[str] = None
    reason: Optional[str] = None


class CascadeStep(BaseModel):
    """Single step in cascade response."""
    step: str
    status: str  # "success", "failed", "skipped"
    reason: Optional[str] = None
    count: Optional[int] = None
    kafka_event_id: Optional[str] = None


class CascadeResponse(BaseModel):
    """Response from agent revocation cascade."""
    cascade_complete: bool
    steps: List[CascadeStep]
    kafka_event_id: str
