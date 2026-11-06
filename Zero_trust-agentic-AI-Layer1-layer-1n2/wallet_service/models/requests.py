"""
wallet_service/models/requests.py
Pydantic request models.
"""

from pydantic import BaseModel, Field
from typing import Optional, List


class WalletInitRequest(BaseModel):
    """Request to initialize a wallet."""
    agent_did: str


class StoreRequest(BaseModel):
    """
    Request to store a credential.

    FIX (combined Layer 1 + Layer 2 integration): this was previously
    typed as `signed_vc: str` with a "JWT-encoded VC" comment, but
    vc_issuance actually issues VCs as JSON-LD documents with an embedded
    Data Integrity `proof` block (Ed25519Signature2020 / BbsBlsSignature2020),
    not as compact JWTs -- confirmed against vc_issuance.py's `_build_vc()`
    and verification_service's vc_sig_verifier.py, which both expect/produce
    this same JSON-LD-with-proof shape. Typing this as `str` meant every
    real call from vc_issuance's response failed FastAPI's request
    validation before it even reached store_vc(). `dict` matches what the
    rest of the system actually sends and expects.
    """
    agent_did: str
    signed_vc: dict  # signed VC as a JSON-LD document (with embedded "proof")


class PresentRequest(BaseModel):
    """Request to present credentials."""
    agent_did: str
    required_types: List[str]
    verifier_did: str
    nonce: str
    credential_ids: Optional[List[str]] = Field(default=None, min_length=1, max_length=20)


class PresentZKPRequest(BaseModel):
    """Request to present with zero-knowledge proof."""
    agent_did: str
    required_type: str
    verifier_did: str
    nonce: str
    predicate: dict  # { proofType, disclosedAttributes?, publicInputs? }


class ReputationRequest(BaseModel):
    """Request to issue a reputation VC."""
    issuer_did: str  # The agent issuing the reputation
    target_did: str  # The agent being praised
    task_context: str
    claims: dict  # Custom reputation claims


class DeleteWalletRequest(BaseModel):
    """Request to delete a wallet."""
    agent_did: str
    controller_signature: str  # Signature from a controller DID
    reason: Optional[str] = None
