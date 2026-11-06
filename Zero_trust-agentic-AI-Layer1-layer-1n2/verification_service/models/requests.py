"""
models/requests.py

Pydantic request models for verification service endpoints.
"""

from pydantic import BaseModel, Field, model_validator
from typing import Optional


class NonceRequest(BaseModel):
    """Request to generate a nonce."""
    
    verifierDID: str = Field(..., description="DID of the verifier requesting the nonce")
    purpose: str = Field(..., description="Purpose of the nonce (e.g., 'presentation_submission')")


class PresentationRequest(BaseModel):
    """Request to verify a VP (Verifiable Presentation)."""
    
    vp_jwt: str = Field(..., description="Signed VP JWT")
    nonce: str = Field(..., description="Nonce value used in the presentation")
    verifierDID: str = Field(..., description="DID of the verifier")


class CredentialRequest(BaseModel):
    """Request to verify a standalone VC (without VP wrapper)."""
    
    vc_jwt: Optional[str] = None
    credential: Optional[dict] = None
    fresh_status: bool = False

    @model_validator(mode="after")
    def exactly_one_credential(self):
        if (self.vc_jwt is None) == (self.credential is None):
            raise ValueError("Provide exactly one of vc_jwt or credential")
        return self
