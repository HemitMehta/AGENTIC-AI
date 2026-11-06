"""
models/responses.py

Pydantic response models for verification service endpoints.
"""

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
from datetime import datetime


class NonceResponse(BaseModel):
    """Response with generated nonce."""
    
    nonce: str = Field(..., description="Cryptographically random nonce (hex-encoded)")
    expiresAt: str = Field(..., description="ISO 8601 timestamp when nonce expires")


class VerificationResponse(BaseModel):
    """Response from VP or standalone VC verification."""
    
    valid: bool = Field(..., description="Whether the presentation/credential is valid")
    verifiedClaims: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Flat merged map of all verified claims if valid=true"
    )
    failedStep: Optional[str] = Field(
        default=None,
        description="Which verification step failed (if valid=false). One of: VP_SIGNATURE, NONCE, VC_SIGNATURE, TRUST_ANCHOR, REVOCATION, EXPIRY"
    )
    reason: Optional[str] = Field(
        default=None,
        description="Human-readable failure reason"
    )


class CredentialVerifyResponse(BaseModel):
    """Response from standalone credential verification."""
    
    valid: bool = Field(..., description="Whether the credential is valid")
    claims: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Verified claims if valid=true"
    )
    issuerDID: Optional[str] = Field(
        default=None,
        description="DID of the credential issuer"
    )
    expiresAt: Optional[str] = Field(
        default=None,
        description="ISO 8601 expiration date of the credential"
    )
    failedStep: Optional[str] = Field(
        default=None,
        description="Which verification step failed (if valid=false)"
    )
    reason: Optional[str] = Field(
        default=None,
        description="Human-readable failure reason"
    )
