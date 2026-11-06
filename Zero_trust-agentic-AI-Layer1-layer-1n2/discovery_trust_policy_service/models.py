"""
models.py -- Discovery Trust Policy Service (Module 3, Person A)

This service is distinct from Layer 1's trust_anchor:
  - trust_anchor  -> "is this VC ISSUER authorized to issue this credential type?"
  - this service  -> "is this DISCOVERY SOURCE (ANS registry / provider / capability
                       namespace) trustworthy enough to even look at?"

It's consulted BEFORE the ANS Resolver (Module 2) returns results from any
registry that isn't the local/default one -- relevant for federated deployments.
"""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


class TrustedRegistryEntry(BaseModel):
    """A trusted ANS registry/resolver, for federated discovery."""
    registryId: str = Field(..., description="Unique id for the remote/partner ANS registry")
    registryUrl: str
    trustedSince: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: Optional[str] = None


class TrustedProviderEntry(BaseModel):
    """A trusted provider name (e.g. 'AcmeFinanceServices')."""
    provider: str
    trustedSince: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: Optional[str] = None


class TrustedCapabilityDomain(BaseModel):
    """A trusted top-level capability namespace (e.g. 'FinancialRiskAnalysis')."""
    domain: str
    trustedSince: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: Optional[str] = None


class TrustCheckRequest(BaseModel):
    """What the ANS Resolver (Module 2) sends to check trust before returning a result."""
    registryId: Optional[str] = Field(None, description="Omit for local/default registry")
    provider: Optional[str] = None
    capability: Optional[str] = None


class TrustCheckResponse(BaseModel):
    trusted: bool
    reasons: list[str] = Field(default_factory=list)
