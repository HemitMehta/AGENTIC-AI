"""
models.py -- Discovery Gateway (Module 5, Shared)

The single external entry point for Layer 2. Orchestrates, in order:
  1. Discovery Trust Policy Service (Module 3, 8010)  -- is this source trusted?
  2. ANS Resolver Service (Module 2, 8009)             -- who matches the capability?
  3. Reputation Service (Module 4, 8011)                -- how trustworthy are they?
and returns one unified, ranked, signed response.
"""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


class DiscoveryRequest(BaseModel):
    """What a caller (e.g. an orchestrator agent, or Layer 3) sends to Layer 2."""
    capability: str = Field(..., description="e.g. 'FinancialRiskAnalysis.CorporateReporting'")
    provider: Optional[str] = None
    protocol: Optional[str] = None
    versionPrefix: Optional[str] = None
    versionRange: Optional[str] = None
    requiredAttestations: list[str] = Field(default_factory=list)
    registryId: Optional[str] = Field(
        None, description="Set only when querying a federated/remote ANS registry"
    )
    maxCandidates: int = Field(default=10, ge=1, le=100)
    requestId: Optional[str] = Field(None, max_length=100, description="Caller challenge echoed in the signed response")


class CandidateSummary(BaseModel):
    """One candidate as seen by the Gateway, enriched with its reputation score."""
    ansName: str
    agentDid: str
    serviceEndpoint: str
    provider: str
    version: str
    capability: str
    reputationScore: float
    reputationSampleSize: int
    ansRecordSignature: Optional[str] = None
    signingKeyId: str
    signatureAlgorithm: str
    signatureVerified: bool
    ansRecord: Optional[dict] = Field(None, description="Complete resolver-signed record for independent client verification")


class DiscoveryResponse(BaseModel):
    resolutionStatus: str = Field(..., description="'success' | 'no_matches' | 'rejected_by_trust_policy'")
    selectedAgent: Optional[str] = Field(None, description="agentDid of the top-ranked candidate")
    endpoint: Optional[str] = None
    reputation: Optional[float] = None
    capabilities: list[str] = Field(default_factory=list)
    candidates: list[CandidateSummary] = Field(default_factory=list)
    rejectionReasons: list[str] = Field(default_factory=list)
    gatewaySignature: Optional[str] = None
    requestId: Optional[str] = None
    resolvedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
