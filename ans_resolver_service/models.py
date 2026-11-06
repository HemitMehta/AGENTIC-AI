"""
models.py -- ANS Resolver Service (Module 2, Person B)

Public query API for capability-based agent discovery. This service is the
"read path" of the ANS: it queries Module 1 (ANS Registry) for candidates,
applies capability matching, verifies presented VC attestations against
Layer 1 (vc_verification + status_list_service), and signs the resolution
response via Layer 1 (kms) before returning it.
"""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


class ResolveByCapabilityRequest(BaseModel):
    """What a caller (typically the Discovery Gateway, Module 5) sends to find agents."""
    capability: str = Field(..., description="e.g. 'FinancialRiskAnalysis.CorporateReporting'")
    provider: Optional[str] = Field(None, description="e.g. 'AcmeFinanceServices'")
    protocol: Optional[str] = Field(None, description="e.g. 'acp', 'a2a', 'mcp' -- filters protocolExtensions")
    versionPrefix: Optional[str] = Field(
        None, description="Simple prefix match on version, e.g. '2.' matches '2.1.3'"
    )
    versionRange: Optional[str] = Field(
        None, description="PEP 440/semver-compatible range, e.g. '>=2.1.0,<3.0.0'"
    )
    requiredAttestations: list[str] = Field(
        default_factory=list,
        description="VC types the candidate agent must hold and have verified, e.g. ['SOXComplianceCertified']",
    )
    maxResults: int = Field(default=10, ge=1, le=100)


class ResolveByNameRequest(BaseModel):
    ansName: str


class RelevantVcSnippet(BaseModel):
    type: str
    issuer: Optional[str] = None
    issueDate: Optional[str] = None
    verified: bool
    revoked: Optional[bool] = None


class ResolvedAgent(BaseModel):
    """One candidate in the resolution response, individually signed for verifiability."""
    ansName: str
    agentDid: str
    serviceEndpoint: str
    provider: str
    version: str
    capability: str
    protocolExtensions: list[dict] = Field(default_factory=list)
    relevantVcSnippets: list[RelevantVcSnippet] = Field(default_factory=list)
    ansRecordSignature: Optional[str] = Field(
        None, description="Ed25519 signature over the canonical record"
    )
    signingKeyId: str
    signatureAlgorithm: str = "Ed25519"


class AnsResolutionResponse(BaseModel):
    resolutionStatus: str = Field(..., description="'success' | 'no_matches' | 'partial'")
    resolvedAgents: list[ResolvedAgent] = Field(default_factory=list)
    resolvedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
