"""
models.py -- ANS Registry Service (Module 1, Person A)

Data models for agent discovery records. These records are what the
ANS Resolver (Module 2, Person B) queries against.
"""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


class ProtocolExtension(BaseModel):
    """Protocol-specific metadata for an agent (e.g. supported message patterns)."""
    protocol: str = Field(..., description="e.g. 'acp', 'a2a', 'mcp'")
    details: dict = Field(default_factory=dict)


class AgentControlProof(BaseModel):
    verificationMethod: str
    signature: str


class AgentRegistrationData(BaseModel):
    """What an agent/controller sends to register itself in the ANS."""
    ansName: str = Field(
        ..., description="e.g. 'acp://RiskAnalyzerBot.FinancialRiskAnalysis.AcmeFinanceServices.v2.1.3.prod'"
    )
    agentDid: str = Field(..., description="The agent's DID, must resolve via Layer 1 did_registry")
    capability: str = Field(..., description="e.g. 'FinancialRiskAnalysis.CorporateReporting'")
    provider: str = Field(..., description="e.g. 'AcmeFinanceServices'")
    version: str = Field(..., description="Semver, e.g. '2.1.3'")
    serviceEndpoint: str = Field(..., description="Where the agent can actually be reached")
    protocolExtensions: list[ProtocolExtension] = Field(default_factory=list)


class AgentRegistrationRequest(AgentRegistrationData):
    registrationProof: Optional[AgentControlProof] = None


class AgentRecord(AgentRegistrationData):
    """Stored representation of a registered agent."""
    recordId: str
    status: str = Field(default="active", description="active | suspended | deregistered")
    createdAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updatedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AgentUpdateRequest(BaseModel):
    """Partial update -- only fields provided are changed."""
    capability: Optional[str] = None
    provider: Optional[str] = None
    version: Optional[str] = None
    serviceEndpoint: Optional[str] = None
    protocolExtensions: Optional[list[ProtocolExtension]] = None
    status: Optional[str] = None
    agentControlProof: Optional[AgentControlProof] = None


class AgentDeregisterRequest(BaseModel):
    agentControlProof: Optional[AgentControlProof] = None


class AgentLookupQuery(BaseModel):
    """Internal query shape used by the ANS Resolver (Module 2) to search this registry."""
    capability: Optional[str] = None
    provider: Optional[str] = None
    ansNamePattern: Optional[str] = None
    status: str = "active"
