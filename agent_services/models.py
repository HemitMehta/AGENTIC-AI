from decimal import Decimal
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

PROTOCOL = "signed-http-json"
ACTION = "analyze_financials"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Period(StrictModel):
    period: str = Field(min_length=1, max_length=80)
    revenue: Decimal = Field(ge=0, max_digits=18, decimal_places=2)
    expenses: Decimal = Field(ge=0, max_digits=18, decimal_places=2)


class FinancialInput(StrictModel):
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    periods: list[Period] = Field(min_length=1, max_length=100)

    @field_validator("periods")
    @classmethod
    def unique_periods(cls, periods):
        if len({item.period for item in periods}) != len(periods):
            raise ValueError("period labels must be unique")
        return periods


class Discovery(StrictModel):
    capability: str = Field(min_length=1, max_length=300)
    provider: str | None = None
    protocol: Literal["signed-http-json"] = PROTOCOL
    versionPrefix: str | None = None
    versionRange: str | None = None
    requiredAttestations: list[str] = Field(default_factory=lambda: ["RoleVC"], min_length=1, max_length=10)
    registryId: str | None = None
    maxCandidates: int = Field(default=10, ge=1, le=10)


class ProtectedSalesInput(StrictModel):
    source: Literal["protected-sales"]
    resourceId: str = Field(min_length=1, max_length=300)
    jobId: str = Field(min_length=1, max_length=300)
    credentialIds: list[str] = Field(min_length=2, max_length=20)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    period: str | None = Field(default=None, max_length=32)
    limit: int = Field(default=100, ge=1, le=100)

    @field_validator("credentialIds")
    @classmethod
    def unique_credentials(cls, value):
        if len(set(value)) != len(value) or any(not item.strip() or len(item) > 300 for item in value):
            raise ValueError("credentialIds must be unique, nonempty credential identifiers")
        return value


class TaskSubmission(StrictModel):
    taskId: UUID = Field(default_factory=uuid4)
    discovery: Discovery
    input: FinancialInput | ProtectedSalesInput


class Proof(StrictModel):
    verificationMethod: str = Field(max_length=500)
    signatureAlgorithm: Literal["Ed25519"] = "Ed25519"
    signature: str = Field(max_length=200)


class TaskMessage(StrictModel):
    type: Literal["agent.task.request.v1"] = "agent.task.request.v1"
    taskId: UUID
    issuerDid: str = Field(max_length=400)
    audienceDid: str = Field(max_length=400)
    action: Literal["analyze_financials"] = ACTION
    issuedAt: int
    expiresAt: int
    input: FinancialInput | ProtectedSalesInput
    proof: Proof
