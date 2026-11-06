import json

from pydantic import Field, field_validator
from layer3_common.policy import StrictModel


class AccessRequest(StrictModel):
    agentDid: str = Field(min_length=1, max_length=500)
    vpJwt: str = Field(min_length=1, max_length=262144)
    nonce: str = Field(min_length=1, max_length=500)
    resourceId: str = Field(min_length=1, max_length=300)
    action: str = Field(min_length=1, max_length=200)
    context: dict = Field(default_factory=dict)

    @field_validator("context")
    @classmethod
    def bounded_json_context(cls, value):
        if len(json.dumps(value, allow_nan=False).encode()) > 32768:
            raise ValueError("Context exceeds 32 KiB")
        return value


class TrustedContext(StrictModel):
    sourceIp: str | None = None
    callerService: str | None = None


class VerifiedAccessRequest(AccessRequest):
    trustedContext: TrustedContext = Field(default_factory=TrustedContext)


class RevalidationRequest(StrictModel):
    agentDid: str
    resourceId: str
    action: str
    context: dict
    credentials: list[dict] = Field(min_length=1, max_length=20)
    holderKeyHash: str
    expiresAt: int
    trustedContext: TrustedContext = Field(default_factory=TrustedContext)
