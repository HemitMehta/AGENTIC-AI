"""
models.py -- Reputation Service (Module 4, Person B)

Write side: records feedback about an agent's task performance and,
optionally, wraps Layer 1's vc_issuance (8004) to mint a signed
ReputationCredential VC for that feedback.

Read side: aggregates all feedback for a given agentDid into a single
0-100 reputation score that the Discovery Gateway (Module 5) and the
ANS Resolver (Module 2) can factor into ranking.
"""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


class ReputationFeedback(BaseModel):
    """Submitted by a rating agent after a task interaction completes."""
    raterDid: str = Field(..., description="DID of the agent giving the feedback")
    ratedAgentDid: str = Field(..., description="DID of the agent being rated")
    rating: int = Field(..., ge=1, le=5, description="1 (poor) to 5 (excellent)")
    ansCapabilityContext: Optional[str] = Field(
        None, description="e.g. 'TaskExecutor.GeneralPurpose.CommunityPool.v1.standard'"
    )
    taskId: Optional[str] = None
    comment: Optional[str] = None
    issueVc: bool = Field(
        default=False, description="If true, also mint a ReputationCredential VC for this feedback"
    )


class StoredFeedback(ReputationFeedback):
    feedbackId: str
    recordedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    issuedVcId: Optional[str] = None


class ReputationScoreResponse(BaseModel):
    agentDid: str
    score: float = Field(..., description="0-100, derived from average rating * 20")
    sampleSize: int
    breakdown: dict[str, int] = Field(
        default_factory=dict, description="Count of feedback entries per rating value 1-5"
    )


class ReputationVcIssueResult(BaseModel):
    feedbackId: str
    issuedVcId: Optional[str]
    issued: bool
    reason: Optional[str] = None
