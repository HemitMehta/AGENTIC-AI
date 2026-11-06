"""
main.py -- Reputation Service (Module 4, Person B)
Port: 8011

Responsibilities:
  - Record task-performance feedback between agents (write side).
  - Aggregate feedback into a 0-100 reputation score per agentDid (read side).
  - Optionally wrap Layer 1's vc_issuance (8004) to mint a signed
    ReputationCredential VC for a specific piece of feedback.

Storage: in-memory dict for now, matching Module 1 and Module 3's approach.
DB wiring (feedback history table) is deferred to the end of the project.

--------------------------------------------------------------------------
FIX (combined Layer 1 + Layer 2 integration): the vc_issuance call below
was originally written against an ASSUMED contract (POST /credentials/issue,
{"type", "issuer", "credentialSubject"} -> {"credentialId"}) that the
module's own docstring flagged as unverified. The real Layer 1
vc_issuance_service.py exposes:

    POST /issue/reputation
      { "subject_did", "issuer_did", "issuer_key_id",
        "claims": {"reputationScore", "tasksCompleted",
                    "violationCount", "peerDID"},
        "trust_domain" }
    -> { "status", "vc_id", "credential_type", "signedVC", "expiresAt" }

Fixed to match. This also means issuing a VC now requires a KMS key for
the issuer DID (REPUTATION_ISSUER_KEY_ID) and that issuer_did must be
authorised for the "Reputation" credential type in that trust_domain via
trust_anchor -- otherwise vc_issuance returns 400 and, per the existing
best-effort design below, feedback is still recorded without a VC.
--------------------------------------------------------------------------
"""

import os
import uuid
import logging
from typing import Optional

import httpx
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, status

from models import (
    ReputationFeedback,
    StoredFeedback,
    ReputationScoreResponse,
    ReputationVcIssueResult,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("reputation_service")

# ---------------------------------------------------------------------------
# Config -- Layer 1 service we optionally depend on
# ---------------------------------------------------------------------------
VC_ISSUANCE_URL = os.getenv("VC_ISSUANCE_URL", "http://vc_issuance:8004")
VC_ISSUANCE_TIMEOUT_SECONDS = float(os.getenv("VC_ISSUANCE_TIMEOUT_SECONDS", "5"))
REPUTATION_ISSUER_DID = os.getenv("REPUTATION_ISSUER_DID", "did:web:layer2:reputation-service")
# Vault/KMS key id for REPUTATION_ISSUER_DID's signing key. Must already
# exist (POST /keys/generate on kms:8001) before VC issuance will succeed.
REPUTATION_ISSUER_KEY_ID = os.getenv("REPUTATION_ISSUER_KEY_ID", "reputation-service-key")
REPUTATION_VC_TRUST_DOMAIN = os.getenv("REPUTATION_VC_TRUST_DOMAIN", "enterprise")
DATABASE_URL = os.getenv("LAYER2_DATABASE_URL")

app = FastAPI(
    title="Reputation Service",
    description="Layer 2 / Module 4 -- reputation feedback + score aggregation",
    version="0.1.0",
)

# ---------------------------------------------------------------------------
# In-memory store (temporary -- DB comes later)
# ---------------------------------------------------------------------------
_feedback_store: dict[str, StoredFeedback] = {}          # feedbackId -> StoredFeedback
_feedback_by_agent: dict[str, list[str]] = {}             # ratedAgentDid -> [feedbackId, ...]


def _db_enabled() -> bool:
    return bool(DATABASE_URL)


def _get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def _row_to_feedback(row: dict) -> StoredFeedback:
    return StoredFeedback(
        feedbackId=row["feedback_id"],
        raterDid=row["rater_did"],
        ratedAgentDid=row["rated_agent_did"],
        rating=row["rating"],
        ansCapabilityContext=row["ans_capability_context"],
        taskId=row["task_id"],
        comment=row["comment"],
        issueVc=row["issue_vc"],
        recordedAt=row["recorded_at"],
        issuedVcId=row["issued_vc_id"],
    )


def _init_db():
    if not _db_enabled():
        logger.info("LAYER2_DATABASE_URL not set; Reputation Service using in-memory storage")
        return

    with _get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS reputation_feedback (
                    feedback_id TEXT PRIMARY KEY,
                    rater_did TEXT NOT NULL,
                    rated_agent_did TEXT NOT NULL,
                    rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
                    ans_capability_context TEXT,
                    task_id TEXT,
                    comment TEXT,
                    issue_vc BOOLEAN NOT NULL DEFAULT FALSE,
                    recorded_at TIMESTAMPTZ NOT NULL,
                    issued_vc_id TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_reputation_feedback_rated_agent
                    ON reputation_feedback(rated_agent_did);
                """
            )
        conn.commit()
    logger.info("Reputation database initialized")


@app.on_event("startup")
async def startup_event():
    _init_db()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
async def _issue_reputation_vc(feedback: StoredFeedback) -> Optional[str]:
    """
    Real Layer 1 contract (vc_issuance_service.py):
      POST /issue/reputation
        {
          "subject_did": <ratedAgentDid>,
          "issuer_did": REPUTATION_ISSUER_DID,
          "issuer_key_id": REPUTATION_ISSUER_KEY_ID,
          "claims": {
            "reputationScore": ...,   # this feedback's rating scaled to 0-100
            "tasksCompleted": 1,      # one feedback record == one completed task
            "violationCount": 0,      # no violation semantics in feedback yet
            "peerDID": <raterDid>,
          },
          "trust_domain": REPUTATION_VC_TRUST_DOMAIN,
        }
      -> 200 { "status", "vc_id", "credential_type", "signedVC", "expiresAt" }

    Best-effort: if vc_issuance is unreachable, or rejects the request
    (e.g. issuer_did not authorised for "Reputation" VCs in trust_anchor,
    or issuer_key_id doesn't exist in KMS yet), feedback is still recorded,
    just without an accompanying VC.
    """
    url = f"{VC_ISSUANCE_URL}/issue/reputation"
    payload = {
        "subject_did": feedback.ratedAgentDid,
        "issuer_did": REPUTATION_ISSUER_DID,
        "issuer_key_id": REPUTATION_ISSUER_KEY_ID,
        "claims": {
            "reputationScore": feedback.rating * 20,
            "tasksCompleted": 1,
            "violationCount": 0,
            "peerDID": feedback.raterDid,
        },
        "trust_domain": REPUTATION_VC_TRUST_DOMAIN,
    }
    try:
        async with httpx.AsyncClient(timeout=VC_ISSUANCE_TIMEOUT_SECONDS) as client:
            resp = await client.post(url, json=payload)
        resp.raise_for_status()
        return resp.json().get("vc_id")
    except httpx.RequestError as exc:
        logger.warning("vc_issuance unreachable at %s, feedback recorded without a VC: %s", url, exc)
        return None
    except httpx.HTTPStatusError as exc:
        logger.warning("vc_issuance rejected the request: HTTP %s -- %s", exc.response.status_code, exc.response.text)
        return None


def _find_or_404(feedback_id: str) -> StoredFeedback:
    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM reputation_feedback WHERE feedback_id = %s", (feedback_id,))
                row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail=f"No feedback record with id '{feedback_id}'")
        return _row_to_feedback(row)

    record = _feedback_store.get(feedback_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"No feedback record with id '{feedback_id}'")
    return record


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS feedback_records, COUNT(DISTINCT rated_agent_did) AS rated_agents FROM reputation_feedback")
                row = cur.fetchone()
        return {
            "status": "healthy",
            "service": "reputation_service",
            "feedback_records": row["feedback_records"],
            "rated_agents": row["rated_agents"],
            "storage": "postgres",
        }

    return {
        "status": "healthy",
        "service": "reputation_service",
        "feedback_records": len(_feedback_store),
        "rated_agents": len(_feedback_by_agent),
    }


# ---------------------------------------------------------------------------
# Write side -- submit feedback (+ optional VC issuance)
# ---------------------------------------------------------------------------
@app.post("/feedback", response_model=StoredFeedback, status_code=status.HTTP_201_CREATED)
async def submit_feedback(payload: ReputationFeedback):
    feedback_id = str(uuid.uuid4())
    record = StoredFeedback(feedbackId=feedback_id, **payload.model_dump())

    if payload.issueVc:
        record.issuedVcId = await _issue_reputation_vc(record)

    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO reputation_feedback
                        (feedback_id, rater_did, rated_agent_did, rating, ans_capability_context,
                         task_id, comment, issue_vc, recorded_at, issued_vc_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        record.feedbackId,
                        record.raterDid,
                        record.ratedAgentDid,
                        record.rating,
                        record.ansCapabilityContext,
                        record.taskId,
                        record.comment,
                        record.issueVc,
                        record.recordedAt,
                        record.issuedVcId,
                    ),
                )
            conn.commit()

        logger.info(
            "Recorded feedback %s for agent %s (rating=%s, vc=%s)",
            feedback_id, payload.ratedAgentDid, payload.rating, record.issuedVcId,
        )
        return record

    _feedback_store[feedback_id] = record
    _feedback_by_agent.setdefault(payload.ratedAgentDid, []).append(feedback_id)

    logger.info(
        "Recorded feedback %s for agent %s (rating=%s, vc=%s)",
        feedback_id, payload.ratedAgentDid, payload.rating, record.issuedVcId,
    )
    return record


@app.post("/feedback/{feedback_id}/issue-vc", response_model=ReputationVcIssueResult)
async def issue_vc_for_existing_feedback(feedback_id: str):
    """Retroactively mint a ReputationCredential VC for feedback that didn't request one at submit time."""
    record = _find_or_404(feedback_id)

    if record.issuedVcId:
        return ReputationVcIssueResult(
            feedbackId=feedback_id, issuedVcId=record.issuedVcId, issued=False,
            reason="VC already issued for this feedback record",
        )

    vc_id = await _issue_reputation_vc(record)
    if vc_id is None:
        return ReputationVcIssueResult(
            feedbackId=feedback_id, issuedVcId=None, issued=False,
            reason="vc_issuance unreachable or rejected the request",
        )

    record.issuedVcId = vc_id
    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE reputation_feedback SET issued_vc_id = %s, issue_vc = TRUE WHERE feedback_id = %s",
                    (vc_id, feedback_id),
                )
            conn.commit()
        return ReputationVcIssueResult(feedbackId=feedback_id, issuedVcId=vc_id, issued=True)

    _feedback_store[feedback_id] = record
    return ReputationVcIssueResult(feedbackId=feedback_id, issuedVcId=vc_id, issued=True)


# ---------------------------------------------------------------------------
# Read side -- aggregated score (consumed by Module 2 / Module 5)
# ---------------------------------------------------------------------------
@app.get("/reputation/{agent_did:path}", response_model=ReputationScoreResponse)
async def get_reputation(agent_did: str):
    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT rating FROM reputation_feedback WHERE rated_agent_did = %s", (agent_did,))
                rows = cur.fetchall()

        if not rows:
            return ReputationScoreResponse(agentDid=agent_did, score=0.0, sampleSize=0, breakdown={})

        breakdown = {str(i): 0 for i in range(1, 6)}
        total = 0
        for row in rows:
            rating = row["rating"]
            breakdown[str(rating)] += 1
            total += rating

        avg = total / len(rows)
        return ReputationScoreResponse(
            agentDid=agent_did,
            score=round(avg * 20, 2),
            sampleSize=len(rows),
            breakdown=breakdown,
        )

    feedback_ids = _feedback_by_agent.get(agent_did, [])

    if not feedback_ids:
        return ReputationScoreResponse(agentDid=agent_did, score=0.0, sampleSize=0, breakdown={})

    breakdown = {str(i): 0 for i in range(1, 6)}
    total = 0
    for fid in feedback_ids:
        rating = _feedback_store[fid].rating
        breakdown[str(rating)] += 1
        total += rating

    avg = total / len(feedback_ids)
    score = round(avg * 20, 2)  # scale 1-5 avg to 0-100
    return ReputationScoreResponse(
        agentDid=agent_did, score=score, sampleSize=len(feedback_ids), breakdown=breakdown
    )


@app.get("/feedback/{feedback_id}", response_model=StoredFeedback)
async def get_feedback(feedback_id: str):
    return _find_or_404(feedback_id)


@app.get("/feedback", response_model=list[StoredFeedback])
async def list_feedback_for_agent(agent_did: Optional[str] = None):
    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                if agent_did is None:
                    cur.execute("SELECT * FROM reputation_feedback ORDER BY recorded_at DESC")
                else:
                    cur.execute(
                        "SELECT * FROM reputation_feedback WHERE rated_agent_did = %s ORDER BY recorded_at DESC",
                        (agent_did,),
                    )
                rows = cur.fetchall()
        return [_row_to_feedback(row) for row in rows]

    if agent_did is None:
        return list(_feedback_store.values())
    return [_feedback_store[fid] for fid in _feedback_by_agent.get(agent_did, [])]
