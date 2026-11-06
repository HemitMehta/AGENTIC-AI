"""Layer 3 Policy Administration Point (PAP)."""

from datetime import datetime, timezone
from typing import Any, Literal, Optional

import psycopg2
from fastapi import FastAPI, HTTPException, Query
from psycopg2.extras import Json, RealDictCursor
from pydantic import BaseModel, Field, field_validator
from layer3_common.security import install, database_kwargs
from layer3_common.crypto import verify_admin
from layer3_common.policy import Policy, Condition, StrictModel
from layer3_common import audit

app = FastAPI(title="Layer 3 Policy Administration Point", version="1.0.0")
install(app, "pap")


class AdminAuthorization(StrictModel):
    adminDID: str
    verificationMethod: str
    signature: str


class PolicyWrite(StrictModel):
    policy: Policy
    adminAuthorization: AdminAuthorization


class Resource(StrictModel):
    resourceId: str = Field(min_length=1, max_length=300)
    version: int = Field(ge=1, strict=True)
    resourceDid: Optional[str] = None
    resourceType: str = Field(min_length=1, max_length=120)
    attributes: dict[str, Any] = Field(default_factory=dict)
    active: bool = Field(default=True, strict=True)


class ResourceWrite(StrictModel):
    resource: Resource
    adminAuthorization: AdminAuthorization


def _db():
    return psycopg2.connect(**database_kwargs(), cursor_factory=RealDictCursor)




def _init_db() -> None:
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS layer3_policies (
                    policy_id TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    policy JSONB NOT NULL,
                    active BOOLEAN NOT NULL,
                    priority INTEGER NOT NULL,
                    added_by TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    PRIMARY KEY (policy_id, version)
                );
                CREATE TABLE IF NOT EXISTS layer3_resources (
                    resource_id TEXT PRIMARY KEY,
                    version INTEGER NOT NULL DEFAULT 1,
                    resource JSONB NOT NULL,
                    active BOOLEAN NOT NULL,
                    added_by TEXT NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL
                );
                ALTER TABLE layer3_resources ADD COLUMN IF NOT EXISTS version INTEGER NOT NULL DEFAULT 1;
                """
            )
            audit.initialize(cur)


@app.on_event("startup")
async def startup() -> None:
    _init_db()


@app.get("/health")
async def health():
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS count FROM layer3_policies")
            count = cur.fetchone()["count"]
    return {"status": "healthy", "service": "policy_administration_point", "policies": count}


@app.post("/policies", status_code=201)
async def write_policy(request: PolicyWrite):
    policy = request.policy.model_dump(mode="json")
    await verify_admin(request.adminAuthorization, {"action": "pap.upsertPolicy", "policy": policy})
    now = datetime.now(timezone.utc)
    try:
        with _db() as conn:
            with conn.cursor() as cur:
                # Serialize writers even when this policy has no existing row.
                cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (request.policy.policyId,))
                cur.execute("SELECT MAX(version) AS version FROM layer3_policies WHERE policy_id = %s", (request.policy.policyId,))
                previous = cur.fetchone()["version"]
                if previous is not None and request.policy.version <= previous:
                    raise HTTPException(409, "Policy version must increase")
                cur.execute("UPDATE layer3_policies SET active = FALSE WHERE policy_id = %s", (request.policy.policyId,))
                cur.execute(
                    "INSERT INTO layer3_policies (policy_id, version, policy, active, priority, added_by, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                    (request.policy.policyId, request.policy.version, Json(policy), request.policy.active,
                     request.policy.priority, request.adminAuthorization.adminDID, now),
                )
                audit.append(cur, "pap.upsertPolicy", {"policy": policy,
                             "adminAuthorization": request.adminAuthorization.model_dump()}, request.adminAuthorization.adminDID)
    except psycopg2.errors.UniqueViolation as exc:
        raise HTTPException(status_code=409, detail="Policy id and version already exist") from exc
    return {"status": "stored", "policy": policy, "addedBy": request.adminAuthorization.adminDID, "createdAt": now}


@app.get("/policies")
async def list_policies(active: Optional[bool] = Query(default=True)):
    with _db() as conn:
        with conn.cursor() as cur:
            if active is None:
                cur.execute("SELECT policy, active FROM layer3_policies ORDER BY priority DESC, policy_id, version DESC")
            else:
                cur.execute("SELECT policy, active FROM layer3_policies WHERE active = %s ORDER BY priority DESC, policy_id, version DESC", (active,))
            return {"policies": [{**row["policy"], "active": row["active"]} for row in cur.fetchall()]}


@app.post("/resources", status_code=201)
async def write_resource(request: ResourceWrite):
    resource = request.resource.model_dump(mode="json")
    await verify_admin(request.adminAuthorization, {"action": "pap.upsertResource", "resource": resource})
    now = datetime.now(timezone.utc)
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO layer3_resources (resource_id, version, resource, active, added_by, updated_at)
                   VALUES (%s,%s,%s,%s,%s,%s)
                   ON CONFLICT (resource_id) DO UPDATE SET version=EXCLUDED.version, resource=EXCLUDED.resource,
                   active=EXCLUDED.active, added_by=EXCLUDED.added_by, updated_at=EXCLUDED.updated_at
                   WHERE layer3_resources.version < EXCLUDED.version""",
                (request.resource.resourceId, request.resource.version, Json(resource), request.resource.active,
                 request.adminAuthorization.adminDID, now),
            )
            if cur.rowcount != 1:
                raise HTTPException(status_code=409, detail="Resource version must increase")
            audit.append(cur, "pap.upsertResource", {"resource": resource,
                         "adminAuthorization": request.adminAuthorization.model_dump()}, request.adminAuthorization.adminDID)
    return {"status": "stored", "resource": resource, "addedBy": request.adminAuthorization.adminDID, "updatedAt": now}


@app.get("/resources/{resource_id:path}")
async def get_resource(resource_id: str):
    with _db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT resource FROM layer3_resources WHERE resource_id = %s AND active = TRUE", (resource_id,))
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Active resource not found")
    return row["resource"]


@app.get("/governance/events")
async def governance_events(after: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000)):
    return audit.events(_db, after, limit)


@app.get("/governance/integrity")
async def governance_integrity():
    return audit.integrity(_db)


@app.get("/history/resources")
async def resource_history(resourceId: str, after: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000)):
    with _db() as conn, conn.cursor() as cur:
        cur.execute("""SELECT * FROM layer3_security_events WHERE sequence > %s
            AND event->>'action' = 'pap.upsertResource'
            AND event->'payload'->'resource'->>'resourceId' = %s ORDER BY sequence LIMIT %s""",
                    (after, resourceId, limit))
        return {"events": cur.fetchall()}


@app.get("/history/policies")
async def policy_history(policyId: str, beforeVersion: int = Query(2147483647, ge=1),
                         limit: int = Query(100, ge=1, le=1000)):
    with _db() as conn, conn.cursor() as cur:
        cur.execute("""SELECT policy, active AS currently_active, added_by, created_at FROM layer3_policies
            WHERE policy_id=%s AND version < %s ORDER BY version DESC LIMIT %s""", (policyId, beforeVersion, limit))
        return {"versions": cur.fetchall()}
