"""A protected SQL resource. No caller-supplied SQL or table names are executed."""
import hashlib
import os
import time
from decimal import Decimal
from uuid import UUID

import httpx
import psycopg2
from fastapi import Depends, FastAPI, HTTPException, Query as QueryParam, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, ConfigDict, Field

from layer3_common.crypto import AdminAuthorization, verify_admin, verify_proof, canonical
from layer3_common import audit
from layer3_common.security import database_kwargs, install, request as http_request

PEP_URL = os.getenv("PEP_URL", "https://access_control_service:8016")
app = FastAPI(title="Protected Sales Resource", version="1.0.0")
install(app, "sales")
bearer = HTTPBearer()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Row(StrictModel):
    period: str = Field(min_length=1, max_length=32)
    currency: str = Field(pattern=r"^[A-Z]{3}$")
    revenue: Decimal = Field(ge=0, max_digits=18, decimal_places=2, allow_inf_nan=False)
    expenses: Decimal = Field(ge=0, max_digits=18, decimal_places=2, allow_inf_nan=False)


class Dataset(StrictModel):
    resourceId: str = Field(min_length=1, max_length=300)
    version: int = Field(ge=1)
    rows: list[Row] = Field(min_length=1, max_length=1000)


class DatasetWrite(StrictModel):
    dataset: Dataset
    adminAuthorization: AdminAuthorization


class Proof(StrictModel):
    verificationMethod: str
    signature: str


class Query(StrictModel):
    resourceId: str = Field(min_length=1, max_length=300)
    agentDid: str
    requestId: UUID
    issuedAt: int
    expiresAt: int
    tokenHash: str = Field(pattern=r"^[0-9a-f]{64}$")
    period: str | None = Field(default=None, max_length=32)
    currency: str | None = Field(default=None, pattern=r"^[A-Z]{3}$")
    limit: int = Field(default=100, ge=1, le=1000)
    proof: Proof


def _db():
    return psycopg2.connect(**database_kwargs(), cursor_factory=RealDictCursor)


@app.on_event("startup")
async def startup():
    with _db() as conn, conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sales_datasets (resource_id TEXT PRIMARY KEY, version INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS sales_rows (
                resource_id TEXT NOT NULL REFERENCES sales_datasets(resource_id),
                period TEXT NOT NULL, currency TEXT NOT NULL,
                revenue NUMERIC(18,2) NOT NULL, expenses NUMERIC(18,2) NOT NULL,
                PRIMARY KEY(resource_id, period, currency));
            CREATE TABLE IF NOT EXISTS sales_replays (
                agent_did TEXT NOT NULL, request_id UUID NOT NULL, expires_at BIGINT NOT NULL,
                PRIMARY KEY(agent_did, request_id));
        """)
        audit.initialize(cur)


@app.get("/health")
async def health():
    with _db() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1")
    return {"status": "healthy", "service": "protected_sales_resource"}


@app.post("/datasets", status_code=201)
async def write_dataset(request: DatasetWrite):
    dataset = request.dataset
    identities = {(r.period, r.currency) for r in dataset.rows}
    if len(identities) != len(dataset.rows):
        raise HTTPException(422, "Duplicate period/currency row")
    await verify_admin(request.adminAuthorization,
                       {"action": "sales.upsertDataset", "dataset": dataset.model_dump(mode="json")})
    with _db() as conn, conn.cursor() as cur:
        cur.execute("""
            INSERT INTO sales_datasets VALUES (%s,%s)
            ON CONFLICT(resource_id) DO UPDATE SET version=EXCLUDED.version
            WHERE sales_datasets.version < EXCLUDED.version
        """, (dataset.resourceId, dataset.version))
        if cur.rowcount != 1:
            raise HTTPException(409, "Dataset version must increase")
        cur.execute("DELETE FROM sales_rows WHERE resource_id=%s", (dataset.resourceId,))
        cur.executemany("INSERT INTO sales_rows VALUES (%s,%s,%s,%s,%s)",
                        [(dataset.resourceId, r.period, r.currency, r.revenue, r.expenses) for r in dataset.rows])
        audit.append(cur, "sales.upsertDataset", {"resourceId": dataset.resourceId, "version": dataset.version,
                     "rows": len(dataset.rows), "contentHash": hashlib.sha256(canonical(dataset.model_dump(mode="json"))).hexdigest()},
                     request.adminAuthorization.adminDID)
    return {"resourceId": dataset.resourceId, "version": dataset.version, "rows": len(dataset.rows)}


def validate_window(request):
    now = int(time.time())
    if (request.issuedAt > now + 5 or request.issuedAt < now - 60
            or request.expiresAt <= now or request.expiresAt <= request.issuedAt
            or request.expiresAt - request.issuedAt > 60):
        raise HTTPException(403, "Proof expired or outside the allowed time window")


@app.post("/query")
async def query(request: Query, http: Request, authorization: HTTPAuthorizationCredentials = Depends(bearer)):
    token = authorization.credentials
    if hashlib.sha256(token.encode()).hexdigest() != request.tokenHash:
        raise HTTPException(403, "Proof is not bound to this token")
    validate_window(request)
    payload = request.model_dump(mode="json", exclude={"proof"})
    await verify_proof(request.agentDid, request.proof.model_dump(), {"action": "sales.query", **payload})
    try:
        response = await http_request("POST", f"{PEP_URL}/access/introspect",
                                      json={"token": token, "resourceId": request.resourceId, "action": "QUERY_TABLE",
                                            "sourceIp": http.client.host if http.client else None})
        response.raise_for_status()
        authorization_state = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(503, "Authorization service unavailable; access denied") from exc
    if not isinstance(authorization_state, dict) or authorization_state.get("active") is not True:
        raise HTTPException(403, "Access grant is inactive")
    claims = authorization_state.get("claims", {})
    if (not isinstance(claims, dict) or claims.get("sub") != request.agentDid
            or claims.get("resourceId") != request.resourceId or claims.get("action") != "QUERY_TABLE"
            or type(claims.get("exp")) is not int or not isinstance(claims.get("jti"), str)):
        raise HTTPException(403, "Access grant is inactive or belongs to another agent")
    resource = authorization_state.get("resource", {})
    if not isinstance(resource, dict) or resource.get("resourceId") != request.resourceId:
        raise HTTPException(403, "Introspection returned a different resource")
    attributes = resource.get("attributes", {})
    if (not isinstance(attributes, dict) or resource.get("resourceType") != "financial-database" or attributes.get("schema") != "Sales"
            or attributes.get("table") != "QuarterlySummaries"):
        raise HTTPException(403, "Resource is not bound to this database adapter")
    validate_window(request)
    if authorization_state["claims"]["exp"] <= int(time.time()):
        raise HTTPException(403, "Access token expired")
    try:
        with _db() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM sales_replays WHERE expires_at < %s", (int(time.time()) - 60,))
            cur.execute("INSERT INTO sales_replays VALUES (%s,%s,%s)",
                        (request.agentDid, str(request.requestId), request.expiresAt))
            # Keep the reported version and its rows consistent during concurrent replacement.
            cur.execute("SELECT version FROM sales_datasets WHERE resource_id=%s FOR SHARE", (request.resourceId,))
            dataset = cur.fetchone()
            if not dataset:
                raise HTTPException(404, "Dataset not found")
            cur.execute("""
                SELECT period,currency,revenue,expenses FROM sales_rows
                WHERE resource_id=%s AND (%s IS NULL OR period=%s) AND (%s IS NULL OR currency=%s)
                ORDER BY period,currency LIMIT %s
            """, (request.resourceId, request.period, request.period, request.currency, request.currency, request.limit))
            rows = [{**row, "revenue": str(row["revenue"]), "expenses": str(row["expenses"])} for row in cur.fetchall()]
            validate_window(request)
            if claims["exp"] <= int(time.time()):
                raise HTTPException(403, "Access token expired during query")
            audit.append(cur, "sales.query", {"resourceId": request.resourceId, "datasetVersion": dataset["version"],
                         "decisionId": claims["jti"], "requestId": str(request.requestId), "rowCount": len(rows)}, request.agentDid)
    except psycopg2.errors.UniqueViolation as exc:
        raise HTTPException(409, "Request proof has already been used") from exc
    return {"resourceId": request.resourceId, "datasetVersion": dataset["version"],
            "decisionId": authorization_state["claims"]["jti"], "requestId": str(request.requestId), "rows": rows}


@app.get("/audit/events")
async def audit_events(after: int = QueryParam(0, ge=0), limit: int = QueryParam(100, ge=1, le=1000)):
    return audit.events(_db, after, limit)


@app.get("/audit/integrity")
async def audit_integrity():
    return audit.integrity(_db)
