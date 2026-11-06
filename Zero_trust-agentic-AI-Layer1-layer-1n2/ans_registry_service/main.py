"""
main.py -- ANS Registry Service (Module 1, Person A)
Port: 8008

Responsibilities:
  - Store agent discovery records (ansName, agentDid, capability, provider,
    version, protocolExtensions, serviceEndpoint).
  - Register / update / deregister endpoints.
  - Validate that agentDid actually resolves via Layer 1's did_registry (8002)
    BEFORE accepting a registration.

Storage: PostgreSQL in the composed stack. An in-memory fallback remains
available only for the isolated mock test when LAYER2_DATABASE_URL is unset.
"""

import os
import base64
import json
import uuid
import logging
from typing import Optional
from datetime import datetime, timezone

import httpx
import base58
import psycopg2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from psycopg2.extras import RealDictCursor, Json
from fastapi import FastAPI, HTTPException, status

from models import (
    AgentRegistrationRequest,
    AgentRegistrationData,
    AgentRecord,
    AgentUpdateRequest,
    AgentDeregisterRequest,
    AgentLookupQuery,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ans_registry_service")

# ---------------------------------------------------------------------------
# Config -- Layer 1 service we depend on
# ---------------------------------------------------------------------------
DID_REGISTRY_URL = os.getenv("DID_REGISTRY_URL", "http://did_registry:8002")
DID_RESOLVE_TIMEOUT_SECONDS = float(os.getenv("DID_RESOLVE_TIMEOUT_SECONDS", "5"))
DATABASE_URL = os.getenv("LAYER2_DATABASE_URL")
REQUIRE_REGISTRATION_PROOF = os.getenv("ANS_REQUIRE_REGISTRATION_PROOF", "true").lower() == "true"

app = FastAPI(
    title="ANS Registry Service",
    description="Layer 2 / Module 1 -- Agent discovery record store",
    version="0.1.0",
)

# ---------------------------------------------------------------------------
# In-memory store (temporary -- DB comes later)
# ---------------------------------------------------------------------------
_registry: dict[str, AgentRecord] = {}          # recordId -> AgentRecord
_ans_name_index: dict[str, str] = {}            # ansName  -> recordId


def _db_enabled() -> bool:
    return bool(DATABASE_URL)


def _get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def _row_to_record(row: dict) -> AgentRecord:
    return AgentRecord(
        recordId=row["record_id"],
        ansName=row["ans_name"],
        agentDid=row["agent_did"],
        capability=row["capability"],
        provider=row["provider"],
        version=row["version"],
        serviceEndpoint=row["service_endpoint"],
        protocolExtensions=row["protocol_extensions"] or [],
        status=row["status"],
        createdAt=row["created_at"],
        updatedAt=row["updated_at"],
    )


def _init_db():
    if not _db_enabled():
        logger.info("LAYER2_DATABASE_URL not set; ANS Registry using in-memory storage")
        return

    with _get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS ans_agent_records (
                    record_id TEXT PRIMARY KEY,
                    ans_name TEXT NOT NULL UNIQUE,
                    agent_did TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    version TEXT NOT NULL,
                    service_endpoint TEXT NOT NULL,
                    protocol_extensions JSONB NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ans_agent_records_capability ON ans_agent_records(capability);
                CREATE INDEX IF NOT EXISTS idx_ans_agent_records_provider ON ans_agent_records(provider);
                CREATE INDEX IF NOT EXISTS idx_ans_agent_records_status ON ans_agent_records(status);
                """
            )
        conn.commit()
    logger.info("ANS Registry database initialized")


@app.on_event("startup")
async def startup_event():
    _init_db()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
async def _resolve_did_document(agent_did: str) -> Optional[dict]:
    """
    Confirm the DID actually resolves via Layer 1's did_registry service.
    This is the one required touchpoint into Layer 1 for this module.

    Real Layer 1 contract (from did_registry_service.py):
      GET /dids/{did_id:path}
      - 200 + {"status": "success", "did": ..., "data": {...}}  -> DID exists
      - 404 + {"detail": "..."}                                  -> DID not found
    Works for both did:key (resolved from the string itself, no DB hit)
    and did:web (resolved via Postgres) -- the HTTP contract is identical
    either way, so this function doesn't need to know which method was used.
    """
    url = f"{DID_REGISTRY_URL}/dids/{agent_did}"
    try:
        async with httpx.AsyncClient(timeout=DID_RESOLVE_TIMEOUT_SECONDS) as client:
            resp = await client.get(url)

        if resp.status_code == 200:
            body = resp.json()
            if body.get("status") == "success":
                data = body.get("data", body)
                return data.get("didDocument", data)
            logger.warning("did_registry returned 200 but unexpected body for %s: %s", agent_did, body)
            return None

        if resp.status_code == 404:
            logger.warning("DID not found in did_registry: %s", agent_did)
            return None

        logger.warning("Unexpected status from did_registry for %s: HTTP %s", agent_did, resp.status_code)
        return None

    except httpx.RequestError as exc:
        logger.error("Could not reach did_registry at %s: %s", url, exc)
        # Fail closed: if we can't verify the DID, we don't register the agent.
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"did_registry unreachable, cannot validate agentDid: {exc}",
        )


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _decode_signature(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except ValueError:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _verification_key(did_document: dict, verification_method: str) -> bytes:
    method = next(
        (item for item in did_document.get("verificationMethod", []) if item.get("id") == verification_method),
        None,
    )
    if not method or method.get("controller") != did_document.get("id"):
        raise PermissionError("registrationProof verification method is not controlled by agentDid")
    multibase = method.get("publicKeyMultibase", "")
    if not multibase.startswith("z"):
        raise PermissionError("registrationProof requires an Ed25519 base58btc key")
    decoded = base58.b58decode(multibase[1:])
    if decoded[:2] != bytes([0xED, 0x01]) or len(decoded[2:]) != 32:
        raise PermissionError("registrationProof key is not valid Ed25519")
    return decoded[2:]


def _verify_control_proof(agent_did: str, proof, did_document: dict, signed_payload: dict) -> None:
    if not REQUIRE_REGISTRATION_PROOF:
        return
    if proof is None:
        raise PermissionError("agent control proof is required")
    if not proof.verificationMethod.startswith(f"{agent_did}#"):
        raise PermissionError("agent control proof does not belong to agentDid")
    try:
        Ed25519PublicKey.from_public_bytes(_verification_key(did_document, proof.verificationMethod)).verify(
            _decode_signature(proof.signature),
            _canonical_json(signed_payload),
        )
    except (InvalidSignature, ValueError, KeyError) as exc:
        raise PermissionError("Invalid ANS agent control proof") from exc


def _find_by_id_or_404(record_id: str) -> AgentRecord:
    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM ans_agent_records WHERE record_id = %s", (record_id,))
                row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail=f"No agent record with id '{record_id}'")
        return _row_to_record(row)

    record = _registry.get(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"No agent record with id '{record_id}'")
    return record


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS count FROM ans_agent_records")
                count = cur.fetchone()["count"]
        return {"status": "healthy", "service": "ans_registry_service", "records": count, "storage": "postgres"}

    return {"status": "healthy", "service": "ans_registry_service", "records": len(_registry), "storage": "memory"}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------
@app.post("/register", response_model=AgentRecord, status_code=status.HTTP_201_CREATED)
async def register_agent(payload: AgentRegistrationRequest):
    """
    Register a new agent in the ANS.

    Flow:
      1. Reject duplicate ansName.
      2. Validate agentDid resolves via Layer 1 did_registry.
      3. Store the record.
    """
    did_document = await _resolve_did_document(payload.agentDid)
    if not did_document:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"agentDid '{payload.agentDid}' does not resolve -- register the DID first",
        )
    if did_document.get("lifecycleStatus") != "active":
        raise HTTPException(status_code=400, detail="agentDid is not active")
    try:
        record_data = AgentRegistrationData(**payload.model_dump(exclude={"registrationProof"})).model_dump(mode="json")
        _verify_control_proof(
            payload.agentDid,
            payload.registrationProof,
            did_document,
            {"action": "ans.register", "record": record_data},
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    record_id = str(uuid.uuid4())
    registration_data = payload.model_dump(exclude={"registrationProof"})
    record = AgentRecord(recordId=record_id, **registration_data)

    if _db_enabled():
        try:
            with _get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO ans_agent_records
                            (record_id, ans_name, agent_did, capability, provider, version,
                             service_endpoint, protocol_extensions, status, created_at, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            record.recordId,
                            record.ansName,
                            record.agentDid,
                            record.capability,
                            record.provider,
                            record.version,
                            record.serviceEndpoint,
                            Json([p.model_dump() if hasattr(p, "model_dump") else p for p in record.protocolExtensions]),
                            record.status,
                            record.createdAt,
                            record.updatedAt,
                        ),
                    )
                conn.commit()
        except psycopg2.errors.UniqueViolation:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"ansName '{payload.ansName}' is already registered",
            )

        logger.info("Registered agent %s (%s)", payload.ansName, payload.agentDid)
        return record

    if payload.ansName in _ans_name_index:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"ansName '{payload.ansName}' is already registered",
        )

    _registry[record_id] = record
    _ans_name_index[payload.ansName] = record_id

    logger.info("Registered agent %s (%s)", payload.ansName, payload.agentDid)
    return record


# ---------------------------------------------------------------------------
# Update
# ---------------------------------------------------------------------------
@app.patch("/agents/{record_id}", response_model=AgentRecord)
async def update_agent(record_id: str, payload: AgentUpdateRequest):
    record = _find_by_id_or_404(record_id)

    update_data = payload.model_dump(exclude_unset=True, exclude={"agentControlProof"})
    did_document = await _resolve_did_document(record.agentDid)
    if not did_document or did_document.get("lifecycleStatus") != "active":
        raise HTTPException(status_code=403, detail="Agent DID is not active")
    try:
        _verify_control_proof(
            record.agentDid,
            payload.agentControlProof,
            did_document,
            {"action": "ans.update", "recordId": record_id, "updates": update_data},
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    for field, value in update_data.items():
        setattr(record, field, value)

    record.updatedAt = datetime.now(timezone.utc)

    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE ans_agent_records
                    SET capability = %s,
                        provider = %s,
                        version = %s,
                        service_endpoint = %s,
                        protocol_extensions = %s,
                        status = %s,
                        updated_at = %s
                    WHERE record_id = %s
                    """,
                    (
                        record.capability,
                        record.provider,
                        record.version,
                        record.serviceEndpoint,
                        Json([p.model_dump() if hasattr(p, "model_dump") else p for p in record.protocolExtensions]),
                        record.status,
                        record.updatedAt,
                        record.recordId,
                    ),
                )
            conn.commit()
        logger.info("Updated agent record %s", record_id)
        return record

    _registry[record_id] = record
    logger.info("Updated agent record %s", record_id)
    return record


# ---------------------------------------------------------------------------
# Deregister
# ---------------------------------------------------------------------------
@app.delete("/agents/{record_id}", status_code=status.HTTP_200_OK)
async def deregister_agent(record_id: str, payload: AgentDeregisterRequest):
    record = _find_by_id_or_404(record_id)
    did_document = await _resolve_did_document(record.agentDid)
    if not did_document:
        raise HTTPException(status_code=403, detail="Agent DID cannot be resolved")
    try:
        _verify_control_proof(
            record.agentDid,
            payload.agentControlProof,
            did_document,
            {"action": "ans.deregister", "recordId": record_id},
        )
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    record.status = "deregistered"

    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE ans_agent_records SET status = %s, updated_at = %s WHERE record_id = %s",
                    ("deregistered", datetime.now(timezone.utc), record_id),
                )
            conn.commit()
        logger.info("Deregistered agent record %s", record_id)
        return {"recordId": record_id, "status": "deregistered"}

    _registry[record_id] = record
    logger.info("Deregistered agent record %s", record_id)
    return {"recordId": record_id, "status": "deregistered"}


# ---------------------------------------------------------------------------
# Lookup endpoints (consumed by Module 2 -- ANS Resolver)
# ---------------------------------------------------------------------------
@app.get("/agents/{record_id}", response_model=AgentRecord)
async def get_agent(record_id: str):
    return _find_by_id_or_404(record_id)


@app.get("/agents/by-name/{ans_name:path}", response_model=AgentRecord)
async def get_agent_by_name(ans_name: str):
    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM ans_agent_records WHERE ans_name = %s", (ans_name,))
                row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail=f"No agent registered under ansName '{ans_name}'")
        return _row_to_record(row)

    record_id = _ans_name_index.get(ans_name)
    if record_id is None:
        raise HTTPException(status_code=404, detail=f"No agent registered under ansName '{ans_name}'")
    return _find_by_id_or_404(record_id)


@app.post("/query", response_model=list[AgentRecord])
async def query_agents(query: AgentLookupQuery):
    """
    Capability-based search -- this is what the ANS Resolver (Module 2) calls.
    Simple substring/equality matching for now; can be swapped for a real
    query engine once the DB is wired in.
    """
    results: list[AgentRecord] = []
    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM ans_agent_records WHERE status = %s", (query.status,))
                rows = cur.fetchall()
        for row in rows:
            record = _row_to_record(row)
            if query.capability and query.capability.lower() not in record.capability.lower():
                continue
            if query.provider and query.provider.lower() != record.provider.lower():
                continue
            if query.ansNamePattern and query.ansNamePattern.replace("*", "") not in record.ansName:
                continue
            results.append(record)
        return results

    for record in _registry.values():
        if record.status != query.status:
            continue
        if query.capability and query.capability.lower() not in record.capability.lower():
            continue
        if query.provider and query.provider.lower() != record.provider.lower():
            continue
        if query.ansNamePattern and query.ansNamePattern.replace("*", "") not in record.ansName:
            continue
        results.append(record)
    return results


@app.get("/agents", response_model=list[AgentRecord])
async def list_agents(status_filter: Optional[str] = "active"):
    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                if status_filter is None:
                    cur.execute("SELECT * FROM ans_agent_records")
                else:
                    cur.execute("SELECT * FROM ans_agent_records WHERE status = %s", (status_filter,))
                rows = cur.fetchall()
        return [_row_to_record(row) for row in rows]

    return [r for r in _registry.values() if (status_filter is None or r.status == status_filter)]
