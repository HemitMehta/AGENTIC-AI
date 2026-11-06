"""Layer 3 PEP: bound, persisted grants with live authorization revalidation."""
import base64
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Any

import httpx
import psycopg2
from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, HTTPException, Request, Query
from psycopg2.extras import Json, RealDictCursor
from pydantic import BaseModel, Field, IPvAnyAddress

from layer3_common.crypto import canonical
from layer3_common.models import AccessRequest
from layer3_common import audit
from layer3_common.security import database_kwargs, install, request as http_request, secret

PDP_URL = os.getenv("PDP_URL", "https://policy_decision_service:8015")
KMS_URL = os.getenv("KMS_URL", "http://kms:8001")
SIGNING_KEY_ID = os.getenv("PEP_SIGNING_KEY_ID", "layer3-pep-signing-key")
TOKEN_TTL_SECONDS = int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", "120"))
app = FastAPI(title="Layer 3 Access Control / Policy Enforcement Point", version="2.0.0")
install(app, "pep")


class IntrospectionRequest(BaseModel):
    token: str = Field(min_length=1, max_length=32768)
    resourceId: str | None = None
    action: str | None = None
    sourceIp: IPvAnyAddress | None = None


class RevocationRequest(BaseModel):
    decisionId: str


def _db():
    return psycopg2.connect(**database_kwargs(), cursor_factory=RealDictCursor)


def _b64url(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def token_hash(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


async def _sign(payload):
    response = await http_request("POST", f"{KMS_URL}/keys/{SIGNING_KEY_ID}/sign",
                                  json={"payload": base64.b64encode(payload).decode("ascii")})
    response.raise_for_status()
    return response.json()["signature"]


async def _public_key():
    response = await http_request("GET", f"{KMS_URL}/keys/{SIGNING_KEY_ID}/public")
    response.raise_for_status()
    body = response.json()
    if body.get("keyStatus") != "active":
        raise ValueError("PEP signing key is not active")
    encoded = body["publicKey"]
    key = (serialization.load_pem_public_key(encoded.encode("ascii")) if encoded.startswith("-----BEGIN")
           else Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded)))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("PEP signing key is not Ed25519")
    return key


def _init_db():
    with _db() as conn, conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS layer3_access_audit (
                decision_id TEXT PRIMARY KEY, agent_did TEXT NOT NULL, resource_id TEXT NOT NULL,
                action TEXT NOT NULL, effect TEXT NOT NULL, decision JSONB NOT NULL,
                recorded_at TIMESTAMPTZ NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_layer3_audit_agent ON layer3_access_audit(agent_did, recorded_at);
            CREATE TABLE IF NOT EXISTS layer3_grants (
                decision_id TEXT PRIMARY KEY REFERENCES layer3_access_audit(decision_id),
                token_hash TEXT UNIQUE NOT NULL, evidence TEXT NOT NULL,
                resource_version INTEGER NOT NULL, policy_refs JSONB NOT NULL,
                expires_at BIGINT NOT NULL, revoked_at TIMESTAMPTZ);
        """)
        audit.initialize(cur)
        audit.protect(cur, "layer3_access_audit")


def _record(result, state, claims):
    # Never persist bearer tokens or plaintext credential evidence in audit records.
    decision = {k: v for k, v in result.items() if k != "accessToken"}
    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO layer3_access_audit VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (decision["decisionId"], decision["agentDid"], decision["resourceId"], decision["action"],
             decision["effect"], Json(decision), datetime.now(timezone.utc)))
        audit.append(cur, "pep.decision", decision, decision["agentDid"])
        if claims:
            encrypted = Fernet(secret("evidence.key").encode()).encrypt(canonical(state)).decode()
            cur.execute(
                "INSERT INTO layer3_grants (decision_id,token_hash,evidence,resource_version,policy_refs,expires_at) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (decision["decisionId"], token_hash(result["accessToken"]), encrypted,
                 decision["resourceVersion"], Json(claims["policyRefs"]), claims["exp"]))


def _grant(decision_id):
    with _db() as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM layer3_grants WHERE decision_id = %s", (decision_id,))
        return cur.fetchone()


@app.on_event("startup")
async def startup():
    _init_db()


@app.get("/health")
async def health():
    with _db() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1")
    return {"status": "healthy", "service": "policy_enforcement_point", "defaultEffect": "deny"}


@app.post("/access/check")
async def check_access(request: AccessRequest, http: Request):
    try:
        body = request.model_dump(mode="json")
        body["trustedContext"] = {"sourceIp": http.client.host if http.client else None,
                                  "callerService": http.state.caller}
        response = await http_request("POST", f"{PDP_URL}/decisions", json=body)
        response.raise_for_status()
        decision = response.json()
        state = decision.pop("authorizationState", None)
        decision.pop("resource", None)
        if decision.get("effect") == "permit" and (not state or state["expiresAt"] <= int(time.time())):
            decision.update(effect="deny", reasons=["Authorization evidence expired before token issuance"])
        result = {**decision, "decisionSignature": await _sign(canonical(decision)),
                  "signingKeyId": SIGNING_KEY_ID, "signatureAlgorithm": "Ed25519", "accessToken": None}
        claims = None
        if decision["effect"] == "permit":
            now = int(time.time())
            claims = {"jti": decision["decisionId"], "sub": decision["agentDid"],
                      "resourceId": decision["resourceId"], "action": decision["action"],
                      "policyRefs": decision["matchedPolicies"], "resourceVersion": decision["resourceVersion"],
                      "contextHash": decision["contextHash"], "iat": now,
                      "exp": min(now + TOKEN_TTL_SECONDS, state["expiresAt"])}
            encoded = _b64url(canonical(claims))
            signature = await _sign(encoded.encode("ascii"))
            result["accessToken"] = f"{encoded}.{_b64url(base64.b64decode(signature))}"
        _record(result, state, claims)
        return result
    except (httpx.HTTPError, ValueError, KeyError, TypeError, OSError, psycopg2.Error) as exc:
        raise HTTPException(503, "Authorization dependencies unavailable; access denied") from exc


@app.post("/access/introspect")
async def introspect(request: IntrospectionRequest, http: Request = None):
    try:
        encoded, signature = request.token.split(".")
        claims = json.loads(_b64url_decode(encoded))
        (await _public_key()).verify(_b64url_decode(signature), encoded.encode("ascii"))
        if not isinstance(claims, dict) or type(claims.get("exp")) is not int:
            raise ValueError("Invalid claims")
        if claims["exp"] <= int(time.time()):
            return {"active": False, "reason": "token expired"}
        if request.resourceId and claims.get("resourceId") != request.resourceId:
            return {"active": False, "reason": "resource scope mismatch"}
        if request.action and claims.get("action") != request.action:
            return {"active": False, "reason": "action scope mismatch"}
        grant = _grant(claims["jti"])
        if not grant or grant["token_hash"] != token_hash(request.token) or grant["revoked_at"]:
            return {"active": False, "reason": "grant unknown or revoked"}
        evidence = json.loads(Fernet(secret("evidence.key").encode()).decrypt(grant["evidence"].encode()))
        if http is not None:
            # Only the authenticated resource adapter may report its observed network peer.
            source_ip = (str(request.sourceIp) if request.sourceIp is not None else None) if http.state.caller == "sales" else (
                http.client.host if http.client else None)
            if source_ip is None:
                return {"active": False, "reason": "current request origin unavailable"}
            evidence["trustedContext"] = {**evidence.get("trustedContext", {}), "sourceIp": source_ip}
        response = await http_request("POST", f"{PDP_URL}/decisions/revalidate", json=evidence)
        response.raise_for_status()
        decision = response.json()
        if decision.get("effect") != "permit":
            return {"active": False, "reason": "current authorization denied"}
        if (decision.get("resourceVersion") != grant["resource_version"]
                or decision.get("matchedPolicies") != grant["policy_refs"]):
            return {"active": False, "reason": "policy or resource changed; obtain a new grant"}
        # Recheck locally after remote calls, including revocations racing with revalidation.
        current = _grant(claims["jti"])
        if not current or current["revoked_at"] or claims["exp"] <= int(time.time()):
            return {"active": False, "reason": "grant revoked or expired"}
        return {"active": True, "claims": claims, "resource": decision["resource"], "signingKeyId": SIGNING_KEY_ID}
    except (ValueError, KeyError, TypeError, InvalidSignature, InvalidToken):
        return {"active": False, "reason": "invalid token or authorization evidence"}
    except (httpx.HTTPError, OSError, psycopg2.Error, HTTPException):
        return {"active": False, "reason": "authorization dependencies unavailable"}


@app.post("/access/revoke")
async def revoke(request: RevocationRequest, http: Request):
    with _db() as conn, conn.cursor() as cur:
        cur.execute("UPDATE layer3_grants SET revoked_at=COALESCE(revoked_at, NOW()) WHERE decision_id=%s",
                    (request.decisionId,))
        if not cur.rowcount:
            raise HTTPException(404, "Grant not found")
        audit.append(cur, "pep.revoke", {"decisionId": request.decisionId}, http.state.caller)
    return {"revoked": True, "decisionId": request.decisionId}


@app.get("/audit")
async def list_audit(agentDid: str | None = None, resourceId: str | None = None,
                     before: datetime | None = None, limit: int = Query(100, ge=1, le=1000)):
    with _db() as conn, conn.cursor() as cur:
        cur.execute("""SELECT decision, recorded_at FROM layer3_access_audit
            WHERE (%s IS NULL OR agent_did=%s) AND (%s IS NULL OR resource_id=%s)
            AND (%s IS NULL OR recorded_at < %s) ORDER BY recorded_at DESC, decision_id LIMIT %s""",
                    (agentDid, agentDid, resourceId, resourceId, before, before, limit))
        return {"decisions": cur.fetchall()}


@app.get("/audit/events")
async def audit_events(after: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000)):
    return audit.events(_db, after, limit)


@app.get("/audit/integrity")
async def audit_integrity():
    return audit.integrity(_db)


@app.get("/audit/{decision_id}")
async def get_audit(decision_id: str):
    with _db() as conn, conn.cursor() as cur:
        cur.execute("SELECT decision FROM layer3_access_audit WHERE decision_id=%s", (decision_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Decision audit record not found")
    return row["decision"]
