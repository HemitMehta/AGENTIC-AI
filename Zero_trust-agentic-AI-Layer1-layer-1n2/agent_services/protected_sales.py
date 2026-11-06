"""Obtain and use a task-bound Layer 3 grant without persisting bearer tokens."""
import base64
import hashlib
import json
import os
import ssl
import time
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from fastapi import HTTPException

from .common import canonical, check_signature, digest, json_call, key_from_kms, kms_public, sign
from .models import FinancialInput


def endpoint(name, default):
    value = os.environ.get(name, default).rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise HTTPException(503, "Protected resource connections require a configured HTTPS endpoint")
    return value


def tls_client():
    directory = Path(os.environ.get("LAYER3_SECURITY_DIR", "/run/layer3"))
    context = ssl.create_default_context(cafile=str(directory / "ca.crt"))
    return httpx.AsyncClient(verify=context, timeout=30, follow_redirects=False, trust_env=False)


def service_headers():
    directory = Path(os.environ.get("LAYER3_SECURITY_DIR", "/run/layer3"))
    token = (directory / "client.key").read_text(encoding="ascii").strip()
    if len(token) < 32:
        raise HTTPException(503, "Layer 3 service credential unavailable")
    return {"X-Service-ID": "risk_agent", "X-Service-Token": token}


async def verified_grant(client, decision, identity, resource_id, context):
    key_id = os.environ.get("TRUSTED_PEP_KEY_ID", "layer3-pep-signing-key")
    if decision.get("signingKeyId") != key_id or decision.get("signatureAlgorithm") != "Ed25519":
        raise HTTPException(403, "Untrusted PEP decision signer")
    key = key_from_kms(await kms_public(client, key_id))
    payload = {k: v for k, v in decision.items()
               if k not in {"decisionSignature", "signingKeyId", "signatureAlgorithm", "accessToken"}}
    check_signature(key, decision.get("decisionSignature"), canonical(payload))
    if (decision.get("agentDid") != identity["did"] or decision.get("resourceId") != resource_id
            or decision.get("action") != "QUERY_TABLE" or decision.get("contextHash") != digest(context)):
        raise HTTPException(403, "PEP decision is not bound to this task")
    if decision.get("effect") != "permit":
        raise HTTPException(403, "Layer 3 denied access; protected resource was not queried")
    try:
        token = decision["accessToken"]
        encoded, signature = token.split(".")
        key.verify(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)), encoded.encode("ascii"))
        claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if (claims["sub"] != identity["did"] or claims["resourceId"] != resource_id
                or claims["action"] != "QUERY_TABLE" or claims["jti"] != decision["decisionId"]
                or claims["contextHash"] != digest(context) or type(claims["exp"]) is not int
                or claims["exp"] <= int(time.time())):
            raise ValueError("Grant binding or expiry mismatch")
    except Exception as exc:
        raise HTTPException(403, "Invalid or expired PEP access token") from exc
    return token, claims


async def read_sales(client, identity, task):
    source = task.input
    context = {"jobId": source.jobId, "taskId": str(task.taskId), "requesterDid": task.issuerDid}
    verifier = os.environ.get("PDP_VERIFIER_DID", "did:web:layer3:pdp")
    verification = os.environ.get("VC_VERIFICATION_URL", "http://vc_verification:8005")
    wallet = os.environ.get("WALLET_SERVICE_URL", "http://wallet_service:8007")
    nonce = await json_call(client, "POST", f"{verification}/verify/nonce",
                            json={"verifierDID": verifier, "purpose": "agent_protected_sales"})
    vp = await json_call(client, "POST", f"{wallet}/wallets/{identity['did']}/present", json={
        "agent_did": identity["did"], "required_types": ["RoleVC", "JITVC"],
        "credential_ids": source.credentialIds, "verifier_did": verifier, "nonce": nonce["nonce"]})
    pep = endpoint("PEP_URL", "https://access_control_service:8016")
    sales = endpoint("PROTECTED_SALES_URL", "https://protected_sales_service:8019")
    async with tls_client() as protected:
        decision = await json_call(protected, "POST", f"{pep}/access/check", headers=service_headers(), json={
            "agentDid": identity["did"], "vpJwt": vp["vp_jwt"], "nonce": nonce["nonce"],
            "resourceId": source.resourceId, "action": "QUERY_TABLE", "context": context})
        token, claims = await verified_grant(client, decision, identity, source.resourceId, context)
        now = int(time.time())
        expires = min(now + 60, task.expiresAt, claims["exp"])
        if expires <= now:
            raise HTTPException(403, "Task expired before protected execution")
        body = {"resourceId": source.resourceId, "agentDid": identity["did"], "requestId": str(uuid4()),
                "issuedAt": now, "expiresAt": expires, "tokenHash": hashlib.sha256(token.encode()).hexdigest(),
                "period": source.period, "currency": source.currency, "limit": source.limit}
        body["proof"] = {"verificationMethod": identity["verificationMethod"],
                         "signature": await sign(client, identity["keyId"], {"action": "sales.query", **body})}
        data = await json_call(protected, "POST", f"{sales}/query", json=body,
                               headers={"Authorization": "Bearer " + token}, propagate_denial=True)
    if (data.get("resourceId") != source.resourceId or data.get("decisionId") != claims["jti"]
            or data.get("requestId") != body["requestId"]):
        raise HTTPException(403, "Database response is not bound to this request")
    rows = data.get("rows")
    if not isinstance(rows, list) or not rows or len(rows) > source.limit:
        raise HTTPException(422, "Protected query returned no usable financial rows")
    if any(row.get("currency") != source.currency or (source.period is not None and row.get("period") != source.period)
           for row in rows):
        raise HTTPException(403, "Database response does not match requested filters")
    financials = FinancialInput(currency=source.currency,
                                periods=[{k: row[k] for k in ("period", "revenue", "expenses")} for row in rows])
    provenance = {"source": "protected-sales", "resourceId": source.resourceId, "jobId": source.jobId,
                  "datasetVersion": data["datasetVersion"], "rowCount": len(rows),
                  "filters": {"period": source.period, "currency": source.currency, "limit": source.limit},
                  "decisionId": claims["jti"], "matchedPolicies": decision["matchedPolicies"],
                  "grantExpiresAt": claims["exp"]}
    return financials, provenance
