"""PIP: fresh attribute collection and revalidation of server-held evidence."""
import base64
import json
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from layer3_common.crypto import did_document, fingerprint
from layer3_common.models import RevalidationRequest, VerifiedAccessRequest, TrustedContext
from layer3_common.policy import equal
from layer3_common.security import install, request as http_request

VC_VERIFICATION_URL = os.getenv("VC_VERIFICATION_URL", "http://vc_verification:8005")
PAP_URL = os.getenv("PAP_URL", "https://policy_administration_service:8013")
PDP_VERIFIER_DID = os.getenv("PDP_VERIFIER_DID", "did:web:layer3:pdp")
app = FastAPI(title="Layer 3 Policy Information Point", version="2.0.0")
install(app, "pip")


AttributeRequest = VerifiedAccessRequest


def decode(value):
    return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))


async def gather(agent, resource_id, action, context, credentials, expected_key=None, upper_expiry=None,
                 trusted_context=None):
    document = await did_document(agent)
    key_hash = fingerprint(document)
    if expected_key and expected_key != key_hash:
        raise HTTPException(403, "Holder key changed since authorization")
    resource_response = await http_request("GET", f"{PAP_URL}/resources/{quote(resource_id, safe='')}")
    resource_response.raise_for_status()
    resource = resource_response.json()
    if not isinstance(resource, dict) or resource.get("resourceId") != resource_id or resource.get("active") is False:
        raise HTTPException(403, "Resource identity mismatch or inactive resource")
    claims, types, ids, issuers, expirations, verified_credentials = {}, set(), [], [], [], []
    if upper_expiry is not None:
        expirations.append(int(upper_expiry))
    for credential in credentials:
        subject = credential.get("credentialSubject", {})
        if subject.get("id") != agent:
            raise HTTPException(403, "Credential subject does not match holder")
        status = credential.get("credentialStatus", {})
        if not status.get("statusListCredential") or status.get("statusListIndex") is None:
            raise HTTPException(403, "Layer 3 requires revocable credentials")
        issuer = credential.get("issuer")
        issuer = issuer.get("id") if isinstance(issuer, dict) else issuer
        await did_document(issuer)
        verified = await http_request("POST", f"{VC_VERIFICATION_URL}/verify/credential",
                                      json={"credential": credential, "fresh_status": True})
        verified.raise_for_status()
        if verified.json().get("valid") is not True:
            raise HTTPException(403, {"message": "Credential no longer valid", "verification": verified.json()})
        try:
            expiry = datetime.fromisoformat(credential["expirationDate"].replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                raise ValueError("Expiration must include a timezone")
            expirations.append(int(expiry.timestamp()))
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(403, "Layer 3 credentials require a valid expiry") from exc
        vc_types = credential.get("type", [])
        if not isinstance(vc_types, list):
            raise HTTPException(403, "Invalid credential types")
        types.update(t for t in vc_types if t != "VerifiableCredential")
        ids.append(credential["id"])
        issuers.append(issuer)
        verified_credentials.append({"id": credential["id"], "issuer": issuer, "type": vc_types,
                                     "credentialSubject": subject, "expiresAt": credential["expirationDate"]})
        for key, value in subject.items():
            if key == "id":
                continue
            if key in claims and not equal(claims[key]["value"], value):
                raise HTTPException(403, "Conflicting credential claims")
            claims[key] = {"value": value, "vcId": credential["id"], "issuerDID": issuer,
                           "expiresAt": credential["expirationDate"]}
    expires = min(expirations)
    if expires <= int(datetime.now(timezone.utc).timestamp()):
        raise HTTPException(403, "Authorization evidence expired")
    now = datetime.now(timezone.utc)
    return {"agent": {"did": agent, "didDocument": document, "claims": claims,
                      "credentials": verified_credentials,
                      "credentialTypes": sorted(types), "credentialIds": ids, "credentialIssuers": issuers},
            "resource": resource,
            "environment": {**(trusted_context or {}), "requestTime": now.isoformat(),
                            "unixTime": int(now.timestamp()), "utcHour": now.hour, "utcWeekday": now.weekday()},
            "request": {"action": action, "context": {**context, "requestTime": now.isoformat()}},
            "authorizationState": {"agentDid": agent, "resourceId": resource_id, "action": action,
                                   "context": context, "credentials": credentials, "holderKeyHash": key_hash,
                                   "expiresAt": expires, "trustedContext": trusted_context or {}}}


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "policy_information_point"}


@app.post("/attributes/collect")
async def collect_attributes(request: AttributeRequest, http: Request):
    if http.state.caller != "pdp":
        request.trustedContext = TrustedContext(sourceIp=http.client.host if http.client else None,
                                               callerService=http.state.caller)
    verified = await http_request("POST", f"{VC_VERIFICATION_URL}/verify/presentation",
                                  json={"vp_jwt": request.vpJwt, "nonce": request.nonce, "verifierDID": PDP_VERIFIER_DID})
    verified.raise_for_status()
    if verified.json().get("valid") is not True:
        raise HTTPException(403, {"message": "VP verification failed", "verification": verified.json()})
    try:
        payload = decode(request.vpJwt.split(".")[1])
        if payload.get("iss") != request.agentDid or payload.get("holder") != request.agentDid:
            raise ValueError("VP holder does not match agentDid")
        credentials = [decode(c.split(".")[1]) if isinstance(c, str) else c for c in payload["verifiableCredential"]]
        if not 1 <= len(credentials) <= 20:
            raise ValueError("Invalid number of credentials")
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise HTTPException(403, "Invalid presentation metadata") from exc
    return await gather(request.agentDid, request.resourceId, request.action, request.context, credentials,
                        upper_expiry=payload.get("exp"), trusted_context=request.trustedContext.model_dump())


@app.post("/attributes/revalidate")
async def revalidate(request: RevalidationRequest):
    return await gather(request.agentDid, request.resourceId, request.action, request.context, request.credentials,
                        request.holderKeyHash, request.expiresAt, request.trustedContext.model_dump())
