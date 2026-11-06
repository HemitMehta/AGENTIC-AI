"""
main.py -- Discovery Gateway (Module 5, Shared)
Port: 8012

Responsibilities:
  Thin orchestrator, no business logic of its own beyond ranking:
    1. Call Discovery Trust Policy Service (Module 3, 8010) -- reject early
       if the requested registry/provider/capability domain isn't trusted.
    2. Call ANS Resolver Service (Module 2, 8009) -- get verified, signed
       candidate agent records for the requested capability.
    3. Call Reputation Service (Module 4, 8011) -- enrich each candidate
       with its aggregated reputation score.
    4. Rank candidates (baseline: reputation score, since Capability Match /
       Intent Match / Trust Prediction / Context are AIADTE Phase 2
       extensions not yet built) and select the best one.
    5. Sign the final unified response via Layer 1's kms (8001) and return it.

This module has no persistent storage and depends only on Modules 2, 3, 4,
plus kms directly for the final response signature. It is intentionally
built last, once Modules 1-4 are individually stable, per the team's build
order -- it is mostly wiring.

IMPORTANT -- contract assumption:
  The kms /sign contract below is ASSUMED, matching the same assumption
  documented in module2_ans_resolver/main.py. Confirm against the actual
  Layer 1 kms service source before relying on this in a real integration
  test.
"""

import os
import base64
import json
import logging

import httpx
from fastapi import FastAPI, HTTPException
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from models import DiscoveryRequest, DiscoveryResponse, CandidateSummary

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("discovery_gateway")

# ---------------------------------------------------------------------------
# Config -- downstream Layer 2 modules + Layer 1 kms
# ---------------------------------------------------------------------------
TRUST_POLICY_URL = os.getenv("TRUST_POLICY_URL", "http://discovery_trust_policy_service:8010")
ANS_RESOLVER_URL = os.getenv("ANS_RESOLVER_URL", "http://ans_resolver_service:8009")
REPUTATION_SERVICE_URL = os.getenv("REPUTATION_SERVICE_URL", "http://reputation_service:8011")
KMS_URL = os.getenv("KMS_URL", "http://kms:8001")
SIGNING_KEY_ID = os.getenv("GATEWAY_SIGNING_KEY_ID", "discovery-gateway-signing-key")
RESOLVER_SIGNING_KEY_ID = os.getenv("ANS_RESOLVER_SIGNING_KEY_ID", "ans-resolver-signing-key")

REQUEST_TIMEOUT_SECONDS = float(os.getenv("DOWNSTREAM_TIMEOUT_SECONDS", "5"))

app = FastAPI(
    title="Discovery Gateway",
    description="Layer 2 / Module 5 -- unified discovery + trust orchestration entry point",
    version="0.1.0",
)


# ---------------------------------------------------------------------------
# Step 1 -- Discovery Trust Policy Service
# ---------------------------------------------------------------------------
async def _check_trust(req: DiscoveryRequest) -> tuple[bool, list[str]]:
    url = f"{TRUST_POLICY_URL}/check"
    body = {"registryId": req.registryId, "provider": req.provider, "capability": req.capability}
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            resp = await client.post(url, json=body)
        resp.raise_for_status()
        data = resp.json()
        return bool(data.get("trusted", False)), data.get("reasons", [])
    except httpx.RequestError as exc:
        logger.error("Discovery Trust Policy Service unreachable at %s: %s", url, exc)
        # Fail closed: if we can't confirm the source is trusted, reject.
        return False, [f"trust policy service unreachable: {exc}"]


# ---------------------------------------------------------------------------
# Step 2 -- ANS Resolver
# ---------------------------------------------------------------------------
async def _resolve_candidates(req: DiscoveryRequest) -> list[dict]:
    url = f"{ANS_RESOLVER_URL}/resolveByCapability"
    body = {
        "capability": req.capability,
        "provider": req.provider,
        "protocol": req.protocol,
        "versionPrefix": req.versionPrefix,
        "versionRange": req.versionRange,
        "requiredAttestations": req.requiredAttestations,
        "maxResults": req.maxCandidates,
    }
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            resp = await client.post(url, json=body)
        resp.raise_for_status()
        return resp.json().get("resolvedAgents", [])
    except httpx.RequestError as exc:
        logger.error("ANS Resolver unreachable at %s: %s", url, exc)
        raise HTTPException(status_code=502, detail=f"ANS Resolver unreachable: {exc}") from exc


def _load_ed25519_public_key(value: str) -> Ed25519PublicKey:
    if value.startswith("-----BEGIN"):
        key = serialization.load_pem_public_key(value.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("ANS resolver KMS key is not Ed25519")
        return key
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(value))


async def _verify_ans_record(record: dict) -> bool:
    signature = record.get("ansRecordSignature")
    key_id = record.get("signingKeyId")
    if not signature or key_id != RESOLVER_SIGNING_KEY_ID or record.get("signatureAlgorithm") != "Ed25519":
        return False

    signed_record = {
        key: value for key, value in record.items()
        if key != "ansRecordSignature"
    }
    canonical = json.dumps(signed_record, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.get(f"{KMS_URL}/keys/{key_id}/public")
        response.raise_for_status()
        public_body = response.json()
        if public_body.get("keyStatus") != "active":
            return False
        public_key = _load_ed25519_public_key(public_body["publicKey"])
        public_key.verify(base64.b64decode(signature), canonical)
        return True
    except (httpx.RequestError, httpx.HTTPStatusError, InvalidSignature, ValueError, KeyError):
        logger.warning("Rejected ANS record with invalid signature for key %s", key_id)
        return False


# ---------------------------------------------------------------------------
# Step 3 -- Reputation Service
# ---------------------------------------------------------------------------
async def _get_reputation(agent_did: str) -> tuple[float, int]:
    url = f"{REPUTATION_SERVICE_URL}/reputation/{agent_did}"
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            resp = await client.get(url)
        resp.raise_for_status()
        data = resp.json()
        return float(data.get("score", 0.0)), int(data.get("sampleSize", 0))
    except httpx.RequestError as exc:
        logger.warning("Reputation Service unreachable at %s, defaulting to score 0: %s", url, exc)
        return 0.0, 0


# ---------------------------------------------------------------------------
# Step 5 -- sign the final response
# ---------------------------------------------------------------------------
async def _sign_response(payload: dict) -> str:
    """
    Real Layer 1 contract (kms_service.py legacy route, deprecated but
    still served): POST /sign { "key_id": ..., "payload": <base64 bytes> }
    -> { "signature": ... }. Payload must be JSON-serialised + base64
    encoded first -- see the identical fix in
    ans_resolver_service/main.py::_sign_record for the full rationale.
    """
    import base64
    import json as _json

    url = f"{KMS_URL}/sign"
    payload_b64 = base64.b64encode(_json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).decode("ascii")
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            resp = await client.post(url, json={"key_id": SIGNING_KEY_ID, "payload": payload_b64})
        resp.raise_for_status()
        signature = resp.json().get("signature")
        if not signature:
            raise HTTPException(status_code=502, detail="KMS returned no gateway signature")
        return signature
    except (httpx.RequestError, httpx.HTTPStatusError) as exc:
        logger.error("KMS could not sign discovery response with %s: %s", SIGNING_KEY_ID, exc)
        raise HTTPException(status_code=502, detail="Discovery response signing failed") from exc


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "discovery_gateway"}


# ---------------------------------------------------------------------------
# The one public endpoint
# ---------------------------------------------------------------------------
@app.post("/discover", response_model=DiscoveryResponse)
async def discover(req: DiscoveryRequest):
    # 1. Trust Policy check
    trusted, reasons = await _check_trust(req)
    if not trusted:
        logger.info("Discovery request rejected by trust policy: %s", reasons)
        return DiscoveryResponse(resolutionStatus="rejected_by_trust_policy", rejectionReasons=reasons)

    # 2. ANS Resolver query
    raw_candidates = await _resolve_candidates(req)
    verified_candidates = []
    for candidate in raw_candidates:
        if await _verify_ans_record(candidate):
            verified_candidates.append(candidate)
    raw_candidates = verified_candidates
    if not raw_candidates:
        return DiscoveryResponse(resolutionStatus="no_matches")

    # 3. Reputation enrichment
    candidates: list[CandidateSummary] = []
    for c in raw_candidates:
        score, sample_size = await _get_reputation(c["agentDid"])
        candidates.append(
            CandidateSummary(
                ansName=c["ansName"],
                agentDid=c["agentDid"],
                serviceEndpoint=c["serviceEndpoint"],
                provider=c["provider"],
                version=c["version"],
                capability=c["capability"],
                reputationScore=score,
                reputationSampleSize=sample_size,
                ansRecordSignature=c.get("ansRecordSignature"),
                signingKeyId=c["signingKeyId"],
                signatureAlgorithm=c["signatureAlgorithm"],
                signatureVerified=True,
                ansRecord=c,
            )
        )

    # 4. Rank by verified reputation, then by the amount of supporting
    # evidence. The rule is deterministic and all inputs come from services.
    candidates.sort(key=lambda c: (c.reputationScore, c.reputationSampleSize), reverse=True)
    best = candidates[0]

    response = DiscoveryResponse(
        resolutionStatus="success",
        selectedAgent=best.agentDid,
        endpoint=best.serviceEndpoint,
        reputation=best.reputationScore,
        capabilities=[best.capability],
        candidates=candidates,
        requestId=req.requestId,
    )

    # 5. Sign the final response
    response.gatewaySignature = await _sign_response(response.model_dump(mode="json", exclude={"gatewaySignature"}))
    return response
