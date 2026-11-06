"""
main.py -- ANS Resolver Service (Module 2, Person B)
Port: 8009

Responsibilities:
  - Public query API: resolveAgentByCapability, resolveAgentByName.
  - Query the ANS Registry (Module 1, port 8008) for candidate agents.
  - Apply capability/protocol/version filtering on top of the registry's
    own substring-match query (belt-and-suspenders -- the registry does a
    first pass, this service does exact/structured filtering).
  - Verify any requiredAttestations against Layer 1's real credential
    stack: wallet_service (8007) + vc_verification (8005).
  - Sign each resolved record via Layer 1's kms (8001) so a caller can
    verify a single record's authenticity even outside a full response.

Storage: none -- this service is stateless. It composes calls to Module 1
and to Layer 1; it never stores agent records itself.

--------------------------------------------------------------------------
FIX (combined Layer 1 + Layer 2 integration): _verify_vc originally called
a made-up "POST /verify {subjectDid, vcType}" endpoint that doesn't exist
on the real vc_verification service, and _is_revoked called an equally
made-up "GET /status/{vc_id}" on status_list_service. Both always failed
(closed), so requiredAttestations was silently a no-op.

The real Layer 1 credential-checking flow is presentation-based, not a
flat type lookup:
  1. wallet_service GET /wallets/{did}/credentials?type=...&status=active
     -- cheap existence check + the only source of issuer/issueDate
     metadata (vc_verification's presentation pipeline returns merged
     claim *values*, not VC-level metadata like issuer or type).
  2. vc_verification POST /verify/nonce {verifierDID, purpose} -- a VP
     can't be built or verified without a fresh one-time nonce.
  3. wallet_service POST /wallets/{did}/present
       {agent_did, required_types, verifier_did, nonce}
     -- the wallet selects the matching VC(s), builds a VP, and signs it.
  4. vc_verification POST /verify/presentation {vp_jwt, nonce, verifierDID}
     -- runs the real 6-step pipeline (VP signature, nonce, VC signature,
     trust anchor, REVOCATION, expiry) in one call. This is why the old
     separate _is_revoked helper is gone entirely: step 5 of that pipeline
     already covers revocation, so a second, separately-broken revocation
     call is both redundant and unnecessary now.

For this to actually verify=true (not just avoid crashing), three Layer 1
preconditions must be true for a given attestation type, none of which
this service can set up itself:
  - The agent has a wallet (POST /wallets/{did}/init) with a real,
    unexpired VC of that type stored in it (POST /wallets/{did}/store).
  - The VC's issuer_did is authorised for that credential type + trust
    domain in trust_anchor (POST /trust-anchor/issuers on port 8003).
  - trust_anchor's own signing key (ROOT_TRUST_KEY_ID, default
    "root-trust-anchor-key") must actually exist in KMS -- like the
    resolver's and gateway's own signing keys, this is NOT auto-created;
    see test_attestation.py for how to provision it.
If any of those aren't true yet, this function still degrades gracefully
(verified=False for that one attestation) rather than crashing the whole
/resolve call -- same fail-closed philosophy as before, just against the
real contract this time.
--------------------------------------------------------------------------
"""

import os
import logging
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, status
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from models import (
    ResolveByCapabilityRequest,
    ResolveByNameRequest,
    ResolvedAgent,
    RelevantVcSnippet,
    AnsResolutionResponse,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ans_resolver_service")

# ---------------------------------------------------------------------------
# Config -- services we depend on
# ---------------------------------------------------------------------------
ANS_REGISTRY_URL = os.getenv("ANS_REGISTRY_URL", "http://ans_registry_service:8008")
VC_VERIFICATION_URL = os.getenv("VC_VERIFICATION_URL", "http://vc_verification:8005")
WALLET_SERVICE_URL = os.getenv("WALLET_SERVICE_URL", "http://wallet_service:8007")
KMS_URL = os.getenv("KMS_URL", "http://kms:8001")
SIGNING_KEY_ID = os.getenv("ANS_RESOLVER_SIGNING_KEY_ID", "ans-resolver-signing-key")
# This resolver's own DID, used as the "verifierDID" when it asks
# vc_verification for a nonce and checks a candidate's presentation.
# Doesn't need to be a real registered DID for the nonce/presentation flow
# itself to work -- it's just an identifier the pipeline threads through.
RESOLVER_VERIFIER_DID = os.getenv("ANS_RESOLVER_VERIFIER_DID", "did:web:layer2:ans-resolver")

REQUEST_TIMEOUT_SECONDS = float(os.getenv("DOWNSTREAM_TIMEOUT_SECONDS", "5"))

app = FastAPI(
    title="ANS Resolver Service",
    description="Layer 2 / Module 2 -- capability-based agent discovery (read path)",
    version="0.2.0",
)


# ---------------------------------------------------------------------------
# Helpers -- Module 1 (ANS Registry)
# ---------------------------------------------------------------------------
async def _query_registry(capability: str, provider: Optional[str]) -> list[dict]:
    """First-pass candidate fetch from the ANS Registry (Module 1)."""
    url = f"{ANS_REGISTRY_URL}/query"
    body = {"capability": capability, "provider": provider, "status": "active"}
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            resp = await client.post(url, json=body)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as exc:
        logger.error("ANS Registry query failed: HTTP %s -- %s", exc.response.status_code, exc.response.text)
        raise HTTPException(status_code=502, detail="ANS Registry query failed") from exc
    except httpx.RequestError as exc:
        logger.error("Could not reach ANS Registry at %s: %s", url, exc)
        raise HTTPException(status_code=502, detail=f"ANS Registry unreachable: {exc}") from exc


async def _get_by_name(ans_name: str) -> Optional[dict]:
    url = f"{ANS_REGISTRY_URL}/agents/by-name/{ans_name}"
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            resp = await client.get(url)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except httpx.RequestError as exc:
        logger.error("Could not reach ANS Registry at %s: %s", url, exc)
        raise HTTPException(status_code=502, detail=f"ANS Registry unreachable: {exc}") from exc


# ---------------------------------------------------------------------------
# Helpers -- Layer 1 (wallet_service / vc_verification / kms)
# ---------------------------------------------------------------------------
async def _verify_vc(agent_did: str, vc_type: str) -> RelevantVcSnippet:
    """
    Verify whether agent_did holds a genuine, unrevoked, unexpired VC of
    vc_type, using the real wallet_service + vc_verification presentation
    flow. See the module docstring above for the full rationale and the
    three Layer 1 preconditions this depends on.
    """
    # Step 1 -- does the wallet even claim to hold this credential type?
    # This is also our only source of issuer/issueDate metadata for the
    # snippet, since the presentation pipeline below returns claim
    # *values*, not VC-level metadata.
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            resp = await client.get(
                f"{WALLET_SERVICE_URL}/wallets/{agent_did}/credentials",
                params={"type": vc_type, "status": "active"},
            )
        resp.raise_for_status()
        held = resp.json().get("credentials", [])
    except httpx.RequestError as exc:
        logger.warning("wallet_service unreachable at %s: %s", WALLET_SERVICE_URL, exc)
        return RelevantVcSnippet(type=vc_type, verified=False)
    except httpx.HTTPStatusError as exc:
        logger.warning("wallet_service credential query rejected (HTTP %s): %s",
                        exc.response.status_code, exc.response.text)
        return RelevantVcSnippet(type=vc_type, verified=False)

    if not held:
        # Agent simply doesn't hold this credential -- not an error.
        return RelevantVcSnippet(type=vc_type, verified=False)

    meta = held[0]  # {vcId, type[], issuer, issuedAt, expiresAt, status}
    snippet = RelevantVcSnippet(
        type=vc_type,
        issuer=meta.get("issuer"),
        issueDate=meta.get("issuedAt"),
        verified=False,
    )

    # Steps 2-4 -- cryptographically prove it, via a fresh VP.
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            nonce_resp = await client.post(
                f"{VC_VERIFICATION_URL}/verify/nonce",
                json={"verifierDID": RESOLVER_VERIFIER_DID, "purpose": "ans_attestation_check"},
            )
            nonce_resp.raise_for_status()
            nonce = nonce_resp.json()["nonce"]

            present_resp = await client.post(
                f"{WALLET_SERVICE_URL}/wallets/{agent_did}/present",
                json={
                    "agent_did": agent_did,
                    "required_types": [vc_type],
                    "verifier_did": RESOLVER_VERIFIER_DID,
                    "nonce": nonce,
                },
            )
            present_resp.raise_for_status()
            vp_jwt = present_resp.json()["vp_jwt"]

            verify_resp = await client.post(
                f"{VC_VERIFICATION_URL}/verify/presentation",
                json={"vp_jwt": vp_jwt, "nonce": nonce, "verifierDID": RESOLVER_VERIFIER_DID},
            )
        verify_resp.raise_for_status()
        result = verify_resp.json()
        snippet.verified = bool(result.get("valid", False))
        # Step 5 of the pipeline (revocation) already ran inside
        # /verify/presentation -- surface it here rather than making a
        # second, separately-fragile call to status_list_service.
        snippet.revoked = (result.get("failedStep") == "REVOCATION") if not snippet.verified else False
        if not snippet.verified:
            logger.info(
                "Attestation %s for %s failed pipeline step %s: %s",
                vc_type, agent_did, result.get("failedStep"), result.get("reason"),
            )
    except httpx.RequestError as exc:
        logger.warning("wallet_service/vc_verification unreachable during presentation check: %s", exc)
    except httpx.HTTPStatusError as exc:
        logger.warning("Presentation verification rejected (HTTP %s): %s",
                        exc.response.status_code, exc.response.text)
    except (KeyError, ValueError) as exc:
        logger.warning("Unexpected response shape during presentation check: %s", exc)

    return snippet


async def _sign_record(record: dict) -> str:
    """
    Real Layer 1 contract (kms_service.py legacy route -- the current route
    POST /keys/{key_id}/sign is path-based, but the deprecated body-based
    alias below is kept for exactly this kind of caller and still works):
      POST /sign  { "key_id": ..., "payload": <base64-encoded bytes> }
      -> 200 { "status", "signature", "algorithm", "keyId" }
    kms.sign_payload() base64-decodes `payload` before signing, so the
    record must be JSON-serialised and base64-encoded first -- sending the
    raw dict (as this helper originally did) fails Pydantic validation.

    Signing is mandatory. Discovery fails closed if KMS cannot produce a
    signature because callers must never use an unauthenticated endpoint.
    """
    import base64
    import json as _json

    url = f"{KMS_URL}/sign"
    canonical = _json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    payload_b64 = base64.b64encode(canonical.encode("utf-8")).decode("ascii")
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
            resp = await client.post(url, json={"key_id": SIGNING_KEY_ID, "payload": payload_b64})
        resp.raise_for_status()
        signature = resp.json().get("signature")
        if not signature:
            raise HTTPException(status_code=502, detail="KMS returned no ANS record signature")
        return signature
    except (httpx.RequestError, httpx.HTTPStatusError) as exc:
        logger.error("KMS could not sign ANS record with %s: %s", SIGNING_KEY_ID, exc)
        raise HTTPException(status_code=502, detail="ANS record signing failed") from exc


# ---------------------------------------------------------------------------
# Matching logic
# ---------------------------------------------------------------------------
def _matches_filters(record: dict, req: ResolveByCapabilityRequest) -> bool:
    if req.versionPrefix and not str(record.get("version", "")).startswith(req.versionPrefix):
        return False
    if req.versionRange:
        try:
            normalized = req.versionRange.replace(" ", ",")
            if Version(str(record.get("version", ""))) not in SpecifierSet(normalized):
                return False
        except (InvalidSpecifier, InvalidVersion) as exc:
            raise HTTPException(status_code=422, detail=f"Invalid versionRange: {exc}") from exc
    if req.protocol:
        exts = record.get("protocolExtensions", []) or []
        if not any(e.get("protocol") == req.protocol for e in exts):
            return False
    return True


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "ans_resolver_service"}


# ---------------------------------------------------------------------------
# Resolution endpoints
# ---------------------------------------------------------------------------
@app.post("/resolveByCapability", response_model=AnsResolutionResponse)
async def resolve_by_capability(req: ResolveByCapabilityRequest):
    candidates = await _query_registry(req.capability, req.provider)
    candidates = [c for c in candidates if _matches_filters(c, req)][: req.maxResults]

    if not candidates:
        return AnsResolutionResponse(resolutionStatus="no_matches", resolvedAgents=[])

    resolved: list[ResolvedAgent] = []
    for candidate in candidates:
        snippets: list[RelevantVcSnippet] = []
        for vc_type in req.requiredAttestations:
            snippets.append(await _verify_vc(candidate["agentDid"], vc_type))

        # If attestations were required and any failed verification or came
        # back revoked, drop this candidate from the result set entirely.
        if req.requiredAttestations:
            if any((not s.verified) or s.revoked for s in snippets):
                logger.info(
                    "Dropping candidate %s -- failed required attestation check", candidate.get("ansName")
                )
                continue

        base_record = {
            "ansName": candidate["ansName"],
            "agentDid": candidate["agentDid"],
            "serviceEndpoint": candidate["serviceEndpoint"],
            "provider": candidate["provider"],
            "version": candidate["version"],
            "capability": candidate["capability"],
            "protocolExtensions": candidate.get("protocolExtensions", []),
            "relevantVcSnippets": [s.model_dump(mode="json") for s in snippets],
            "signingKeyId": SIGNING_KEY_ID,
            "signatureAlgorithm": "Ed25519",
        }
        signature = await _sign_record(base_record)

        resolved.append(
            ResolvedAgent(
                **base_record,
                ansRecordSignature=signature,
            )
        )

    if not resolved:
        return AnsResolutionResponse(resolutionStatus="no_matches", resolvedAgents=[])

    status_str = "success" if len(resolved) == len(candidates) else "partial"
    return AnsResolutionResponse(resolutionStatus=status_str, resolvedAgents=resolved)


@app.post("/resolveByName", response_model=AnsResolutionResponse)
async def resolve_by_name(req: ResolveByNameRequest):
    candidate = await _get_by_name(req.ansName)
    if candidate is None:
        return AnsResolutionResponse(resolutionStatus="no_matches", resolvedAgents=[])

    base_record = {
        "ansName": candidate["ansName"],
        "agentDid": candidate["agentDid"],
        "serviceEndpoint": candidate["serviceEndpoint"],
        "provider": candidate["provider"],
        "version": candidate["version"],
        "capability": candidate["capability"],
        "protocolExtensions": candidate.get("protocolExtensions", []),
        "relevantVcSnippets": [],
        "signingKeyId": SIGNING_KEY_ID,
        "signatureAlgorithm": "Ed25519",
    }
    signature = await _sign_record(base_record)

    resolved = ResolvedAgent(**base_record, ansRecordSignature=signature)
    return AnsResolutionResponse(resolutionStatus="success", resolvedAgents=[resolved])
