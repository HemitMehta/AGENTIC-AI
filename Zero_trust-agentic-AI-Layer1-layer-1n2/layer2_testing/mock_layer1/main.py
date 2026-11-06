"""
mock_layer1/main.py -- Minimal Layer 1 stand-in for isolated Layer 2 tests.

This fixture implements only the Layer 1 HTTP contracts used by the current
Layer 2 services:
  - DID registry resolution
  - wallet credential lookup and presentation creation
  - nonce generation and presentation verification
  - KMS signing
  - reputation VC issuance
"""

import base64
import hashlib
import json
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException

app = FastAPI(title="Mock Layer 1 (test fixture only)")

_known_dids = {
    "did:web:acme:agent:riskanalyzer:beta-007",
    "did:web:company:ocr17",
    "did:web:untrusted:agent:mystery-001",
    "did:web:enterprise:agent:orchestrator:alpha-001",
}

_credentials = {
    ("did:web:acme:agent:riskanalyzer:beta-007", "SOXComplianceCertified"): {
        "vcId": "vc-sox-001",
        "type": ["VerifiableCredential", "SOXComplianceCertified"],
        "issuer": "did:web:acme:audit",
        "issuedAt": "2025-01-15T00:00:00Z",
        "expiresAt": "2030-01-15T00:00:00Z",
        "status": "active",
    },
    ("did:web:acme:agent:riskanalyzer:beta-007", "RevokedCredentialTest"): {
        "vcId": "vc-revoked-001",
        "type": ["VerifiableCredential", "RevokedCredentialTest"],
        "issuer": "did:web:acme:audit",
        "issuedAt": "2025-01-15T00:00:00Z",
        "expiresAt": "2030-01-15T00:00:00Z",
        "status": "active",
    },
}


def _digest_signature(body: dict) -> str:
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
    return f"sha256:{digest[:16]}"


@app.get("/dids/{did_id:path}")
async def resolve_did(did_id: str):
    if did_id in _known_dids:
        return {"status": "success", "did": did_id, "data": {}}
    raise HTTPException(404, detail=f"DID not found: {did_id}")


@app.get("/wallets/{agent_did:path}/credentials")
async def list_credentials(agent_did: str, type: str | None = None, status: str = "active"):
    credentials = []
    for (did, vc_type), credential in _credentials.items():
        if did != agent_did:
            continue
        if type is not None and vc_type != type:
            continue
        if credential.get("status") != status:
            continue
        credentials.append(credential)
    return {"credentials": credentials}


@app.post("/verify/nonce")
async def create_nonce(body: dict):
    verifier = body.get("verifierDID", "did:web:test:verifier")
    raw = f"{verifier}:{body.get('purpose', 'test')}:{datetime.now(timezone.utc).isoformat()}"
    nonce = hashlib.sha256(raw.encode()).hexdigest()[:24]
    return {"nonce": nonce, "expiresAt": "2030-01-01T00:00:00Z"}


@app.post("/wallets/{agent_did:path}/present")
async def present(agent_did: str, body: dict):
    required_types = body.get("required_types", [])
    vcs = []
    for vc_type in required_types:
        meta = _credentials.get((agent_did, vc_type))
        if meta is None:
            raise HTTPException(404, detail=f"Credential {vc_type} not found")
        vcs.append(
            {
                "id": meta["vcId"],
                "type": meta["type"],
                "issuer": meta["issuer"],
                "issuanceDate": meta["issuedAt"],
                "expirationDate": meta["expiresAt"],
                "credentialSubject": {"id": agent_did, "attestationType": vc_type},
            }
        )

    payload = {
        "iss": agent_did,
        "nonce": body.get("nonce"),
        "vp": {"type": ["VerifiablePresentation"], "verifiableCredential": vcs},
    }
    payload_json = json.dumps(payload, separators=(",", ":")).encode()
    vp_jwt = "mock." + base64.urlsafe_b64encode(payload_json).decode().rstrip("=") + ".signature"
    return {"vp_jwt": vp_jwt}


@app.post("/verify/presentation")
async def verify_presentation(body: dict):
    try:
        payload_part = body["vp_jwt"].split(".")[1]
        payload_part += "=" * (-len(payload_part) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_part.encode()))
    except Exception as exc:
        raise HTTPException(400, detail=f"Invalid mock VP: {exc}") from exc

    vcs = payload.get("vp", {}).get("verifiableCredential", [])
    if any(vc.get("id") == "vc-revoked-001" for vc in vcs):
        return {
            "valid": False,
            "failedStep": "REVOCATION",
            "reason": "Credential vc-revoked-001 has been revoked",
        }

    return {"valid": True, "verifiedClaims": {"mockVerified": True}}


@app.post("/keys/{key_id}/sign")
async def sign_by_path(key_id: str, body: dict):
    return {"status": "success", "signature": _digest_signature({"key_id": key_id, **body})}


@app.post("/sign")
async def sign_legacy(body: dict):
    return {"status": "success", "signature": _digest_signature(body)}


@app.post("/issue/reputation")
async def issue_reputation(body: dict):
    return {
        "status": "success",
        "vc_id": "vc:jwt:uri:reputation-service:mock-001",
        "credential_type": "ReputationCredential",
        "signedVC": {"id": "vc:jwt:uri:reputation-service:mock-001"},
        "expiresAt": "2030-01-01T00:00:00Z",
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "mock_layer1"}
