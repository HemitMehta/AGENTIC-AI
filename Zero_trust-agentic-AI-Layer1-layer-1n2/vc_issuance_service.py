"""
vc_issuance_service.py
FastAPI wrapper for VC Issuance Service (SubSystem 4)
Exposes vc_issuance.py functions as HTTP endpoints.

--------------------------------------------------------------------------
FIX (audit finding #3): every issue_*_vc endpoint previously called the
underlying vc_issuance.py functions with the wrong number and order of
arguments -- e.g.:

    vc_issuance.issue_role_vc(request.issuer_did, request.subject_did, request.role)

but the real signature is:

    issue_role_vc(subject_did, issuer_did, issuer_key_id, claims, trust_domain=..., valid_until_iso=None)

This meant issuer_did/subject_did were silently swapped, and the required
`claims` dict was missing entirely -- confirmed to crash immediately with:
    TypeError: issue_role_vc() missing 1 required positional argument: 'claims'

Fixed by:
  - Adding `issuer_key_id: str` and `claims: dict` to every request model
    (these were missing before -- there was no way to pass them at all).
  - Calling every issue_*_vc function with the correct keyword arguments,
    matching vc_issuance.py's real signatures exactly.
  - Also exposing issue_provenance_vc and issue_jit_vc, which exist in
    vc_issuance.py but had no HTTP route before this fix.
--------------------------------------------------------------------------
"""

import logging
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import vc_issuance

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="VC Issuance Service", version="1.1.0")


# ── Request Models
# All four (plus provenance/jit) share the same core shape --
# subject_did, issuer_did, issuer_key_id, claims -- matching
# vc_issuance.py's real function signatures.

class RoleVCRequest(BaseModel):
    subject_did: str
    issuer_did: str
    issuer_key_id: str
    claims: dict            # required: roleName, roleDescription, organisationDID
    trust_domain: str = "enterprise"
    valid_until_iso: Optional[str] = None


class CapabilityVCRequest(BaseModel):
    subject_did: str
    issuer_did: str
    issuer_key_id: str
    claims: dict            # required: capabilityName, certifiedActions, toolsDID, modelVersionHash, certifyingBodyDID
    trust_domain: str = "enterprise"
    valid_until_iso: Optional[str] = None


class ComplianceVCRequest(BaseModel):
    subject_did: str
    issuer_did: str
    issuer_key_id: str
    claims: dict            # required: complianceFramework, auditDate, auditRef, auditBodyDID, scope
    trust_domain: str = "enterprise"
    valid_until_iso: Optional[str] = None


class ProvenanceVCRequest(BaseModel):
    subject_did: str
    issuer_did: str
    issuer_key_id: str
    claims: dict            # required: parentDID, spawnedAt, spawnReason, provenanceAttestation
    trust_domain: str = "enterprise"


class ReputationVCRequest(BaseModel):
    subject_did: str
    issuer_did: str
    issuer_key_id: str
    claims: dict            # required: reputationScore, tasksCompleted, violationCount, peerDID
    trust_domain: str = "enterprise"
    valid_until_iso: Optional[str] = None


class JitVCRequest(BaseModel):
    subject_did: str
    issuer_did: str
    issuer_key_id: str
    claims: dict             # required: jobID, toolDID, allowedAction, inputHandle, outputHandle
    trust_domain: str = "enterprise"
    valid_until_iso: Optional[str] = None   # default: now + 15 minutes, per vc_issuance.py


class LogPeerIssuedVCRequest(BaseModel):
    """Matches wallet_service's reputation_issuer.py -- an already-signed VC."""
    signedVC: str
    subject_did: str
    issuer_did: str
    credential_type: str = "ReputationVC"
    trust_domain: str = "peer"


class HealthResponse(BaseModel):
    status: str
    service: str


# ── Lifecycle

@app.on_event("startup")
async def startup_event():
    logger.info("VC Issuance Service starting up...")
    vc_issuance.initialize_schema()


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "vc_issuance"}


# ── Endpoints

@app.post("/issue/role")
async def issue_role_vc(request: RoleVCRequest):
    """Issue a Role VC."""
    try:
        result = vc_issuance.issue_role_vc(
            subject_did=request.subject_did,
            issuer_did=request.issuer_did,
            issuer_key_id=request.issuer_key_id,
            claims=request.claims,
            trust_domain=request.trust_domain,
            valid_until_iso=request.valid_until_iso,
        )
        return {
            "status": "success",
            "vc_id": result.get("vcId"),
            "credential_type": "Role",
            "signedVC": result.get("signedVC"),
            "expiresAt": result.get("expiresAt"),
        }
    except (PermissionError, ValueError) as e:
        logger.warning(f"Role VC issuance rejected: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error issuing Role VC: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/issue/capability")
async def issue_capability_vc(request: CapabilityVCRequest):
    """Issue a Capability VC."""
    try:
        result = vc_issuance.issue_capability_vc(
            subject_did=request.subject_did,
            issuer_did=request.issuer_did,
            issuer_key_id=request.issuer_key_id,
            claims=request.claims,
            trust_domain=request.trust_domain,
            valid_until_iso=request.valid_until_iso,
        )
        return {
            "status": "success",
            "vc_id": result.get("vcId"),
            "credential_type": "Capability",
            "signedVC": result.get("signedVC"),
            "expiresAt": result.get("expiresAt"),
        }
    except (PermissionError, ValueError) as e:
        logger.warning(f"Capability VC issuance rejected: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error issuing Capability VC: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/issue/compliance")
async def issue_compliance_vc(request: ComplianceVCRequest):
    """Issue a Compliance VC."""
    try:
        result = vc_issuance.issue_compliance_vc(
            subject_did=request.subject_did,
            issuer_did=request.issuer_did,
            issuer_key_id=request.issuer_key_id,
            claims=request.claims,
            trust_domain=request.trust_domain,
            valid_until_iso=request.valid_until_iso,
        )
        return {
            "status": "success",
            "vc_id": result.get("vcId"),
            "credential_type": "Compliance",
            "signedVC": result.get("signedVC"),
            "expiresAt": result.get("expiresAt"),
        }
    except (PermissionError, ValueError) as e:
        logger.warning(f"Compliance VC issuance rejected: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error issuing Compliance VC: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/issue/provenance")
async def issue_provenance_vc(request: ProvenanceVCRequest):
    """Issue a Provenance VC (lineage attestation when an agent is spawned)."""
    try:
        result = vc_issuance.issue_provenance_vc(
            subject_did=request.subject_did,
            issuer_did=request.issuer_did,
            issuer_key_id=request.issuer_key_id,
            claims=request.claims,
            trust_domain=request.trust_domain,
        )
        return {
            "status": "success",
            "vc_id": result.get("vcId"),
            "credential_type": "Provenance",
            "signedVC": result.get("signedVC"),
            "expiresAt": result.get("expiresAt"),
        }
    except (PermissionError, ValueError) as e:
        logger.warning(f"Provenance VC issuance rejected: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error issuing Provenance VC: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/issue/reputation")
async def issue_reputation_vc(request: ReputationVCRequest):
    """Issue a Reputation VC (peer-issued performance attestation)."""
    try:
        result = vc_issuance.issue_reputation_vc(
            subject_did=request.subject_did,
            issuer_did=request.issuer_did,
            issuer_key_id=request.issuer_key_id,
            claims=request.claims,
            trust_domain=request.trust_domain,
            valid_until_iso=request.valid_until_iso,
        )
        return {
            "status": "success",
            "vc_id": result.get("vcId"),
            "credential_type": "Reputation",
            "signedVC": result.get("signedVC"),
            "expiresAt": result.get("expiresAt"),
        }
    except (PermissionError, ValueError) as e:
        logger.warning(f"Reputation VC issuance rejected: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error issuing Reputation VC: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/issue/jit")
async def issue_jit_vc(request: JitVCRequest):
    """Issue a Just-In-Time VC (short-lived, narrow-scope credential)."""
    try:
        result = vc_issuance.issue_jit_vc(
            subject_did=request.subject_did,
            issuer_did=request.issuer_did,
            issuer_key_id=request.issuer_key_id,
            claims=request.claims,
            trust_domain=request.trust_domain,
            valid_until_iso=request.valid_until_iso,
        )
        return {
            "status": "success",
            "vc_id": result.get("vcId"),
            "credential_type": "JIT",
            "signedVC": result.get("signedVC"),
            "expiresAt": result.get("expiresAt"),
        }
    except (PermissionError, ValueError) as e:
        logger.warning(f"JIT VC issuance rejected: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error issuing JIT VC: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/credentials/log/peer-issued")
async def log_peer_issued_vc(request: LogPeerIssuedVCRequest):
    """
    Record an already-signed, peer-issued VC (e.g. reputation VCs signed
    by the issuing agent's own key) without re-signing or re-validating it.
    ADDED (audit finding #8) -- see vc_issuance.log_peer_issued_vc() docstring.
    """
    try:
        result = vc_issuance.log_peer_issued_vc(
            signed_vc_jwt=request.signedVC,
            subject_did=request.subject_did,
            issuer_did=request.issuer_did,
            credential_type=request.credential_type,
            trust_domain=request.trust_domain,
        )
        return {"status": "success", "vcId": result["vcId"]}
    except Exception as e:
        logger.error(f"Error logging peer-issued VC: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/credentials/log/{subject_did:path}")
async def get_credential_log(subject_did: str):
    """Return the issuance log for a given subject DID."""
    try:
        result = vc_issuance.get_credential_log(subject_did)
        return {"status": "success", "log": result}
    except Exception as e:
        logger.error(f"Error retrieving credential log: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8004)