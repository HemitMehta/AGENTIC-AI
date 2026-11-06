"""
trust_anchor_service.py
FastAPI wrapper for Root Trust Anchor service (SubSystem 3)
Exposes root_trust.py functions as HTTP endpoints.

--------------------------------------------------------------------------
FIX (audit finding #2): this file previously called
root_trust.authorize_issuer() and root_trust.check_issuer_authorization(),
neither of which exist in root_trust.py -- every functional call crashed
with AttributeError -> HTTP 500.

It also exposed routes (/trust/authorize, /trust/issuers/{did}/{type})
that didn't match what root_trust.py's own docstrings specify, and didn't
match what verification_service/clients/trust_anchor_client.py actually
calls (/trust-anchor, /trust-anchor/validate).

This rewrite calls the real functions (validate_issuer, add_issuer,
remove_issuer, get_trust_anchor, get_federation_trust_anchor) at the
routes root_trust.py's docstrings specify, which also now match
verification_service's client exactly.
--------------------------------------------------------------------------
"""

import logging
from typing import Optional, List
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx
import os

import root_trust

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Root Trust Anchor Service", version="1.1.0")

KMS_URL = os.getenv("KMS_URL", "http://kms:8001")
DID_REGISTRY_URL = os.getenv("DID_REGISTRY_URL", "http://did_registry:8002")


# ── Minimal HTTP-backed clients passed into root_trust.py's functions
# root_trust.py's add_issuer()/get_trust_anchor() expect kms_client and
# did_registry_client objects with specific method names -- these thin
# wrappers translate that into real HTTP calls against the running
# kms and did_registry services.

class _KMSHttpClient:
    def sign_payload(self, key_id: str, payload: bytes) -> dict:
        resp = httpx.post(
            f"{KMS_URL}/keys/{key_id}/sign",
            json={"payload": __import__("base64").b64encode(payload).decode()},
            timeout=10,
        )
        resp.raise_for_status()
        body = resp.json()
        return {"signature": body["signature"], "keyId": body["keyId"], "algorithm": body["algorithm"]}

    def get_public_key(self, key_id: str) -> dict:
        resp = httpx.get(f"{KMS_URL}/keys/{key_id}/public", timeout=10)
        resp.raise_for_status()
        body = resp.json()
        return {"publicKey": body["publicKey"], "keyId": body["keyId"], "algorithm": body["algorithm"]}


class _DIDRegistryHttpClient:
    def resolve_did(self, did: str) -> dict:
        resp = httpx.get(f"{DID_REGISTRY_URL}/dids/{did}", timeout=10)
        resp.raise_for_status()
        body = resp.json()
        # did_registry_service.py wraps the real payload under "data"
        data = body.get("data", body)
        return {"didDocument": data.get("didDocument", data)}


_kms_client = _KMSHttpClient()
_did_registry_client = _DIDRegistryHttpClient()


# ── Request / Response Models

class ValidateIssuerRequest(BaseModel):
    issuerDID: str
    credentialType: str
    trustDomain: str = "enterprise"


class AddIssuerRequest(BaseModel):
    issuerDID: str
    credentialTypes: List[str]
    trustDomain: str = "enterprise"
    validUntil: Optional[str] = None
    adminSignature: dict = {}


class RemoveIssuerRequest(BaseModel):
    reason: str
    adminSignature: dict = {}


class AddFederationOrgRequest(BaseModel):
    orgName: str
    orgDID: str
    rootPublicKey: str
    trustAnchorUrl: str


class HealthResponse(BaseModel):
    status: str
    service: str


# ── Lifecycle

@app.on_event("startup")
async def startup_event():
    logger.info("Root Trust Anchor Service starting up...")
    try:
        root_trust.initialize_schema()
    except Exception as e:
        logger.warning(f"Schema initialization warning: {e}")


# ── Endpoints
# Routes match root_trust.py's own docstrings and what
# verification_service/clients/trust_anchor_client.py already calls.

@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "trust_anchor"}


@app.get("/trust-anchor")
async def get_trust_anchor():
    """Return the current signed trust anchor document and root public key."""
    try:
        result = root_trust.get_trust_anchor(_kms_client)
        return result
    except Exception as e:
        logger.error(f"Error fetching trust anchor: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/trust-anchor/federation")
async def get_federation_trust_anchor():
    """Return the federation trust document listing each org's root trust anchor."""
    try:
        result = root_trust.get_federation_trust_anchor()
        return result
    except Exception as e:
        logger.error(f"Error fetching federation trust anchor: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/trust-anchor/validate")
async def validate_issuer(request: ValidateIssuerRequest):
    """
    Check whether a specific issuer DID is authorized to issue a specific
    credential type in a specific trust domain. Called by
    verification_service for every VC being verified.
    """
    try:
        result = root_trust.validate_issuer(
            issuer_did=request.issuerDID,
            credential_type=request.credentialType,
            trust_domain=request.trustDomain,
        )
        return result
    except Exception as e:
        logger.error(f"Error validating issuer: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/trust-anchor/issuers")
async def add_issuer(request: AddIssuerRequest):
    """Accredit a new issuer -- adds an authorization and re-signs the trust document."""
    try:
        result = root_trust.add_issuer(
            issuer_did=request.issuerDID,
            credential_types=request.credentialTypes,
            trust_domain=request.trustDomain,
            valid_until=request.validUntil,
            admin_signature=request.adminSignature,
            kms_client=_kms_client,
            did_registry_client=_did_registry_client,
        )
        return result
    except PermissionError as e:
        logger.warning(f"Issuer accreditation forbidden: {e}")
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        logger.warning(f"Cannot add issuer: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error adding issuer: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/trust-anchor/issuers/{issuer_did:path}")
async def remove_issuer(issuer_did: str, request: RemoveIssuerRequest):
    """Revoke an issuer's authorization -- re-signs and publishes a new trust document."""
    try:
        result = root_trust.remove_issuer(
            issuer_did=issuer_did,
            reason=request.reason,
            admin_signature=request.adminSignature,
            kms_client=_kms_client,
            did_registry_client=_did_registry_client,
        )
        return result
    except PermissionError as e:
        logger.warning(f"Issuer removal forbidden: {e}")
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        logger.warning(f"Cannot remove issuer: {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error removing issuer: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/trust-anchor/federation/orgs")
async def add_federation_org(request: AddFederationOrgRequest):
    """Add a participating organization to the federation trust document."""
    try:
        result = root_trust.add_federation_org(
            org_name=request.orgName,
            org_did=request.orgDID,
            root_public_key=request.rootPublicKey,
            trust_anchor_url=request.trustAnchorUrl,
        )
        return result
    except Exception as e:
        logger.error(f"Error adding federation org: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
