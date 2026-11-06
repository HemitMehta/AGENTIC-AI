"""
did_registry_service.py
FastAPI wrapper for DID Registry service (SubSystem 2)
Exposes did.py functions as HTTP endpoints.

--------------------------------------------------------------------------
FIX (audit finding #7): status_list_service/clients/did_registry_client.py
already calls PUT /dids/{did} (used for revocation -- setting
lifecycleStatus to "revoked"), but no such route existed here at all,
so every revocation attempt would 404/405.

Added: PUT /dids/{did_id} -> calls the new did.update_did_document()
function, matching the request shape the client already sends:
    { "updates": {...}, "authoritySignature": "..." }
--------------------------------------------------------------------------
"""

import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
import did

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="DID Registry Service", version="1.1.0")


# Request / Response Models

class DIDRegisterRequest(BaseModel):
    public_key_b64: str
    key_id: str
    owner_did: str
    controller_dids: List[str] = []
    scope_of_behavior: dict = {}
    toolset: List[str] = []
    model_hash: str = ""
    aibom_ref: str = ""
    did_method: str = "key"          # "key" or "web"
    domain: Optional[str] = None     # required when did_method == "web"
    metadata: dict = {}


class DIDUpdateRequest(BaseModel):
    """Matches what status_list_service's client already sends."""
    updates: dict
    authoritySignature: str = ""


class HealthResponse(BaseModel):
    status: str
    service: str


# Lifecycle

@app.on_event("startup")
async def startup_event():
    logger.info("DID Registry Service starting up...")
    # FIX: this was never calling did.initialize_schema() -- did_documents
    # and did_document_versions tables never existed, causing every write
    # to fail with "relation did_documents does not exist". Now matches
    # the same startup pattern trust_anchor_service.py and
    # vc_issuance_service.py already use.
    did.initialize_schema()


# Endpoints

@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "did_registry"}


@app.post("/dids/register")
async def register_did(request: DIDRegisterRequest):
    """Create and persist a new DID Document."""
    try:

        result = did.create_did(
            metadata=request.metadata,
            owner_did=request.owner_did,
            controller_dids=request.controller_dids,
            scope_of_behavior=request.scope_of_behavior,
            toolset=request.toolset,
            model_hash=request.model_hash,
            aibom_ref=request.aibom_ref,
            public_key_b64=request.public_key_b64,
            key_id=request.key_id,
            did_method=request.did_method,
            domain=request.domain,
        )
        return {
            "status": "success",
            "did": result["did"],
            "version": result["version"],
            "didDocument": result["didDocument"],
        }
    except Exception as e:
        logger.error(f"Error registering DID: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/dids/{did_id:path}")
async def resolve_did(
    did_id: str,
    at: Optional[str] = Query(
        default=None,
        description="ISO 8601 timestamp for point-in-time resolution. Defaults to now."
    ),
):
    """
    Resolve a DID Document.

    Pass ?at=2024-09-15T10:00:00Z to retrieve the document as it existed at that time.
    Omit ?at to resolve the current (latest) version.
    """
    try:

        at_iso = at or datetime.now(timezone.utc).isoformat()

        if did_id.startswith("did:key:"):
            result = did._resolve_did_key(did_id)
            return {
                "status": "success",
                "did": did_id,
                "data": result,
            }

        result = did.resolve_did_at_time(did_id, at_iso)
        return {
            "status": "success",
            "did": did_id,
            "data": result,
        }
    except ValueError as e:
        logger.warning(f"DID not found: {did_id} — {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error resolving DID: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/dids/{did_id:path}")
async def update_did(did_id: str, request: DIDUpdateRequest):
    """
    Apply a partial update to a DID Document (e.g. revocation via
    {"updates": {"lifecycleStatus": "revoked"}}).

    Note: did:key DIDs are derived entirely from their key material and
    have no database row to update -- attempting to PUT a did:key DID
    returns 400, since there is nothing to persist.
    """
    if did_id.startswith("did:key:"):
        raise HTTPException(
            status_code=400,
            detail="did:key DIDs are derived from key material and cannot be updated in place.",
        )

    try:
        result = did.update_did_document(
            did=did_id,
            updates=request.updates,
            authority_signature=request.authoritySignature,
        )
        return {
            "status": "success",
            "did": result["did"],
            "version": result["version"],
            "didDocument": result["didDocument"],
            "updatedAt": result["updatedAt"],
        }
    except ValueError as e:
        logger.warning(f"DID not found for update: {did_id} — {e}")
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating DID: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
