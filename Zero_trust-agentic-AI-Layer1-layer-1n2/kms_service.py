"""
kms_service.py
FastAPI wrapper for KMS service (SubSystem 1)
Exposes kms.py functions as HTTP endpoints.

--------------------------------------------------------------------------
FIXES applied (audit findings #4 and #6):

#6 — kms.generate_key()/get_public_key() return camelCase keys
     ("publicKey", "keyId"), but this file was reading snake_case
     ("public_key", "key_id") via .get(), which silently returned None
     for both fields on every call. Fixed to read the correct keys.

#4 — Route mismatch across three independent client implementations.
     verification_service, wallet_service, and status_list_service each
     expect a slightly different KMS route shape. This file now exposes
     the superset all three actually need:

       POST /keys/generate          (unchanged, already matched)
       GET  /keys/{key_id}/public   (added /public suffix -- all three
                                      clients already expect this)
       POST /keys/{key_id}/sign     (path-based, matches
                                      status_list_service's existing
                                      client; wallet_service's client is
                                      updated separately to match this)
       POST /keys/{key_id}/revoke   (new -- wallet_service's client
                                      already expected this and nothing
                                      implemented it before)

     The old POST /sign (key_id in body) route is kept as a deprecated
     alias so nothing that already worked breaks, but new code should
     use POST /keys/{key_id}/sign.

FIX (found via live testing, post-audit): every call to
kms.generate_key()/sign_payload()/get_public_key() failed with:
    "no handler for route \"transit/keys/...\". route entry not found."
Vault's Transit secrets engine is never mounted by default -- Vault dev
mode auto-mounts a KV store at secret/, but NOT transit/. Nothing
previously enabled it (there is no Vault equivalent of init_databases.sh).
Since Vault dev mode is in-memory, this mount is also lost on every
container restart, so this must be ensured at startup, not just once
manually. Fixed by adding an idempotent enable step in startup_event()
below -- safe to run on every start, including when it's already enabled.
--------------------------------------------------------------------------
"""

import base64
import logging
import hvac
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import kms

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="KMS Service", version="1.2.0")


# ── Request / Response Models

class KeyRequest(BaseModel):
    agent_did: str
    key_purpose: str


class SignRequest(BaseModel):
    payload: str  # base64-encoded bytes


class LegacySignRequest(BaseModel):
    """Deprecated -- key_id in body. Kept only for backward compatibility."""
    key_id: str
    payload: str


class HealthResponse(BaseModel):
    status: str
    service: str


# ── Lifecycle

@app.on_event("startup")
async def startup_event():
    logger.info("KMS Service starting up...")
    _ensure_transit_engine_enabled()
    _ensure_bootstrap_keys_exist()


def _ensure_bootstrap_keys_exist():
    """
    Ensure fixed service keys exist after every Vault dev-mode restart.

    Several services use stable key names from env vars instead of calling
    /keys/generate at runtime. Vault dev storage is ephemeral, so those names
    must be recreated idempotently on KMS startup.
    """
    import os
    configured = os.getenv("KMS_BOOTSTRAP_KEY_IDS", "")
    key_ids = [os.getenv("ROOT_TRUST_KEY_ID", "root-trust-anchor-key")]
    key_ids.extend(k.strip() for k in configured.split(",") if k.strip())

    seen = set()
    ordered_key_ids = []
    for key_id in key_ids:
        if key_id not in seen:
            ordered_key_ids.append(key_id)
            seen.add(key_id)

    try:
        for key_id in ordered_key_ids:
            result = kms.ensure_key_exists(key_id)
            logger.info(f"KMS bootstrap key check for {key_id}: {result}")
    except Exception as e:
        logger.error(f"Could not ensure KMS bootstrap keys exist: {e}")
        raise


def _ensure_transit_engine_enabled():
    """
    Idempotently enable Vault's Transit secrets engine at path 'transit/'.
    Safe to call every startup -- if it's already enabled (e.g. Vault
    wasn't restarted), the "already in use" error is caught and ignored.
    """
    import os
    vault_addr = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
    vault_token = os.getenv("VAULT_TOKEN", "root")

    client = hvac.Client(url=vault_addr, token=vault_token)

    try:
        client.sys.enable_secrets_engine(backend_type="transit", path="transit")
        logger.info("Vault Transit secrets engine enabled at transit/")
    except hvac.exceptions.InvalidRequest as e:
        if "already in use" in str(e).lower() or "path is already in use" in str(e).lower():
            logger.info("Vault Transit secrets engine already enabled at transit/ — OK")
        else:
            logger.error(f"Unexpected error enabling Transit engine: {e}")
            raise
    except Exception as e:
        logger.error(f"Could not reach Vault to enable Transit engine: {e}")
        raise


# ── Endpoints

@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return {"status": "healthy", "service": "kms"}


@app.post("/keys/generate")
async def generate_key(request: KeyRequest):
    """Generate a new Ed25519 key pair for an agent."""
    try:
        result = kms.generate_key(request.agent_did, request.key_purpose)
        return {
            "status": "success",
            "publicKey": result["publicKey"],
            "keyId": result["keyId"],
            "algorithm": result["algorithm"],
            "keyPurpose": result["keyPurpose"],
            "createdAt": result["createdAt"],
        }
    except Exception as e:
        logger.error(f"Error generating key: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/keys/{key_id}/sign")
async def sign_payload_by_path(key_id: str, request: SignRequest):
    """
    Sign a base64-encoded payload using the key identified by key_id
    (path parameter). This is the primary signing route -- matches
    status_list_service's client and the updated wallet_service client.
    """
    try:
        payload_bytes = base64.b64decode(request.payload)
        result = kms.sign_payload(key_id, payload_bytes)
        return {
            "status": "success",
            "signature": result["signature"],
            "algorithm": result["algorithm"],
            "keyId": result["keyId"],
        }
    except Exception as e:
        logger.error(f"Error signing payload: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/sign")
async def sign_payload_legacy(request: LegacySignRequest):
    """
    Deprecated: key_id passed in the request body instead of the path.
    Kept only so any pre-existing caller of the old contract keeps working.
    Prefer POST /keys/{key_id}/sign for all new code.
    """
    try:
        payload_bytes = base64.b64decode(request.payload)
        result = kms.sign_payload(request.key_id, payload_bytes)
        return {
            "status": "success",
            "signature": result["signature"],
            "algorithm": result["algorithm"],
            "keyId": result["keyId"],
        }
    except Exception as e:
        logger.error(f"Error signing payload (legacy route): {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/keys/{key_id}/public")
async def get_public_key(key_id: str):
    """
    Get the public key for a given key_id.
    Route matches what verification_service, wallet_service, and
    status_list_service all already expect.
    """
    try:
        result = kms.get_public_key(key_id)
        return {
            "status": "success",
            "publicKey": result["publicKey"],
            "keyId": result["keyId"],
            "algorithm": result["algorithm"],
            "keyStatus": result["status"],
        }
    except Exception as e:
        logger.error(f"Error retrieving public key: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/keys/{key_id}/revoke")
async def revoke_key(key_id: str):
    """
    Revoke (delete) a key from Vault. Matches what wallet_service's
    client already expected -- previously no endpoint existed for this.
    """
    try:
        result = kms.revoke_key(key_id)
        return {
            "status": "success",
            "keyId": result["keyId"],
            "keyStatus": result["status"],
        }
    except Exception as e:
        logger.error(f"Error revoking key: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
