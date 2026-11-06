import base64
import hashlib
import json
import os

import base58
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import HTTPException
from pydantic import BaseModel

from .security import request


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def fingerprint(document):
    return hashlib.sha256(canonical({k: document.get(k) for k in ("verificationMethod", "authentication")})).hexdigest()


class AdminAuthorization(BaseModel):
    adminDID: str
    verificationMethod: str
    signature: str


async def did_document(did):
    response = await request("GET", f"{os.getenv('DID_REGISTRY_URL', 'http://did_registry:8002')}/dids/{did}")
    response.raise_for_status()
    data = response.json().get("data", response.json())
    document = data.get("didDocument", data)
    if document.get("id") != did or document.get("lifecycleStatus") != "active":
        raise HTTPException(403, "DID is not active")
    return document


async def verify_proof(did, proof, payload):
    document = await did_document(did)
    vm = proof["verificationMethod"]
    method = next((m for m in document.get("verificationMethod", []) if m.get("id") == vm), None)
    if (not vm.startswith(did + "#") or not method or method.get("controller") != did
            or vm not in document.get("authentication", [])):
        raise HTTPException(403, "Verification method is not controlled by the authenticated DID")
    try:
        encoded = method.get("publicKeyMultibase", "")
        raw = base58.b58decode(encoded[1:])
        if not encoded.startswith("z") or raw[:2] != b"\xed\x01" or len(raw) != 34:
            raise ValueError("Not an Ed25519 key")
        Ed25519PublicKey.from_public_bytes(raw[2:]).verify(base64.b64decode(proof["signature"], validate=True), canonical(payload))
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise HTTPException(403, "Invalid DID signature") from exc


async def verify_admin(auth, payload):
    allowed = set(os.getenv("LAYER3_ADMIN_DIDS", "").split(","))
    if auth.adminDID not in allowed:
        raise HTTPException(403, "DID is not authorized for Layer 3 administration")
    await verify_proof(auth.adminDID, auth.model_dump(), payload)
