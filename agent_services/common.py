import base64
import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote, urlsplit

import base58
import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import HTTPException


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: dict) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


async def json_call(client, method, url, propagate_denial=False, **kwargs):
    try:
        response = await client.request(method, url, **kwargs)
        if propagate_denial and response.status_code in (403, 409):
            raise HTTPException(response.status_code, "Agent rejected task authorization or replay")
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Expected a JSON object")
        return result
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(502, "Required service returned an error or was unavailable") from exc


def kms_url() -> str:
    return os.environ.get("KMS_URL", "http://kms:8001")


async def kms_public(client, key_id):
    body = await json_call(client, "GET", f"{kms_url()}/keys/{quote(key_id, safe='')}/public")
    if body.get("keyStatus") != "active" or body.get("keyId") != key_id:
        raise HTTPException(502, "Trusted signing key is not active")
    return body["publicKey"]


def key_from_kms(value):
    if value.startswith("-----BEGIN"):
        key = serialization.load_pem_public_key(value.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("Expected an Ed25519 key")
        return key
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(value, validate=True))


def check_signature(key, signature, payload):
    try:
        key.verify(base64.b64decode(signature, validate=True), payload)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise HTTPException(403, "Invalid signature") from exc


async def sign(client, key_id, payload):
    response = await json_call(client, "POST", f"{kms_url()}/keys/{quote(key_id, safe='')}/sign",
                               json={"payload": base64.b64encode(canonical(payload)).decode("ascii")})
    return response["signature"]


def identity_did(public, label, domain):
    raw = key_from_kms(public).public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    fingerprint = hashlib.sha256(raw).hexdigest()[:24]
    return f"did:web:{domain}:agents:{label}-{fingerprint}"


async def register_identity(client, key_id, label, domain, wallet=False):
    public = await kms_public(client, key_id)
    did = identity_did(public, label, domain)
    identity = {"did": did, "keyId": key_id, "verificationMethod": f"{did}#{key_id}"}
    registry = os.environ.get("DID_REGISTRY_URL", "http://did_registry:8002")
    try:
        existing = await client.get(f"{registry}/dids/{quote(did, safe=':')}")
        if existing.status_code != 404:
            existing.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(502, "Cannot establish the service DID's current status") from exc
    if existing.status_code == 404:
        registered = await json_call(client, "POST", f"{registry}/dids/register", json={
            "public_key_b64": public, "key_id": key_id,
            "owner_did": os.environ.get("AGENT_OWNER_DID", f"did:web:{domain}:owner"),
            "controller_dids": [], "scope_of_behavior": {"allowed": ["analyze_financials"]},
            "toolset": ["financial-summary"], "did_method": "web", "domain": domain,
            "metadata": {"agentId": did.rsplit(":", 1)[-1], "name": label},
        })
        if registered.get("did") != did:
            raise RuntimeError("DID registration did not match the service key")
    # Reuse, never overwrite, an existing DID: a restart must not undo revocation.
    challenge = await signed_message(client, identity, {"type": "agent.startup.v1", "nonce": secrets.token_hex(24)})
    await verify_did_message(client, challenge, did)
    if wallet:
        wallet_url = os.environ.get("WALLET_SERVICE_URL", "http://wallet_service:8007")
        await json_call(client, "POST", f"{wallet_url}/wallets/{did}/init")
    return identity


async def signed_message(client, identity, payload):
    return {**payload, "proof": {
        "verificationMethod": identity["verificationMethod"], "signatureAlgorithm": "Ed25519",
        "signature": await sign(client, identity["keyId"], payload),
    }}


async def verify_did_message(client, message, expected_did):
    proof = message.get("proof", {})
    vm_id = proof.get("verificationMethod", "")
    if proof.get("signatureAlgorithm") != "Ed25519" or not vm_id.startswith(expected_did + "#"):
        raise HTTPException(403, "Signature is not from the expected agent")
    registry = os.environ.get("DID_REGISTRY_URL", "http://did_registry:8002")
    resolved = await json_call(client, "GET", f"{registry}/dids/{quote(expected_did, safe=':')}")
    document = resolved.get("data", resolved).get("didDocument", {})
    if document.get("id") != expected_did or document.get("lifecycleStatus") != "active":
        raise HTTPException(403, "Agent DID is not active")
    methods = document.get("verificationMethod", [])
    method = next((m for m in methods if m.get("id") == vm_id), None)
    if not method or method.get("controller") != expected_did or vm_id not in document.get("authentication", []):
        raise HTTPException(403, "Key is not authorized for agent authentication")
    encoded = method.get("publicKeyMultibase", "")
    try:
        raw = base58.b58decode(encoded[1:])
        if not encoded.startswith("z") or raw[:2] != b"\xed\x01" or len(raw) != 34:
            raise ValueError("Expected an Ed25519 multibase key")
        key = Ed25519PublicKey.from_public_bytes(raw[2:])
    except (ValueError, TypeError) as exc:
        raise HTTPException(403, "Agent verification key is invalid") from exc
    check_signature(key, proof.get("signature"), canonical({k: v for k, v in message.items() if k != "proof"}))


def validate_endpoint(endpoint, allowed, allow_http=False):
    try:
        parts = urlsplit(endpoint)
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("Credentials, queries and fragments are not allowed")
        if parts.scheme not in ({"https", "http"} if allow_http else {"https"}) or not parts.hostname:
            raise ValueError("Unsupported endpoint scheme")
        if endpoint not in allowed:
            raise ValueError("Discovered endpoint is outside the configured allowlist")
        _ = parts.port
    except ValueError as exc:
        raise HTTPException(403, str(exc)) from exc
    return endpoint


def operator_token(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="ascii") as stream:
            os.chmod(path, 0o600)
            stream.write(secrets.token_urlsafe(48))
    except FileExistsError:
        pass
    token = path.read_text(encoding="ascii").strip()
    if len(token) < 32:
        raise RuntimeError("Operator API token must have at least 32 characters")
    return token


class TaskStore:
    """Persistent duplicate protection and task outcomes; no automatic task retries."""

    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY, request TEXT NOT NULL, status TEXT NOT NULL,
                result TEXT, error TEXT, updated_at INTEGER NOT NULL)""")
            db.execute("UPDATE tasks SET status='interrupted', error='Service restarted; execution outcome must be checked' WHERE status='running'")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def reserve(self, task_id, request):
        try:
            with self.connect() as db:
                db.execute("INSERT INTO tasks VALUES (?, ?, 'running', NULL, NULL, ?)",
                           (task_id, canonical(request).decode(), int(time.time())))
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "Task ID already used; retrieve the existing task instead of replaying") from exc

    def finish(self, task_id, result=None, error=None):
        with self.connect() as db:
            db.execute("UPDATE tasks SET status=?, result=?, error=?, updated_at=? WHERE task_id=?",
                       ("failed" if error else "completed", json.dumps(result) if result else None,
                        error, int(time.time()), task_id))

    def get(self, task_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Task not found")
        return {"taskId": row["task_id"], "status": row["status"],
                "result": json.loads(row["result"]) if row["result"] else None,
                "error": row["error"], "updatedAt": row["updated_at"]}
