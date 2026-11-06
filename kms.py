"""
kms.py
Sub-System 1: Key Management Service  (Person A — Layer 1)

All private key operations happen inside HashiCorp Vault Transit.
Private keys are generated inside Vault and NEVER exported.

Exports (what test.py expects):
  vault_client          — module-level hvac client (patchable with @patch("kms.vault_client"))
  generate_key()        — create Ed25519 keypair in Vault, return public key only
  sign_payload()        — sign bytes via Vault, return signature only
  compute_model_hash()  — SHA3-256 fingerprint of model binary
  get_public_key()      — return public key + status for a key_id
  revoke_key()          — delete a key from Vault (emergency revocation)

--------------------------------------------------------------------------
FIX (audit finding #5): keyId now IS the Vault key name.

Previously, generate_key() created the Vault key under a name derived by
_vault_key_name(), but returned a *separately* derived keyId from
_derive_key_id(). Those two strings were different, so any caller that
later used the returned keyId to call sign_payload()/get_public_key()
would fail against a real Vault with "key not found" -- the only thing
that ever worked was test_integration.py, which manually substituted
vaultKeyName back in.

Fix: there is now a single derivation function, _derive_vault_key_name(),
used both as the Vault key name AND as the keyId returned to callers.
They are now guaranteed to be identical, so any keyId returned by
generate_key() can be used directly and correctly with sign_payload()
and get_public_key() with no separate lookup needed.
--------------------------------------------------------------------------
"""

import os
import base64
import hashlib
import logging
from datetime import datetime, timezone

import hvac

logger = logging.getLogger(__name__)

# ── Module-level Vault client
# Defined at module scope so tests can patch it with @patch("kms.vault_client").
#
# We expose the .secrets.transit namespace so call sites look like:
#   vault_client.create_key(...)   vault_client.transit.sign_data(...)
#
# Lazy init: if Vault is unreachable at import time the module still loads.
# Tests replace this attribute before calling any function.

class _LazyTransit:
    """
    Proxy that defers .secrets.transit resolution until first use.
    This lets the module import cleanly even without a running Vault,
    and lets @patch("kms.vault_client") replace it before any call is made.
    """
    def __init__(self):
        self._client = None

    def _get(self):
        if self._client is None:
            self._client = hvac.Client(
                url=os.getenv("VAULT_ADDR", "http://127.0.0.1:8200"),
                token=os.getenv("VAULT_TOKEN", "root"),
            ).secrets.transit
        return self._client

    def __getattr__(self, name):
        return getattr(self._get(), name)


vault_client = _LazyTransit()


# ── Internal helpers

def _derive_vault_key_name(agent_did: str, key_purpose: str) -> str:
    """
    Single source of truth for the Vault key name AND the public keyId.

    Vault key names must be alphanumeric + hyphens — no colons — so we
    hash the DID+purpose pair to keep the name short and safe.

    This value is returned to callers as "keyId" and is ALSO the literal
    name used to create/read/sign with the key in Vault. There is no
    second, different identifier anymore -- this fixes audit finding #5.
    """
    raw = f"{agent_did}:{key_purpose}"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return f"agent-{digest}"


# ── Public API

def generate_key(agent_did: str, key_purpose: str) -> dict:
    """
    Generate an Ed25519 keypair inside Vault Transit.
    Private key NEVER leaves Vault.
    Returns only: publicKey, keyId, algorithm, keyPurpose.

    Args:
        agent_did:    DID of the agent this key belongs to.
        key_purpose:  'authentication' | 'assertionMethod' | 'keyAgreement'

    Returns:
        {
            "publicKey":   str   — base64-encoded raw 32-byte public key,
            "keyId":       str   — the Vault key name itself (no colons),
            "algorithm":   "Ed25519",
            "keyPurpose":  str,
            "createdAt":   str,
        }
    """
    key_id = _derive_vault_key_name(agent_did, key_purpose)

    # Create key inside Vault — private material stays there
    vault_client.create_key(name=key_id, key_type="ed25519")

    # Read back only the public key
    info = vault_client.read_key(name=key_id)
    latest = info["data"]["latest_version"]
    raw_public = info["data"]["keys"][str(latest)]["public_key"]
    # raw_public may be base64 (Vault ≥1.11) or a PEM string depending on version

    return {
        "publicKey":  raw_public,
        "keyId":      key_id,           # <-- now IS the vault key name
        "algorithm":  "Ed25519",
        "keyPurpose": key_purpose,
        "createdAt":  datetime.now(timezone.utc).isoformat(),
    }


def sign_payload(key_id: str, payload: bytes) -> dict:
    """
    Sign arbitrary bytes using the Vault Transit key identified by key_id.
    Private key never leaves Vault.

    Vault returns:  "vault:v1:<base64-signature>"
    We strip the prefix and return only the raw base64 signature.

    Args:
        key_id:   Key ID exactly as returned by generate_key(). Since
                  keyId IS the Vault key name (see module docstring),
                  this can be used directly with no separate lookup.
        payload:  Raw bytes to sign.

    Returns:
        {
            "signature":  str  — raw base64 (colon-free),
            "algorithm":  "Ed25519",
            "keyId":      str,
        }
    """
    # Vault Transit sign_data expects a base64-encoded hash input
    payload_b64 = base64.b64encode(payload).decode()

    response = vault_client.sign_data(
        name=key_id,
        hash_input=payload_b64,
        hash_algorithm="sha2-256",
    )

    vault_sig = response["data"]["signature"]   # "vault:v1:ACTUALSIGNATURE=="
    # Strip "vault:v1:" prefix — return only the base64 part
    raw_sig = str(vault_sig).split(":")[-1]  # str() cast so mock strings split correctly

    return {
        "signature": raw_sig,
        "algorithm": "Ed25519",
        "keyId":     key_id,
    }


def compute_model_hash(
    model_path: str = None,
    model_binary: bytes = None,
) -> dict:
    """
    Compute SHA3-256 fingerprint of model weights.
    MUST use SHA3-256 — NOT SHA-256 (per spec).

    Provide exactly one of:
        model_path   — path to model weights file on disk
        model_binary — raw bytes of model weights

    Returns:
        {
            "sha3_256_hash": str   — 64-character hex string,
            "algorithm":     "SHA3-256",
        }
    """
    if model_path is None and model_binary is None:
        raise ValueError("Provide model_path or model_binary — both are None")

    if model_path is not None:
        with open(model_path, "rb") as f:
            data = f.read()
    else:
        data = model_binary

    fingerprint = hashlib.sha3_256(data).hexdigest()

    return {
        "sha3_256_hash": fingerprint,
        "algorithm":     "SHA3-256",
    }


def get_public_key(key_id: str) -> dict:
    """
    Return public key material and status for a given key_id.
    If the key has been deleted/revoked from Vault, returns status='revoked'
    with publicKey=None — does NOT raise an exception.

    Args:
        key_id: exactly as returned by generate_key() (IS the vault key name).

    Returns:
        {
            "keyId":      str,
            "publicKey":  str | None,
            "algorithm":  "Ed25519",
            "status":     "active" | "revoked",
        }
    """
    try:
        info = vault_client.read_key(name=key_id)
        latest = info["data"]["latest_version"]
        raw_public = info["data"]["keys"][str(latest)]["public_key"]

        return {
            "keyId":     key_id,
            "publicKey": raw_public,
            "algorithm": "Ed25519",
            "status":    "active",
        }

    except Exception:
        # Key was deleted (emergency revocation) — return gracefully
        logger.warning("get_public_key: key not found in Vault (revoked?): %s", key_id)
        return {
            "keyId":     key_id,
            "publicKey": None,
            "algorithm": "Ed25519",
            "status":    "revoked",
        }


def ensure_key_exists(key_id: str, key_type: str = "ed25519") -> dict:
    """
    Idempotently ensure a Vault Transit key exists under an EXACT, literal
    name (not derived via _derive_vault_key_name). Used for well-known,
    fixed-name keys such as the root trust anchor's signing key
    ("root-trust-anchor-key"), which root_trust.py expects to already
    exist and has no other bootstrap mechanism for.

    Safe to call on every service startup -- if the key already exists,
    this is a no-op (confirmed by attempting a read first).

    Args:
        key_id:   Exact Vault key name to ensure exists (no hashing/derivation).
        key_type: Vault key type, defaults to "ed25519".

    Returns:
        { "keyId": str, "status": "created" | "already_exists" }
    """
    try:
        vault_client.read_key(name=key_id)
        logger.info("Key already exists in Vault: %s", key_id)
        return {"keyId": key_id, "status": "already_exists"}
    except Exception:
        pass  # doesn't exist yet -- fall through and create it

    vault_client.create_key(name=key_id, key_type=key_type)
    logger.info("Key created in Vault: %s", key_id)
    return {"keyId": key_id, "status": "created"}


def revoke_key(key_id: str) -> dict:
    """
    Permanently delete a key from Vault (emergency revocation).

    NOTE: Vault Transit keys are soft-protected by default -- deletion
    requires the key's `deletion_allowed` config to be set to True first.
    This function sets that config, then deletes the key.

    Args:
        key_id: exactly as returned by generate_key() (IS the vault key name).

    Returns:
        { "keyId": str, "status": "revoked" }
    """
    try:
        # Vault requires deletion_allowed=True to be set before a key can be deleted
        vault_client.update_key_configuration(name=key_id, deletion_allowed=True)
        vault_client.delete_key(name=key_id)
        logger.info("Key revoked (deleted from Vault): %s", key_id)
    except Exception as e:
        logger.error("Failed to revoke key %s: %s", key_id, e)
        raise

    return {
        "keyId":  key_id,
        "status": "revoked",
    }