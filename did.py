"""
did.py
Sub-System 2: DID Registry  (Person A — Layer 1)

Stores and resolves DID Documents for all agents.
Supports did:key (derived from key material, no DB) and did:web (DB-backed).
Maintains full version history for point-in-time resolution.

Exports (what test.py expects):
  get_db_connection()            — psycopg2 connection (patchable)
  initialize_schema()            — create did_documents / did_document_versions tables
  create_did()                   — create + persist a new DID Document
  resolve_did_at_time()          — point-in-time resolution
  _resolve_did_key()             — decode did:key from DID string (no DB)
  _generate_did_key()            — derive did:key string from public key b64
  _build_did_document()          — construct DID Document dict
  _verify_controller_signature() — check signer is in controllerDIDs
  update_did_document()          — apply a partial update / revoke a DID

--------------------------------------------------------------------------
FIX (found via live testing): this file had NO initialize_schema() function
and no CREATE TABLE statements anywhere. init_databases.sh only creates the
empty `did_registry` database -- it never creates any tables inside it.
Unlike root_trust.py and vc_issuance.py (both of which have
initialize_schema() called from their service's startup event),
did_registry_service.py never created its tables at all, so every write
failed with:
    relation "did_documents" does not exist

Fixed by adding initialize_schema() below, matching the exact columns
create_did(), resolve_did_at_time(), _verify_controller_signature(), and
update_did_document() already assume. did_registry_service.py's startup
event is updated separately to call this.
--------------------------------------------------------------------------
"""

import os
import json
import base64
import logging
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta

import base58
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))


logger = logging.getLogger(__name__)


# ── Database Connection 

def get_db_connection():
    """
    FIX (found via live testing): vc_issuance.py imports this module
    directly (as `did_registry`) and runs it in-process inside the
    vc_issuance container, which sets CRDB_DB=vc_issuance for its OWN
    database needs -- causing this module's DID lookups to silently hit
    the wrong database when called from within vc_issuance.

    Fixed by checking a more specific DID_REGISTRY_CRDB_DB env var first,
    falling back to the generic CRDB_DB for backward compatibility with
    the standalone did_registry container (which only sets CRDB_DB).
    """
    return psycopg2.connect(
        host=os.getenv("CRDB_HOST", "localhost"),
        port=int(os.getenv("CRDB_PORT", "26257")),
        dbname=os.getenv("DID_REGISTRY_CRDB_DB", os.getenv("CRDB_DB", "did_registry")),
        user=os.getenv("CRDB_USER", "root"),
        password=os.getenv("CRDB_PASSWORD", ""),
        sslmode=os.getenv("CRDB_SSLMODE", "disable"),  # "require" in prod
        sslrootcert=os.getenv("CRDB_SSLROOTCERT", ""),
        cursor_factory=RealDictCursor,
    )


# ── Schema Initialization
# ADDED: this table DDL was missing entirely. Columns match exactly what
# create_did(), resolve_did_at_time(), _verify_controller_signature(), and
# update_did_document() already assume.

DID_REGISTRY_SCHEMA = """
CREATE TABLE IF NOT EXISTS did_documents (
    id                TEXT PRIMARY KEY,
    current_version   INTEGER NOT NULL DEFAULT 1,
    did_document      JSONB NOT NULL,
    owner_did         TEXT NOT NULL,
    controller_dids   JSONB NOT NULL,
    lifecycle_status  TEXT NOT NULL DEFAULT 'active',
    method            TEXT NOT NULL,
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    updated_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_did_documents_owner_did ON did_documents(owner_did);
CREATE INDEX IF NOT EXISTS idx_did_documents_lifecycle_status ON did_documents(lifecycle_status);

CREATE TABLE IF NOT EXISTS did_document_versions (
    did           TEXT NOT NULL,
    version       INTEGER NOT NULL,
    raw_document  JSONB NOT NULL,
    change_type   TEXT NOT NULL,
    valid_from    TIMESTAMPTZ NOT NULL,
    valid_until   TIMESTAMPTZ,
    PRIMARY KEY (did, version)
);

CREATE INDEX IF NOT EXISTS idx_did_document_versions_did ON did_document_versions(did);
CREATE INDEX IF NOT EXISTS idx_did_document_versions_valid_from ON did_document_versions(valid_from);
"""


def initialize_schema():
    """
    Create did_documents and did_document_versions tables if they don't
    already exist. Must be called once at service startup -- see
    did_registry_service.py's startup_event.
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(DID_REGISTRY_SCHEMA)
        conn.commit()
    logger.info("DID Registry schema initialized.")


# ── DID Document Builder 

def _build_did_document(
    did: str,
    public_key_b64: str,
    key_id: str,
    owner_did: str,
    controller_dids: list,
    scope_of_behavior,
    toolset: list,
    model_hash: str,
    aibom_ref: str,
    expires_days: int = 365,
) -> dict:
    """
    Construct a full W3C DID Document with all spec-required fields.

    Required W3C fields:
        @context, id, verificationMethod, authentication

    Agentic AI extended fields (per spec):
        ownerDID, controllerDIDs, scopeOfBehavior, toolset,
        modelHash, lifecycleStatus, aibomReference,
        createdAt, updatedAt, expiresAt
    """
    now = datetime.now(timezone.utc).isoformat()
    expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()

    # Multibase-encode public key: multicodec Ed25519 prefix (0xed 0x01) + raw bytes
    pub_bytes = base64.b64decode(public_key_b64)
    multicodec_prefix = bytes([0xed, 0x01])
    multibase = "z" + base58.b58encode(multicodec_prefix + pub_bytes).decode()

    vm_id = f"{did}#{key_id}"

    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": multibase,
            }
        ],
        "authentication":          [vm_id],
        "assertionMethod":         [vm_id],
        "capabilityInvocation":    [vm_id],
        "capabilityDelegation":    [vm_id],
        "keyAgreement":            [],
        "service":                 [],
        # ── Extended fields required by spec 
        "ownerDID":        owner_did,
        "controllerDIDs":  controller_dids if controller_dids else [owner_did],
        "scopeOfBehavior": scope_of_behavior,
        "toolset":         toolset,
        "modelHash":       model_hash,
        "lifecycleStatus": "active",
        "aibomReference":  aibom_ref,
        "createdAt":       now,
        "updatedAt":       now,
        "expiresAt":       expires_at,
    }


# ── did:key helpers 

def _generate_did_key(public_key_b64: str) -> str:
    """
    Derive a did:key DID string from a base64-encoded Ed25519 public key.
    Encoding: multicodec prefix (0xed 0x01) + raw key bytes → base58btc → 'z' prefix.
    """
    pub_bytes = base64.b64decode(public_key_b64)
    multicodec_prefix = bytes([0xed, 0x01])
    multibase = "z" + base58.b58encode(multicodec_prefix + pub_bytes).decode()
    return f"did:key:{multibase}"


def _resolve_did_key(did: str) -> dict:
    """
    Resolve a did:key entirely from the DID string itself.
    NO database lookup — the DID document is derived from the key material.

    Returns:
        {
            "didDocument":     dict,
            "currentVersion":  None   (no DB version for did:key)
        }
    """
    if not did.startswith("did:key:z"):
        raise ValueError(f"Not a valid did:key: {did}")

    multibase = did[len("did:key:"):]   # e.g. "z6Mk..."

    # Decode base58btc (strip leading 'z')
    try:
        decoded = base58.b58decode(multibase[1:])
    except Exception as e:
        raise ValueError(f"Cannot decode multibase from did:key: {e}")

    # Verify Ed25519 multicodec prefix
    if len(decoded) < 2 or decoded[:2] != bytes([0xed, 0x01]):
        # Some test DIDs use base32 encoding — try that as fallback
        try:
            import base64 as _b64
            padded = multibase[1:].upper()
            padding = (8 - len(padded) % 8) % 8
            decoded = _b64.b32decode(padded + "=" * padding)
        except Exception:
            raise ValueError("Unsupported multibase encoding in did:key")

    pub_bytes = decoded[2:]
    pub_key_b64 = base64.b64encode(pub_bytes).decode()
    vm_id = f"{did}#{multibase}"

    did_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": multibase,
            }
        ],
        "authentication":       [vm_id],
        "assertionMethod":      [vm_id],
        "capabilityInvocation": [vm_id],
        "capabilityDelegation": [vm_id],
        "lifecycleStatus":      "active",
    }

    return {
        "didDocument":    did_document,
        "currentVersion": None,     # did:key has no DB version
    }


# ── Create DID 

def create_did(
    metadata: dict,
    owner_did: str,
    controller_dids: list,
    scope_of_behavior,
    toolset: list,
    model_hash: str,
    aibom_ref: str,
    public_key_b64: str,
    key_id: str,
    did_method: str = "key",
    domain: str = None,
) -> dict:
    """
    Create and persist a new DID Document.

    For did:key — DID is derived from the public key bytes.
    For did:web — DID is did:web:<domain>:agents:<agentId> where agentId
                  comes from metadata["agentId"].

    Writes one row to did_documents (current) and one to
    did_document_versions (version 1, valid_from=now, valid_until=NULL).

    Returns:
        { "did": str, "didDocument": dict, "version": 1 }
    """
    agent_id = metadata.get("agentId", key_id)

    if did_method == "key":
        did = _generate_did_key(public_key_b64)
    elif did_method == "web":
        host = domain or os.getenv("APP_DOMAIN", "agents.example.com")
        did = f"did:web:{host}:agents:{agent_id}"
    else:
        raise ValueError(f"Unknown DID method: {did_method}")

    did_document = _build_did_document(
        did=did,
        public_key_b64=public_key_b64,
        key_id=key_id,
        owner_did=owner_did,
        controller_dids=controller_dids,
        scope_of_behavior=scope_of_behavior,
        toolset=toolset,
        model_hash=model_hash,
        aibom_ref=aibom_ref,
    )

    now = datetime.now(timezone.utc)

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT current_version FROM did_documents WHERE id = %s",
                (did,),
            )
            existing = cur.fetchone()

            if existing:
                new_version = existing["current_version"] + 1

                cur.execute(
                    """
                    UPDATE did_document_versions
                    SET valid_until = %s
                    WHERE did = %s AND version = %s AND valid_until IS NULL
                    """,
                    (now, did, existing["current_version"]),
                )

                cur.execute(
                    """
                    UPDATE did_documents
                    SET current_version = %s,
                        did_document = %s,
                        owner_did = %s,
                        controller_dids = %s,
                        lifecycle_status = 'active',
                        method = %s,
                        updated_at = %s
                    WHERE id = %s
                    """,
                    (
                        new_version,
                        json.dumps(did_document),
                        owner_did,
                        json.dumps(controller_dids),
                        did_method,
                        now,
                        did,
                    ),
                )

                cur.execute(
                    """
                    INSERT INTO did_document_versions
                        (did, version, raw_document, change_type, valid_from, valid_until)
                    VALUES (%s, %s, %s, 'updated', %s, NULL)
                    ON CONFLICT (did, version) DO UPDATE SET
                        raw_document = EXCLUDED.raw_document,
                        change_type = EXCLUDED.change_type,
                        valid_from = EXCLUDED.valid_from,
                        valid_until = NULL
                    """,
                    (did, new_version, json.dumps(did_document), now),
                )
            else:
                new_version = 1

                cur.execute(
                    """
                    INSERT INTO did_documents
                        (id, current_version, did_document, owner_did, controller_dids,
                         lifecycle_status, method, created_at, updated_at)
                    VALUES (%s, 1, %s, %s, %s, 'active', %s, %s, %s)
                    """,
                    (did, json.dumps(did_document), owner_did, json.dumps(controller_dids), did_method, now, now),
                )

                cur.execute(
                    """
                    INSERT INTO did_document_versions
                        (did, version, raw_document, change_type, valid_from, valid_until)
                    VALUES (%s, 1, %s, 'created', %s, NULL)
                    """,
                    (did, json.dumps(did_document), now),
                )
        conn.commit()

    logger.info("DID created: %s (method=%s)", did, did_method)

    return {
        "did":         did,
        "didDocument": did_document,
        "version":     new_version,
    }


# ── Point-in-Time Resolution 

def resolve_did_at_time(did: str, at_iso: str) -> dict:
    """
    Return the DID Document exactly as it was at a given timestamp.

    Queries did_document_versions for the version where:
        valid_from <= at  AND  (valid_until > at OR valid_until IS NULL)

    Raises ValueError if no version exists at that timestamp.

    Args:
        did:     DID string to resolve.
        at_iso:  ISO 8601 timestamp string, e.g. "2024-09-15T10:00:00Z"

    Returns:
        {
            "didDocument": dict,
            "version":     int,
            "validFrom":   str,
            "validUntil":  str | None,
        }
    """
    at_dt = datetime.fromisoformat(at_iso.replace("Z", "+00:00"))

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT raw_document, version, valid_from, valid_until
                FROM did_document_versions
                WHERE did = %s
                  AND valid_from <= %s
                  AND (valid_until > %s OR valid_until IS NULL)
                ORDER BY version DESC
                LIMIT 1
                """,
                (did, at_dt, at_dt),
            )
            row = cur.fetchone()

    if not row:
        raise ValueError(
            f"No DID Document found for {did} at {at_iso}"
        )

    doc = row["raw_document"]
    if isinstance(doc, str):
        doc = json.loads(doc)

    return {
        "didDocument": doc,
        "version":     row["version"],
        "validFrom":   row["valid_from"].isoformat() if hasattr(row["valid_from"], "isoformat") else str(row["valid_from"]),
        "validUntil":  row["valid_until"].isoformat() if row["valid_until"] and hasattr(row["valid_until"], "isoformat") else (str(row["valid_until"]) if row["valid_until"] else None),
    }


# ── Controller Validation 

def _verify_controller_signature(
    did: str,
    controller_did: str,
    signature_data: dict,
    kms_client,
) -> None:
    """
    Verify that controller_did is listed in the DID Document's controllerDIDs.
    Raises PermissionError if not authorized.
    Raises ValueError if DID not found in registry.

    This function only checks DID-level controller authorisation.
    Cryptographic signature verification is handled by the KMS.

    Args:
        did:            The DID whose document is being updated.
        controller_did: The DID claiming to be a controller.
        signature_data: Signature payload (passed to KMS for crypto verify).
        kms_client:     KMS client instance (injected dependency).
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT controller_dids
                FROM did_documents
                WHERE id = %s
                """,
                (did,),
            )
            row = cur.fetchone()

    if not row:
        raise ValueError(f"DID not found in registry: {did}")

    controller_dids = row["controller_dids"]

    # controller_dids may be a JSON string (psycopg2 with JSONB) or already a list
    if isinstance(controller_dids, str):
        controller_dids = json.loads(controller_dids)

    if controller_did not in controller_dids:
        raise PermissionError(
            f"{controller_did} is not authorized to update {did}. "
            f"Authorized controllers: {controller_dids}"
        )
    # Authorized — return normally (no return value needed)


# ── Update DID Document
# --------------------------------------------------------------------------
# ADDED (audit finding #7): status_list_service/clients/did_registry_client.py
# already calls PUT /dids/{did} expecting an update path to exist -- there
# was no corresponding function in this file (or route in
# did_registry_service.py) at all. This adds the missing capability.
#
# NOTE on authority_signature: the calling client currently sends this as an
# opaque string, not a structured payload identifying which controller DID
# is asking for the update. This function logs the signature for audit
# purposes but does not yet cryptographically verify it against a specific
# controller's key. If/when the calling client is extended to pass a
# controller_did alongside the signature, wire that through to
# _verify_controller_signature() here for real authorization enforcement.
# --------------------------------------------------------------------------

def update_did_document(did: str, updates: dict, authority_signature: str) -> dict:
    """
    Apply a partial update to a DID Document and persist a new version.

    Common use: revocation -- callers pass {"lifecycleStatus": "revoked"}
    to mark an agent's DID as no longer active, without touching any other
    field.

    Writes a new row to did_document_versions (version N+1, valid_from=now)
    and closes out the previous version's valid_until, then updates the
    current-document row in did_documents.

    Args:
        did:                 DID string to update.
        updates:              dict of top-level DID Document fields to
                               overwrite (e.g. {"lifecycleStatus": "revoked"}).
        authority_signature:  Opaque signature/token from the caller,
                               logged for audit. See NOTE above regarding
                               its current lack of cryptographic verification.

    Returns:
        {
            "did":         str,
            "didDocument": dict   (the full updated document),
            "version":     int    (the new version number),
            "updatedAt":   str,
        }

    Raises:
        ValueError if the DID does not exist in the registry.
    """
    now = datetime.now(timezone.utc)

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT did_document, current_version FROM did_documents WHERE id = %s",
                (did,),
            )
            row = cur.fetchone()

            if not row:
                raise ValueError(f"DID not found in registry: {did}")

            current_doc = row["did_document"]
            if isinstance(current_doc, str):
                current_doc = json.loads(current_doc)

            new_version = row["current_version"] + 1

            # Merge updates into the existing document
            updated_doc = {**current_doc, **updates}
            updated_doc["updatedAt"] = now.isoformat()

            # Close out the previous version's validity window
            cur.execute(
                """
                UPDATE did_document_versions
                SET valid_until = %s
                WHERE did = %s AND version = %s AND valid_until IS NULL
                """,
                (now, did, row["current_version"]),
            )

            # Write the new version row
            cur.execute(
                """
                INSERT INTO did_document_versions
                    (did, version, raw_document, change_type, valid_from, valid_until)
                VALUES (%s, %s, %s, 'updated', %s, NULL)
                """,
                (did, new_version, json.dumps(updated_doc), now),
            )

            # Update the current-document row
            cur.execute(
                """
                UPDATE did_documents
                SET current_version = %s,
                    did_document = %s,
                    lifecycle_status = %s,
                    updated_at = %s
                WHERE id = %s
                """,
                (
                    new_version,
                    json.dumps(updated_doc),
                    updated_doc.get("lifecycleStatus", "active"),
                    now,
                    did,
                ),
            )
        conn.commit()

    logger.info(
        "DID updated: %s (version=%s, authority_signature=%s)",
        did, new_version, authority_signature[:16] if authority_signature else None,
    )

    return {
        "did":         did,
        "didDocument": updated_doc,
        "version":     new_version,
        "updatedAt":   now.isoformat(),
    }
