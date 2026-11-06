"""
Sub-System 3: Root Trust Anchor Service
Person A - Layer 1 Identity & Credential Management

The governance layer. Tells every verifier in the system which issuers are
trusted to issue which types of credentials in which trust domains.
Without this, the entire VC system has no foundation of trust.
"""

import os
import json
import uuid
import time
import base64
import logging
from datetime import datetime, timezone
from typing import Optional
import psycopg2
from psycopg2.extras import RealDictCursor
import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)
from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))


def _canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_add_issuer_admin_payload(
    issuer_did: str,
    credential_types: list,
    trust_domain: str,
    valid_until: Optional[str],
) -> dict:
    """
    Canonical payload that a governance admin must sign to accredit an issuer.
    Exposed so tests/scripts can sign the exact same bytes the service verifies.
    """
    return {
        "action": "trust-anchor.addIssuer",
        "issuerDID": issuer_did,
        "credentialTypes": credential_types,
        "trustDomain": trust_domain,
        "validUntil": valid_until,
    }


def build_remove_issuer_admin_payload(issuer_did: str, reason: str) -> dict:
    """Canonical payload that a governance admin must sign to remove an issuer."""
    return {
        "action": "trust-anchor.removeIssuer",
        "issuerDID": issuer_did,
        "reason": reason,
    }


def _configured_admin_dids() -> set[str]:
    raw = os.getenv("TRUST_ANCHOR_ADMIN_DIDS", "")
    return {did.strip() for did in raw.split(",") if did.strip()}


def _decode_signature(signature: str) -> bytes:
    padded = signature + ("=" * (-len(signature) % 4))
    try:
        return base64.b64decode(padded, validate=True)
    except Exception:
        return base64.urlsafe_b64decode(padded)


def _public_key_from_did_document(did_document: dict, verification_method: str = None) -> bytes:
    methods = did_document.get("verificationMethod", [])
    if verification_method:
        methods = [m for m in methods if m.get("id") == verification_method]
    if not methods:
        raise PermissionError("Admin DID document has no matching verificationMethod")

    public_key_multibase = methods[0].get("publicKeyMultibase")
    if not public_key_multibase or not public_key_multibase.startswith("z"):
        raise PermissionError("Admin verificationMethod missing supported publicKeyMultibase")

    decoded = base58.b58decode(public_key_multibase[1:])
    if len(decoded) < 2 or decoded[:2] != bytes([0xED, 0x01]):
        raise PermissionError("Admin verificationMethod is not an Ed25519 key")
    return decoded[2:]


def _verify_admin_signature(admin_signature: dict, payload: dict, did_registry_client) -> str:
    """
    Verify a governance admin signature before mutating trust-anchor state.

    Expected admin_signature:
      {
        "adminDID": "did:web:...",
        "signature": "<base64 signature over canonical payload>",
        "verificationMethod": "did:web:...#key-id"   # optional
      }
    """
    admin_did = (admin_signature or {}).get("adminDID")
    signature = (admin_signature or {}).get("signature")
    verification_method = (admin_signature or {}).get("verificationMethod")

    if not admin_did or not signature:
        raise PermissionError("adminSignature must include adminDID and signature")

    allowed_admins = _configured_admin_dids()
    if not allowed_admins:
        raise PermissionError("No governance admin DIDs configured in TRUST_ANCHOR_ADMIN_DIDS")
    if admin_did not in allowed_admins:
        raise PermissionError(f"Admin DID {admin_did} is not authorized for trust-anchor governance")

    try:
        admin_doc_data = did_registry_client.resolve_did(admin_did)
        admin_doc = admin_doc_data["didDocument"]
        if admin_doc.get("lifecycleStatus") not in ("active", None):
            raise PermissionError(f"Admin DID {admin_did} is not active")

        public_key = _public_key_from_did_document(admin_doc, verification_method)
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            _decode_signature(signature),
            _canonical_json_bytes(payload),
        )
    except InvalidSignature as exc:
        raise PermissionError("Invalid governance admin signature") from exc
    except PermissionError:
        raise
    except Exception as exc:
        raise PermissionError(f"Could not verify governance admin signature: {exc}") from exc

    return admin_did


# ─── Retry Helper (CockroachDB serialization failures) 

def run_with_retry(fn, max_retries=5):
    """
    Retry wrapper for CockroachDB optimistic concurrency.
    Retries on error 40001 (SerializationFailure) with exponential backoff.
    """
    for attempt in range(max_retries):
        try:
            return fn()
        except psycopg2.errors.SerializationFailure:
            if attempt == max_retries - 1:
                raise
            time.sleep(0.1 * (2 ** attempt))


# ─── Database Connection 

def get_db_connection():
    """
    FIX (found via live testing): trust_anchor_service.py runs this module
    standalone with CRDB_DB=trust_anchors set correctly. But vc_issuance.py
    ALSO imports this module directly and runs it in-process inside the
    vc_issuance container, which sets CRDB_DB=vc_issuance for its OWN
    database needs -- causing root_trust's queries to silently hit the
    wrong database (or fail entirely) when called from within vc_issuance.

    Fixed by checking a more specific TRUST_ANCHOR_CRDB_DB env var first,
    falling back to the generic CRDB_DB for backward compatibility with
    the standalone trust_anchor container (which only sets CRDB_DB).
    """
    return psycopg2.connect(
        host=os.getenv("CRDB_HOST", "localhost"),
        port=int(os.getenv("CRDB_PORT", "26257")),
        dbname=os.getenv("TRUST_ANCHOR_CRDB_DB", os.getenv("CRDB_DB", "trust_anchors")),
        user=os.getenv("CRDB_USER", "root"),
        password=os.getenv("CRDB_PASSWORD", ""),
        sslmode=os.getenv("CRDB_SSLMODE", "disable"),  # "require" in prod
        sslrootcert=os.getenv("CRDB_SSLROOTCERT", ""),
        cursor_factory=RealDictCursor,
    )


# ─── Schema 

TRUST_ANCHOR_SCHEMA = """
-- Issuer authorizations: who can issue what credentials in which trust domains
CREATE TABLE IF NOT EXISTS trust_anchor_issuers (
    id                  UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    issuer_did          TEXT NOT NULL,
    credential_types    JSONB NOT NULL DEFAULT '[]',
    trust_domain        TEXT NOT NULL,
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until         TIMESTAMPTZ,
    conditions          JSONB,
    added_by            TEXT NOT NULL,
    revoked             BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at          TIMESTAMPTZ,
    revocation_reason   TEXT,
    UNIQUE(issuer_did, trust_domain)
);

-- Signed trust anchor document versions
CREATE TABLE IF NOT EXISTS trust_anchor_documents (
    id              UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    version         INTEGER NOT NULL UNIQUE,
    document        JSONB NOT NULL,
    signature       TEXT NOT NULL,
    signed_by_key   TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Federation trust anchors (cross-org trust)
CREATE TABLE IF NOT EXISTS federation_trust_anchors (
    id              UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    org_name        TEXT NOT NULL UNIQUE,
    org_did         TEXT NOT NULL,
    root_public_key TEXT NOT NULL,
    trust_anchor_url TEXT NOT NULL,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active          BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_issuers_did
    ON trust_anchor_issuers(issuer_did, trust_domain);
CREATE INDEX IF NOT EXISTS idx_issuers_active
    ON trust_anchor_issuers(revoked, valid_until);
"""


def initialize_schema():
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(TRUST_ANCHOR_SCHEMA)
        conn.commit()
    logger.info("Trust Anchor schema initialized.")


# ─── Trust Document Builder 

def _build_trust_document(issuers: list, version: int) -> dict:
    """
    Constructs the signed trust anchor document.
    Lists all authorized issuers with their credential types and trust domains.
    """
    return {
        "@context": "https://w3id.org/trust-anchor/v1",
        "type": "TrustAnchorDocument",
        "version": version,
        "issuedAt": datetime.now(timezone.utc).isoformat(),
        "issuerAuthorizations": [
            {
                "issuerDID": issuer["issuer_did"],
                "credentialTypes": issuer["credential_types"],
                "trustDomain": issuer["trust_domain"],
                "validFrom": issuer["valid_from"].isoformat() if issuer["valid_from"] else None,
                "validUntil": issuer["valid_until"].isoformat() if issuer["valid_until"] else None,
                "conditions": issuer["conditions"],
            }
            for issuer in issuers
            if not issuer["revoked"]
        ],
    }


def _get_next_version() -> int:
    """Gets the next trust document version number."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COALESCE(MAX(version), 0) + 1 AS next FROM trust_anchor_documents")
            return cur.fetchone()["next"]


def _sign_and_store_document(document: dict, kms_client, root_key_id: str) -> tuple[str, int]:
    """
    Signs the trust document using KMS root key and stores it.
    Returns (signature, version).

    No is_current flag — current document is always the MAX(version) row.
    Uses retry logic for CockroachDB serialization failures (error 40001).
    """
    version = document["version"]
    payload = json.dumps(document, sort_keys=True).encode()

    sig_result = kms_client.sign_payload(key_id=root_key_id, payload=payload)
    signature = sig_result["signature"]

    def _write():
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO trust_anchor_documents (version, document, signature, signed_by_key)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (version, json.dumps(document), signature, root_key_id),
                )
            conn.commit()

    run_with_retry(_write)
    return signature, version


# ─── Get Trust Anchor 

def get_trust_anchor(kms_client) -> dict:
    """
    GET /trust-anchor
    Returns the current signed trust anchor document and root public key.
    All verifiers fetch this on startup and periodically refresh it.

    Returns:
        { signedTrustDocument, version, rootPublicKey }
    """
    root_key_id = os.getenv("ROOT_TRUST_KEY_ID", "root-trust-anchor-key")

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # Get current signed document — most recent version is always current
            cur.execute(
                "SELECT document, signature, version, signed_by_key FROM trust_anchor_documents ORDER BY version DESC LIMIT 1"
            )
            doc_row = cur.fetchone()

    if not doc_row:
        # No document yet — build one from current issuers
        return _rebuild_trust_document(kms_client, root_key_id)

    # Get root public key from KMS
    root_key_info = kms_client.get_public_key(doc_row["signed_by_key"])

    return {
        "signedTrustDocument": {
            **doc_row["document"],
            "proof": {
                "type": "Ed25519Signature2020",
                "verificationMethod": f"did:example:root#{root_key_id}",
                "signature": doc_row["signature"],
            },
        },
        "version": doc_row["version"],
        "rootPublicKey": root_key_info["publicKey"],
    }


def _rebuild_trust_document(kms_client, root_key_id: str) -> dict:
    """Builds and signs a fresh trust document from current issuers."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM trust_anchor_issuers WHERE revoked = FALSE ORDER BY id"
            )
            issuers = cur.fetchall()

    version = _get_next_version()
    document = _build_trust_document(issuers, version)
    signature, _ = _sign_and_store_document(document, kms_client, root_key_id)

    root_key_info = kms_client.get_public_key(root_key_id)

    return {
        "signedTrustDocument": {
            **document,
            "proof": {
                "type": "Ed25519Signature2020",
                "verificationMethod": f"did:example:root#{root_key_id}",
                "signature": signature,
            },
        },
        "version": version,
        "rootPublicKey": root_key_info["publicKey"],
    }


# ─── Federation Trust Anchor 

def get_federation_trust_anchor() -> dict:
    """
    GET /trust-anchor/federation
    Returns the federation trust document listing root trust anchors
    of each participating organization.
    Cross-org resolution path: federation anchor → org root → individual issuer DID.

    Returns:
        { signedFederationDocument, participatingOrgs }
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT org_name, org_did, root_public_key, trust_anchor_url FROM federation_trust_anchors WHERE active = TRUE"
            )
            orgs = cur.fetchall()

    participating_orgs = [
        {
            "orgName": org["org_name"],
            "orgDID": org["org_did"],
            "rootPublicKey": org["root_public_key"],
            "trustAnchorUrl": org["trust_anchor_url"],
        }
        for org in orgs
    ]

    federation_document = {
        "@context": "https://w3id.org/trust-anchor/federation/v1",
        "type": "FederationTrustAnchorDocument",
        "issuedAt": datetime.now(timezone.utc).isoformat(),
        "participatingOrganizations": participating_orgs,
    }

    return {
        "signedFederationDocument": federation_document,
        "participatingOrgs": participating_orgs,
    }


# ─── Validate Issuer Authority 

def validate_issuer(issuer_did: str, credential_type: str, trust_domain: str) -> dict:
    """
    POST /trust-anchor/validate
    Checks whether a specific issuer DID is authorized to issue a
    specific credential type in a specific trust domain.

    Called by Person B's Verification Service for every VC being verified.

    Args:
        issuer_did: DID of the issuer to validate.
        credential_type: Type of credential (e.g., 'RoleVC', 'ComplianceVC').
        trust_domain: Trust domain to validate within.

    Returns:
        { authorised: bool, reason: str, validUntil: str | None }
    """
    now = datetime.now(timezone.utc)

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT credential_types, trust_domain, valid_until, conditions
                FROM trust_anchor_issuers
                WHERE issuer_did = %s
                  AND trust_domain = %s
                  AND revoked = FALSE
                  AND valid_from <= %s
                  AND (valid_until IS NULL OR valid_until > %s)
                """,
                (issuer_did, trust_domain, now, now),
            )
            row = cur.fetchone()

    if not row:
        logger.warning(f"Issuer NOT authorized: did={issuer_did}, type={credential_type}, domain={trust_domain}")
        return {
            "authorised": False,
            "reason": f"Issuer {issuer_did} not found in trust domain '{trust_domain}' or authorization expired.",
            "validUntil": None,
        }

    authorized_types = row["credential_types"]
    if credential_type not in authorized_types:
        logger.warning(f"Issuer {issuer_did} not authorized for credential type {credential_type}")
        return {
            "authorised": False,
            "reason": f"Issuer {issuer_did} is not authorized to issue '{credential_type}'. "
                      f"Authorized types: {authorized_types}",
            "validUntil": row["valid_until"].isoformat() if row["valid_until"] else None,
        }

    logger.info(f"Issuer AUTHORIZED: did={issuer_did}, type={credential_type}, domain={trust_domain}")
    return {
        "authorised": True,
        "reason": "Issuer is authorized.",
        "validUntil": row["valid_until"].isoformat() if row["valid_until"] else None,
        "conditions": row["conditions"],
    }


# ─── Add Issuer (Accreditation Flow) 

def add_issuer(
    issuer_did: str,
    credential_types: list,
    trust_domain: str,
    valid_until: Optional[str],
    admin_signature: dict,
    kms_client,
    did_registry_client,
) -> dict:
    """
    POST /trust-anchor/issuers
    Adds a new issuer to the trust anchor document.

    Flow:
      1. Validate issuer DID exists and is active (calls DID Registry).
      2. Append new authorization entry.
      3. Re-sign the trust document with root key via KMS.
      4. Increment version and make new version available immediately.

    Args:
        issuer_did: DID of the issuer to accredit.
        credential_types: List of credential types this issuer may issue.
        trust_domain: Trust domain for this authorization.
        valid_until: ISO timestamp when authorization expires (None = never).
        admin_signature: Signature from governance authority.
        kms_client: KMS client for signing.
        did_registry_client: DID Registry client to verify issuer DID is active.

    Returns:
        { newTrustDocumentVersion, effectiveAt }
    """
    root_key_id = os.getenv("ROOT_TRUST_KEY_ID", "root-trust-anchor-key")

    governance_payload = build_add_issuer_admin_payload(
        issuer_did=issuer_did,
        credential_types=credential_types,
        trust_domain=trust_domain,
        valid_until=valid_until,
    )
    admin_did = _verify_admin_signature(admin_signature, governance_payload, did_registry_client)

    # Step 1: Verify issuer DID exists and is active in the DID Registry
    try:
        issuer_doc_data = did_registry_client.resolve_did(issuer_did)
        issuer_doc = issuer_doc_data["didDocument"]
        if issuer_doc.get("lifecycleStatus") not in ("active", None):
            raise ValueError(f"Issuer DID {issuer_did} is not active (status: {issuer_doc.get('lifecycleStatus')})")
    except Exception as e:
        raise ValueError(f"Cannot accredit issuer {issuer_did}: DID resolution failed — {e}")

    now = datetime.now(timezone.utc)
    valid_until_ts = datetime.fromisoformat(valid_until.replace("Z", "+00:00")) if valid_until else None

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # Step 2: Upsert issuer authorization
            cur.execute(
                """
                INSERT INTO trust_anchor_issuers (
                    issuer_did, credential_types, trust_domain,
                    valid_from, valid_until, added_by, revoked
                )
                VALUES (%s, %s, %s, %s, %s, %s, FALSE)
                ON CONFLICT (issuer_did, trust_domain)
                DO UPDATE SET
                    credential_types = EXCLUDED.credential_types,
                    valid_until = EXCLUDED.valid_until,
                    revoked = FALSE,
                    revoked_at = NULL
                """,
                (
                    issuer_did,
                    json.dumps(credential_types),
                    trust_domain,
                    now,
                    valid_until_ts,
                    admin_did,
                ),
            )

            # Fetch all active issuers for new document
            cur.execute("SELECT * FROM trust_anchor_issuers WHERE revoked = FALSE ORDER BY id")
            all_issuers = cur.fetchall()

        conn.commit()

    # Step 3: Build + sign new trust document
    new_version = _get_next_version()
    document = _build_trust_document(all_issuers, new_version)
    _sign_and_store_document(document, kms_client, root_key_id)

    logger.info(f"Issuer accredited: {issuer_did}, types={credential_types}, domain={trust_domain}, version={new_version}")

    return {
        "newTrustDocumentVersion": new_version,
        "effectiveAt": now.isoformat(),
        "issuerDID": issuer_did,
        "credentialTypes": credential_types,
        "trustDomain": trust_domain,
    }


# ─── Remove Issuer 

def remove_issuer(issuer_did: str, reason: str, admin_signature: dict, kms_client, did_registry_client) -> dict:
    """
    DELETE /trust-anchor/issuers/:did
    Revokes an issuer's authorization. Re-signs and publishes new trust document.

    Returns:
        { removedAt, newTrustDocumentVersion }
    """
    root_key_id = os.getenv("ROOT_TRUST_KEY_ID", "root-trust-anchor-key")
    now = datetime.now(timezone.utc)

    governance_payload = build_remove_issuer_admin_payload(issuer_did=issuer_did, reason=reason)
    _verify_admin_signature(admin_signature, governance_payload, did_registry_client)

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # Mark issuer as revoked
            cur.execute(
                """
                UPDATE trust_anchor_issuers
                SET revoked = TRUE, revoked_at = %s, revocation_reason = %s
                WHERE issuer_did = %s AND revoked = FALSE
                """,
                (now, reason, issuer_did),
            )
            affected = cur.rowcount

            if affected == 0:
                raise ValueError(f"Issuer {issuer_did} not found or already revoked.")

            # Fetch remaining active issuers
            cur.execute("SELECT * FROM trust_anchor_issuers WHERE revoked = FALSE ORDER BY id")
            all_issuers = cur.fetchall()

        conn.commit()

    # Build + sign updated trust document
    new_version = _get_next_version()
    document = _build_trust_document(all_issuers, new_version)
    _sign_and_store_document(document, kms_client, root_key_id)

    logger.info(f"Issuer removed from trust anchor: {issuer_did}, reason={reason}, version={new_version}")

    return {
        "removedAt": now.isoformat(),
        "newTrustDocumentVersion": new_version,
        "issuerDID": issuer_did,
        "reason": reason,
    }


# ─── Federation Management 

def add_federation_org(
    org_name: str,
    org_did: str,
    root_public_key: str,
    trust_anchor_url: str,
) -> dict:
    """
    Adds a participating organization to the federation trust document.
    Used for cross-organizational trust scenarios.

    Returns:
        { orgName, addedAt }
    """
    now = datetime.now(timezone.utc)

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO federation_trust_anchors (org_name, org_did, root_public_key, trust_anchor_url, added_at, active)
                VALUES (%s, %s, %s, %s, %s, TRUE)
                ON CONFLICT (org_name) DO UPDATE SET
                    org_did = EXCLUDED.org_did,
                    root_public_key = EXCLUDED.root_public_key,
                    trust_anchor_url = EXCLUDED.trust_anchor_url,
                    active = TRUE
                """,
                (org_name, org_did, root_public_key, trust_anchor_url, now),
            )
        conn.commit()

    logger.info(f"Federation org added: {org_name} ({org_did})")
    return {"orgName": org_name, "addedAt": now.isoformat()}
