"""
vc_issuance.py
──────────────
Sub-System 4: VC Issuance Service  (Person B — Layer 1)

Issues all six VC types. Validates authority, constructs W3C-compliant
VC JSON-LD, signs via KMS, registers in StatusList, persists to vc_log.

Exports:
  get_db_connection()
  initialize_schema()
  issue_role_vc()
  issue_capability_vc()
  issue_compliance_vc()
  issue_provenance_vc()
  issue_reputation_vc()
  issue_jit_vc()
  get_credential_log()
"""

import os
import json
import uuid
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from contextlib import contextmanager

import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

import kms
import did as did_registry
import root_trust
import status_list

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
logger = logging.getLogger(__name__)

# Default JIT VC max minutes
JIT_VC_MAX_MINUTES = int(os.getenv("JIT_VC_MAX_MINUTES", "15"))
AUTOCREATE_SCHEMA = os.getenv("AUTOCREATE_SCHEMA", "false").lower() == "true"


# ── Database Connection 

def get_db_connection():
    """
    Get a CockroachDB connection with RealDictCursor.
    Matches pattern from did.py and root_trust.py.

    Returns:
        psycopg2 connection object
    """
    return psycopg2.connect(
        host=os.getenv("CRDB_HOST", "localhost"),
        port=int(os.getenv("CRDB_PORT", "26257")),
        dbname=os.getenv("CRDB_DB", "did_registry"),
        user=os.getenv("CRDB_USER", "root"),
        password=os.getenv("CRDB_PASSWORD", ""),
        sslmode=os.getenv("CRDB_SSLMODE", "disable"),
        sslrootcert=os.getenv("CRDB_SSLROOTCERT", ""),
        cursor_factory=RealDictCursor,
    )


# ── Schema 

VC_SCHEMA = """
CREATE TABLE IF NOT EXISTS vc_credentials (
    id                   TEXT PRIMARY KEY,
    subject_did          TEXT NOT NULL,
    issuer_did           TEXT NOT NULL,
    credential_type      TEXT NOT NULL,
    trust_domain         TEXT NOT NULL,
    issued_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at           TIMESTAMPTZ NOT NULL,
    status               TEXT NOT NULL DEFAULT 'active',
    status_list_url      TEXT,
    status_list_index    INTEGER,
    content_hash         TEXT NOT NULL,
    raw_vc               JSONB NOT NULL,
    revoked_at           TIMESTAMPTZ,
    revocation_reason    TEXT
);

CREATE INDEX IF NOT EXISTS idx_vc_subject    ON vc_credentials(subject_did);
CREATE INDEX IF NOT EXISTS idx_vc_issuer     ON vc_credentials(issuer_did);
CREATE INDEX IF NOT EXISTS idx_vc_type       ON vc_credentials(credential_type);
CREATE INDEX IF NOT EXISTS idx_vc_status     ON vc_credentials(status);
"""


def initialize_schema() -> None:
    """
    Create vc_credentials table and indices if they don't exist.
    Called at module import if AUTOCREATE_SCHEMA=true, or manually by user.

    Returns:
        None
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(VC_SCHEMA)
        conn.commit()
        logger.info("VC schema initialized.")
    finally:
        conn.close()


# Auto-create schema at module import if enabled
if AUTOCREATE_SCHEMA:
    try:
        initialize_schema()
    except Exception as e:
        logger.warning(f"Failed to auto-create schema: {e}")


# ── W3C VC Document Builder 

def _build_vc_document(
    vc_id: str,
    issuer_did: str,
    subject_did: str,
    credential_type: str,
    claims: dict,
    valid_from: datetime,
    valid_until: datetime,
) -> dict:
    """
    Construct a W3C VC JSON-LD document structure.
    Does NOT include proof or credentialStatus blocks — those are added later.

    Args:
        vc_id:              urn:uuid:<uuid>
        issuer_did:         DID of the issuer
        subject_did:        DID of the credential subject
        credential_type:    e.g. "RoleVC", "CapabilityVC"
        claims:             Credential-specific claims dict
        valid_from:         datetime when credential becomes valid
        valid_until:        datetime when credential expires

    Returns:
        dict: W3C VC document (without proof or credentialStatus)
    """
    return {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
            "https://w3id.org/vc-status-list-2021/v1"
        ],
        "id": vc_id,
        "type": ["VerifiableCredential", credential_type],
        "issuer": {
            "id": issuer_did
        },
        "issuanceDate": valid_from.isoformat(),
        "expirationDate": valid_until.isoformat(),
        "credentialSubject": {
            "id": subject_did,
            **claims
        }
    }


# ── Claims Validators 

def _validate_claims_role(claims: dict) -> None:
    """
    Validate Role VC claims.
    Required: roleName, roleDescription, organisationDID

    Args:
        claims: dict of claims

    Raises:
        ValueError: if required claims are missing or invalid
    """
    required = ["roleName", "roleDescription", "organisationDID"]
    for field in required:
        if field not in claims or not claims[field]:
            raise ValueError(f"Missing required claim: {field}")

    if not isinstance(claims["roleName"], str) or not claims["roleName"].strip():
        raise ValueError("roleName must be a non-empty string")
    if not isinstance(claims["roleDescription"], str) or not claims["roleDescription"].strip():
        raise ValueError("roleDescription must be a non-empty string")
    if not isinstance(claims["organisationDID"], str) or not claims["organisationDID"].strip():
        raise ValueError("organisationDID must be a non-empty string")


def _validate_claims_capability(claims: dict, subject_did: str) -> None:
    """
    Validate Capability VC claims.
    Required: capabilityName, certifiedActions, toolsDID, modelVersionHash, certifyingBodyDID
    Special rule: modelVersionHash must match subject's DID Document modelHash.

    Args:
        claims:      dict of claims
        subject_did: DID of subject (needed to resolve DID Document for model hash check)

    Raises:
        ValueError: if required claims missing or model hash mismatch
    """
    required = ["capabilityName", "certifiedActions", "toolsDID", "modelVersionHash", "certifyingBodyDID"]
    for field in required:
        if field not in claims or (claims[field] is None or (isinstance(claims[field], (list, str)) and not claims[field])):
            raise ValueError(f"Missing required claim: {field}")

    if not isinstance(claims["capabilityName"], str) or not claims["capabilityName"].strip():
        raise ValueError("capabilityName must be a non-empty string")
    if not isinstance(claims["certifiedActions"], list) or len(claims["certifiedActions"]) == 0:
        raise ValueError("certifiedActions must be a non-empty array")
    if not isinstance(claims["toolsDID"], list) or len(claims["toolsDID"]) == 0:
        raise ValueError("toolsDID must be a non-empty array")

    # Check model hash matches subject's DID Document
    try:
        did_result = did_registry.resolve_did_at_time(subject_did, datetime.now(timezone.utc).isoformat())
        subject_model_hash = did_result["didDocument"].get("modelHash")
        
        if subject_model_hash != claims["modelVersionHash"]:
            raise ValueError(
                f"Model hash mismatch: capability VC certified for different model version"
            )
    except Exception as e:
        if "Model hash mismatch" in str(e):
            raise
        # If DID resolution fails for other reasons, let it propagate
        raise ValueError(f"Cannot resolve subject DID for model hash verification: {e}")


def _validate_claims_compliance(claims: dict) -> None:
    """
    Validate Compliance VC claims.
    Required: complianceFramework, auditDate, auditRef, auditBodyDID, scope

    Args:
        claims: dict of claims

    Raises:
        ValueError: if required claims missing
    """
    required = ["complianceFramework", "auditDate", "auditRef", "auditBodyDID", "scope"]
    for field in required:
        if field not in claims or not claims[field]:
            raise ValueError(f"Missing required claim: {field}")

    if not isinstance(claims["complianceFramework"], str) or not claims["complianceFramework"].strip():
        raise ValueError("complianceFramework must be a non-empty string")
    if not isinstance(claims["auditDate"], str) or not claims["auditDate"].strip():
        raise ValueError("auditDate must be a non-empty ISO 8601 string")
    if not isinstance(claims["auditRef"], str) or not claims["auditRef"].strip():
        raise ValueError("auditRef must be a non-empty string")


def _validate_claims_provenance(claims: dict) -> None:
    """
    Validate Provenance VC claims.
    Required: parentDID, spawnedAt, spawnReason, provenanceAttestation

    Args:
        claims: dict of claims

    Raises:
        ValueError: if required claims missing
    """
    required = ["parentDID", "spawnedAt", "spawnReason", "provenanceAttestation"]
    for field in required:
        if field not in claims or not claims[field]:
            raise ValueError(f"Missing required claim: {field}")

    if not isinstance(claims["parentDID"], str) or not claims["parentDID"].strip():
        raise ValueError("parentDID must be a non-empty string")
    if not isinstance(claims["spawnedAt"], str) or not claims["spawnedAt"].strip():
        raise ValueError("spawnedAt must be a non-empty ISO 8601 string")
    if not isinstance(claims["spawnReason"], str) or not claims["spawnReason"].strip():
        raise ValueError("spawnReason must be a non-empty string")
    if not isinstance(claims["provenanceAttestation"], str) or not claims["provenanceAttestation"].strip():
        raise ValueError("provenanceAttestation must be a non-empty string")


def _validate_claims_reputation(claims: dict) -> None:
    """
    Validate Reputation VC claims.
    Required: reputationScore, tasksCompleted, violationCount, peerDID

    Args:
        claims: dict of claims

    Raises:
        ValueError: if required claims missing or invalid
    """
    required = ["reputationScore", "tasksCompleted", "violationCount", "peerDID"]
    for field in required:
        if field not in claims:
            raise ValueError(f"Missing required claim: {field}")

    if not isinstance(claims["reputationScore"], (int, float)) or not (0 <= claims["reputationScore"] <= 100):
        raise ValueError("reputationScore must be a number between 0 and 100")
    if not isinstance(claims["tasksCompleted"], int) or claims["tasksCompleted"] < 0:
        raise ValueError("tasksCompleted must be a non-negative integer")
    if not isinstance(claims["violationCount"], int) or claims["violationCount"] < 0:
        raise ValueError("violationCount must be a non-negative integer")
    if not isinstance(claims["peerDID"], str) or not claims["peerDID"].strip():
        raise ValueError("peerDID must be a non-empty string")


def _validate_claims_jit(claims: dict, subject_did: str) -> None:
    """
    Validate JIT VC claims.
    Required: jobID, toolDID, allowedAction, inputHandle, outputHandle
    Special rule: toolDID must be in subject's DID Document toolset array.

    Args:
        claims:      dict of claims
        subject_did: DID of subject (needed to check toolset)

    Raises:
        ValueError: if required fields missing, empty, or toolDID not in toolset
    """
    required = ["jobID", "toolDID", "allowedAction", "inputHandle", "outputHandle"]
    for field in required:
        if field not in claims or not claims[field]:
            raise ValueError(f"Missing required claim: {field}")

    # Verify all required fields are non-empty strings
    for field in required:
        if not isinstance(claims[field], str) or not claims[field].strip():
            raise ValueError(f"Required JIT field {field} must be a non-empty string")

    # Verify toolDID is in subject's toolset
    try:
        did_result = did_registry.resolve_did_at_time(subject_did, datetime.now(timezone.utc).isoformat())
        subject_toolset = did_result["didDocument"].get("toolset", [])
        
        # Handle both flat list of DIDs and list of dicts {toolName, toolDID}
        toolset_dids = [
            t if isinstance(t, str) else t.get("toolDID", "")
            for t in subject_toolset
        ]
        
        if claims["toolDID"] not in toolset_dids:
            raise ValueError(
                f"toolDID {claims['toolDID']} not in subject agent's authorised toolset"
            )
    except ValueError as e:
        if "not in subject agent's authorised toolset" in str(e):
            raise
        raise ValueError(f"Cannot resolve subject DID for toolset verification: {e}")


def _validate_peer_issuer(issuer_did: str) -> None:
    """
    Validate that a peer issuer (agent DID) is active.
    Unlike other VC types, Reputation VCs can be issued by any active agent,
    not just governance DIDs listed in trust_anchor_issuers.

    Args:
        issuer_did: DID of the peer issuer (agent)

    Raises:
        ValueError: if DID not found or not active
    """
    try:
        did_result = did_registry.resolve_did_at_time(issuer_did, datetime.now(timezone.utc).isoformat())
        did_doc = did_result["didDocument"]
        
        if did_doc.get("lifecycleStatus") != "active":
            raise ValueError(
                f"Peer issuer DID {issuer_did} is not active: {did_doc.get('lifecycleStatus')}"
            )
    except ValueError as e:
        if "is not active" in str(e):
            raise
        raise ValueError(f"Peer issuer DID {issuer_did} not found or cannot be resolved: {e}")


# ── Persistence 

def _persist_vc(vc_result: dict, trust_domain: str) -> None:
    """
    Write VC record to vc_credentials table.
    Called as the final step of the issuance pipeline (step 7).

    Args:
        vc_result:   dict with keys: vcId, signedVC, credentialType, subjectDID, issuerDID,
                     issuedAt, expiresAt, statusListUrl, statusListIndex, contentHash
        trust_domain: trust domain for this VC

    Raises:
        RuntimeError: if database write fails
    """
    try:
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO vc_credentials
                        (id, subject_did, issuer_did, credential_type, trust_domain,
                         issued_at, expires_at, status, status_list_url, status_list_index,
                         content_hash, raw_vc)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        vc_result["vcId"],
                        vc_result["subjectDID"],
                        vc_result["issuerDID"],
                        vc_result["credentialType"],
                        trust_domain,
                        vc_result["issuedAt"],
                        vc_result["expiresAt"],
                        "active",
                        vc_result["statusListUrl"],
                        vc_result["statusListIndex"],
                        vc_result["contentHash"],
                        json.dumps(vc_result["signedVC"])
                    )
                )
            conn.commit()
            logger.info(f"VC {vc_result['vcId']} persisted to vc_credentials table")
        finally:
            conn.close()
    except Exception as e:
        raise RuntimeError(f"VC log write failed: {e}")


# ── Issuance Pipeline 

def _run_issuance_pipeline(
    credential_type: str,
    subject_did: str,
    issuer_did: str,
    issuer_key_id: str,
    claims: dict,
    trust_domain: str,
    valid_from: datetime,
    valid_until: datetime,
    claims_validator: callable,
    skip_authority_check: bool = False,
) -> dict:
    """
    Execute the 8-step issuance pipeline for a VC.
    This is called by all issue_*_vc() functions.

    Step 1: Authority check (validate_issuer or _validate_peer_issuer)
    Step 2: Subject DID active check
    Step 3: Type-specific claim validation
    Step 4: Construct W3C VC JSON-LD
    Step 5: Allocate StatusList2021 entry
    Step 6: Sign the VC via KMS
    Step 7: Persist to vc_log
    Step 8: Return

    Args:
        credential_type:      VC type ("RoleVC", etc.)
        subject_did:          Subject DID
        issuer_did:           Issuer DID
        issuer_key_id:        Key ID for signing
        claims:               Credential claims
        trust_domain:         Trust domain
        valid_from:           Issuance date
        valid_until:          Expiration date
        claims_validator:     Function to validate claims for this type
        skip_authority_check: If True, skip validate_issuer (for Reputation VCs)

    Returns:
        dict: result dict with vcId, signedVC, etc.

    Raises:
        PermissionError, ValueError, RuntimeError on any step failure
    """
    # Step 1: Authority check
    if not skip_authority_check:
        auth_result = root_trust.validate_issuer(issuer_did, credential_type, trust_domain)
        if not auth_result["authorised"]:
            raise PermissionError(auth_result["reason"])
        logger.info(f"Step 1 passed: issuer {issuer_did} authorized for {credential_type}")
    else:
        logger.info(f"Step 1 skipped: skip_authority_check=True (Reputation VC peer-issued)")

    # Step 2: Subject DID active check
    try:
        did_result = did_registry.resolve_did_at_time(subject_did, datetime.now(timezone.utc).isoformat())
        did_doc = did_result["didDocument"]
    except ValueError as e:
        raise ValueError(f"Subject DID {subject_did} not found")

    if did_doc.get("lifecycleStatus") != "active":
        raise ValueError(
            f"Subject DID {subject_did} is not active: {did_doc.get('lifecycleStatus')}"
        )
    logger.info(f"Step 2 passed: subject {subject_did} is active")

    # Step 3: Type-specific claim validation
    claims_validator(claims)
    logger.info(f"Step 3 passed: claims validated for {credential_type}")

    # Step 4: Construct W3C VC JSON-LD
    vc_id = f"urn:uuid:{uuid.uuid4()}"
    vc_document = _build_vc_document(
        vc_id=vc_id,
        issuer_did=issuer_did,
        subject_did=subject_did,
        credential_type=credential_type,
        claims=claims,
        valid_from=valid_from,
        valid_until=valid_until,
    )
    logger.info(f"Step 4 passed: VC document constructed")

    # Step 5: Allocate StatusList2021 entry
    try:
        status_result = status_list.allocate_status_entry(vc_id, issuer_did)
        status_list_url = status_result["statusListUrl"]
        status_list_index = status_result["bitIndex"]
    except Exception as e:
        raise RuntimeError(f"StatusList allocation failed: {e}")

    vc_document["credentialStatus"] = {
        "id": f"{status_list_url}#{status_list_index}",
        "type": "StatusList2021Entry",
        "statusPurpose": "revocation",
        "statusListIndex": str(status_list_index),
        "statusListCredential": status_list_url
    }
    logger.info(f"Step 5 passed: StatusList entry allocated at index {status_list_index}")

    # Compute content hash BEFORE signing (hash the content without proof)
    content_hash = hashlib.sha3_256(
        json.dumps(vc_document, sort_keys=True).encode()
    ).hexdigest()

    # Step 6: Sign the VC via KMS
    try:
        payload = json.dumps(vc_document, sort_keys=True).encode()
        sig_result = kms.sign_payload(key_id=issuer_key_id, payload=payload)
        signature = sig_result["signature"]
    except Exception as e:
        raise RuntimeError(f"KMS signing failed: {e}")

    now_iso = datetime.now(timezone.utc).isoformat()
    vc_document["proof"] = {
        "type": "Ed25519Signature2020",
        "created": now_iso,
        "verificationMethod": f"{issuer_did}#{issuer_key_id}",
        "proofPurpose": "assertionMethod",
        "proofValue": signature
    }
    logger.info(f"Step 6 passed: VC signed with proof block")

    # Step 7: Persist to vc_log
    vc_result = {
        "vcId": vc_id,
        "signedVC": vc_document,
        "credentialType": credential_type,
        "subjectDID": subject_did,
        "issuerDID": issuer_did,
        "issuedAt": valid_from.isoformat(),
        "expiresAt": valid_until.isoformat(),
        "statusListUrl": status_list_url,
        "statusListIndex": status_list_index,
        "contentHash": content_hash,
    }
    _persist_vc(vc_result, trust_domain)
    logger.info(f"Step 7 passed: VC persisted to database")

    # Step 8: Return
    logger.info(f"VC {vc_id} issued successfully (type={credential_type})")
    return vc_result


# ── Public Issuance Functions 

def issue_role_vc(
    subject_did: str,
    issuer_did: str,
    issuer_key_id: str,
    claims: dict,
    trust_domain: str = "enterprise",
    valid_until_iso: str = None,
) -> dict:
    """
    Issue a Role VC (attestation of organisational role).

    Required claims: roleName, roleDescription, organisationDID
    Optional claims: department, reportingTo
    Default validity: 365 days

    Args:
        subject_did:      DID of the agent receiving the role
        issuer_did:       DID of the HR authority
        issuer_key_id:    Key ID for signing
        claims:           dict with roleName, roleDescription, organisationDID, etc.
        trust_domain:     trust domain (default "enterprise")
        valid_until_iso:  ISO string for expiration (default now + 365 days)

    Returns:
        dict: {vcId, signedVC, credentialType, subjectDID, issuerDID, issuedAt, expiresAt, statusListUrl, statusListIndex, contentHash}

    Raises:
        PermissionError, ValueError, RuntimeError
    """
    now = datetime.now(timezone.utc)
    valid_from = now
    valid_until = datetime.fromisoformat(valid_until_iso.replace("Z", "+00:00")) if valid_until_iso else now + timedelta(days=365)

    return _run_issuance_pipeline(
        credential_type="RoleVC",
        subject_did=subject_did,
        issuer_did=issuer_did,
        issuer_key_id=issuer_key_id,
        claims=claims,
        trust_domain=trust_domain,
        valid_from=valid_from,
        valid_until=valid_until,
        claims_validator=_validate_claims_role,
    )


def issue_capability_vc(
    subject_did: str,
    issuer_did: str,
    issuer_key_id: str,
    claims: dict,
    trust_domain: str = "enterprise",
    valid_until_iso: str = None,
) -> dict:
    """
    Issue a Capability VC (technical certification).

    Required claims: capabilityName, certifiedActions, toolsDID, modelVersionHash, certifyingBodyDID
    Default validity: 180 days
    Special rule: modelVersionHash must match subject's DID Document modelHash

    Args:
        subject_did:      DID of the certified agent
        issuer_did:       DID of technical governance authority
        issuer_key_id:    Key ID for signing
        claims:           dict with capability details
        trust_domain:     trust domain (default "enterprise")
        valid_until_iso:  ISO string for expiration (default now + 180 days)

    Returns:
        dict: result dict

    Raises:
        PermissionError, ValueError, RuntimeError
    """
    now = datetime.now(timezone.utc)
    valid_from = now
    valid_until = datetime.fromisoformat(valid_until_iso.replace("Z", "+00:00")) if valid_until_iso else now + timedelta(days=180)

    return _run_issuance_pipeline(
        credential_type="CapabilityVC",
        subject_did=subject_did,
        issuer_did=issuer_did,
        issuer_key_id=issuer_key_id,
        claims=claims,
        trust_domain=trust_domain,
        valid_from=valid_from,
        valid_until=valid_until,
        claims_validator=lambda c: _validate_claims_capability(c, subject_did),
    )


def issue_compliance_vc(
    subject_did: str,
    issuer_did: str,
    issuer_key_id: str,
    claims: dict,
    trust_domain: str = "enterprise",
    valid_until_iso: str = None,
) -> dict:
    """
    Issue a Compliance VC (regulatory certification).

    Required claims: complianceFramework, auditDate, auditRef, auditBodyDID, scope
    Optional claims: nextAuditDue
    Default validity: 365 days

    Args:
        subject_did:      DID of the compliant entity
        issuer_did:       DID of audit authority
        issuer_key_id:    Key ID for signing
        claims:           dict with compliance details
        trust_domain:     trust domain (default "enterprise")
        valid_until_iso:  ISO string for expiration (default now + 365 days)

    Returns:
        dict: result dict

    Raises:
        PermissionError, ValueError, RuntimeError
    """
    now = datetime.now(timezone.utc)
    valid_from = now
    valid_until = datetime.fromisoformat(valid_until_iso.replace("Z", "+00:00")) if valid_until_iso else now + timedelta(days=365)

    return _run_issuance_pipeline(
        credential_type="ComplianceVC",
        subject_did=subject_did,
        issuer_did=issuer_did,
        issuer_key_id=issuer_key_id,
        claims=claims,
        trust_domain=trust_domain,
        valid_from=valid_from,
        valid_until=valid_until,
        claims_validator=_validate_claims_compliance,
    )


def issue_provenance_vc(
    subject_did: str,
    issuer_did: str,
    issuer_key_id: str,
    claims: dict,
    trust_domain: str = "enterprise",
) -> dict:
    """
    Issue a Provenance VC (lineage attestation when agent is spawned).

    Required claims: parentDID, spawnedAt, spawnReason, provenanceAttestation
    Optional claims: jobID
    Default validity: 99 years (permanent)

    Args:
        subject_did:      DID of the spawned agent
        issuer_did:       DID of parent agent or platform management
        issuer_key_id:    Key ID for signing
        claims:           dict with parentDID, spawnedAt, etc.
        trust_domain:     trust domain (default "enterprise")

    Returns:
        dict: result dict

    Raises:
        PermissionError, ValueError, RuntimeError
    """
    now = datetime.now(timezone.utc)
    valid_from = now
    valid_until = now + timedelta(days=365*99)

    return _run_issuance_pipeline(
        credential_type="ProvenanceVC",
        subject_did=subject_did,
        issuer_did=issuer_did,
        issuer_key_id=issuer_key_id,
        claims=claims,
        trust_domain=trust_domain,
        valid_from=valid_from,
        valid_until=valid_until,
        claims_validator=_validate_claims_provenance,
    )


def issue_reputation_vc(
    subject_did: str,
    issuer_did: str,
    issuer_key_id: str,
    claims: dict,
    trust_domain: str = "enterprise",
    valid_until_iso: str = None,
) -> dict:
    """
    Issue a Reputation VC (peer-issued performance attestation).

    SPECIAL RULE: issuer_did is a peer agent DID (not a governance DID).
    Authority check is replaced with peer issuer active check.

    Required claims: reputationScore, tasksCompleted, violationCount, peerDID
    Optional claims: collaborationJobIDs, assessmentSummary
    Default validity: 365 days

    Args:
        subject_did:      DID of the peer being assessed
        issuer_did:       DID of the peer agent issuing the reputation (NOT an authority)
        issuer_key_id:    Key ID for signing
        claims:           dict with reputation details
        trust_domain:     trust domain (default "enterprise")
        valid_until_iso:  ISO string for expiration (default now + 365 days)

    Returns:
        dict: result dict

    Raises:
        ValueError, RuntimeError
    """
    now = datetime.now(timezone.utc)
    valid_from = now
    valid_until = datetime.fromisoformat(valid_until_iso.replace("Z", "+00:00")) if valid_until_iso else now + timedelta(days=365)

    # Validate peer issuer first (before pipeline, so we fail fast)
    _validate_peer_issuer(issuer_did)

    return _run_issuance_pipeline(
        credential_type="ReputationVC",
        subject_did=subject_did,
        issuer_did=issuer_did,
        issuer_key_id=issuer_key_id,
        claims=claims,
        trust_domain=trust_domain,
        valid_from=valid_from,
        valid_until=valid_until,
        claims_validator=_validate_claims_reputation,
        skip_authority_check=True,
    )


def issue_jit_vc(
    subject_did: str,
    issuer_did: str,
    issuer_key_id: str,
    claims: dict,
    trust_domain: str = "enterprise",
    valid_until_iso: str = None,
) -> dict:
    """
    Issue a JIT VC (Just-In-Time credential for single tool invocation).

    Ultra-short-lived credential. Default: 15 minutes. Maximum allowed: 60 minutes.

    Required claims: jobID, toolDID, allowedAction, inputHandle, outputHandle
    Optional claims: scopeNote
    Special rule: toolDID must be in subject's DID Document toolset array.

    Args:
        subject_did:      DID of the agent invoking the tool
        issuer_did:       DID of workflow engine
        issuer_key_id:    Key ID for signing
        claims:           dict with JIT-specific fields
        trust_domain:     trust domain (default "enterprise")
        valid_until_iso:  ISO string (default now + 15 min); MUST be <= now + 60 min

    Returns:
        dict: result dict

    Raises:
        PermissionError, ValueError, RuntimeError
    """
    now = datetime.now(timezone.utc)
    valid_from = now

    if valid_until_iso:
        valid_until = datetime.fromisoformat(valid_until_iso.replace("Z", "+00:00"))
    else:
        valid_until = now + timedelta(minutes=JIT_VC_MAX_MINUTES)

    # Check validity doesn't exceed 60 minutes
    max_valid_until = now + timedelta(minutes=60)
    if valid_until > max_valid_until:
        raise ValueError("JIT VC validity exceeds maximum of 60 minutes")

    return _run_issuance_pipeline(
        credential_type="JITVC",
        subject_did=subject_did,
        issuer_did=issuer_did,
        issuer_key_id=issuer_key_id,
        claims=claims,
        trust_domain=trust_domain,
        valid_from=valid_from,
        valid_until=valid_until,
        claims_validator=lambda c: _validate_claims_jit(c, subject_did),
    )


# ── Credential Log Query 

def log_peer_issued_vc(
    signed_vc_jwt: str,
    subject_did: str,
    issuer_did: str,
    credential_type: str = "ReputationVC",
    trust_domain: str = "peer",
    valid_days: int = 365,
) -> dict:
    """
    Persist an already-signed, peer-issued VC to the audit log WITHOUT
    re-signing it or running it through the full issuance pipeline.

    ADDED (audit finding #8): wallet_service's reputation_issuer.py signs
    reputation VCs itself (using the issuing agent's own KMS key) and only
    needs this service to *record* the result for audit purposes -- it
    explicitly does not want this service acting as the signing authority
    for peer-to-peer reputation credentials. No such "log only, don't
    re-sign" function existed before; issue_reputation_vc() always signs
    with a centrally-authorized issuer_key_id, which is the wrong tool for
    this peer-issuance case.

    Args:
        signed_vc_jwt:    The already-signed VC (JWT string) as produced
                           by the issuing agent's own wallet/KMS.
        subject_did:       DID the credential is about.
        issuer_did:        DID that signed the credential (the peer agent).
        credential_type:   Defaults to "ReputationVC".
        trust_domain:      Defaults to "peer" to distinguish from
                            centrally-authorized issuance domains.
        valid_days:        Used only to populate the NOT NULL expires_at
                            column for audit/query purposes -- does not
                            re-validate or extend the credential's actual
                            cryptographic validity, which lives inside the
                            JWT payload itself.

    Returns:
        { "vcId": str, "status": "logged" }
    """
    vc_id = f"urn:uuid:{uuid.uuid4()}"
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=valid_days)
    content_hash = hashlib.sha3_256(signed_vc_jwt.encode()).hexdigest()

    vc_result = {
        "vcId":            vc_id,
        "subjectDID":      subject_did,
        "issuerDID":       issuer_did,
        "credentialType":  credential_type,
        "issuedAt":        now,
        "expiresAt":       expires_at,
        "statusListUrl":   None,
        "statusListIndex": None,
        "contentHash":     content_hash,
        "signedVC":        signed_vc_jwt,
    }

    _persist_vc(vc_result, trust_domain)

    logger.info("Peer-issued VC logged: %s (subject=%s, issuer=%s)", vc_id, subject_did, issuer_did)

    return {"vcId": vc_id, "status": "logged"}


def get_credential_log(
    subject_did: str,
    credential_type: str = None,
    issuer_did: str = None,
    include_expired: bool = False,
) -> list:
    """
    Query the credential log for a subject.
    Supports optional filtering by credential type and issuer.
    Computes "expired" status dynamically.

    Args:
        subject_did:      Subject DID to query
        credential_type:  Optional filter for VC type
        issuer_did:       Optional filter for issuer DID
        include_expired:  If False, exclude expired credentials

    Returns:
        list of dicts with keys: vcId, credentialType, issuerDID, issuedAt, expiresAt, status, statusListIndex
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            query = "SELECT * FROM vc_credentials WHERE subject_did = %s"
            params = [subject_did]

            if credential_type:
                query += " AND credential_type = %s"
                params.append(credential_type)

            if issuer_did:
                query += " AND issuer_did = %s"
                params.append(issuer_did)

            cur.execute(query, params)
            rows = cur.fetchall()

        result = []
        now = datetime.now(timezone.utc)

        for row in rows:
            # Compute dynamic "expired" status
            expires_at = row["expires_at"]
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))

            status = row["status"]
            if status == "active" and expires_at < now:
                status = "expired"

            if status == "expired" and not include_expired:
                continue

            result.append({
                "vcId": row["id"],
                "credentialType": row["credential_type"],
                "issuerDID": row["issuer_did"],
                "issuedAt": row["issued_at"].isoformat() if hasattr(row["issued_at"], "isoformat") else str(row["issued_at"]),
                "expiresAt": row["expires_at"].isoformat() if hasattr(row["expires_at"], "isoformat") else str(row["expires_at"]),
                "status": status,
                "statusListIndex": row["status_list_index"],
            })

        return result
    finally:
        conn.close()