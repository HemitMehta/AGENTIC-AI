# Build Prompt — Person B, Sub-System 4: VC Issuance Service
## Layer 1 · Zero-Trust Identity Framework for Agentic AI

---

## 1. Your Role and Context

You are building **Sub-System 4: VC Issuance Service** for Person B of Layer 1.

Person A has already built three files that you will import and call directly.
They are included alongside this prompt:

| File | What it gives you |
|------|-------------------|
| `kms.py` | `sign_payload()`, `get_public_key()`, `compute_model_hash()`, `generate_key()` |
| `did.py` | `create_did()`, `resolve_did_at_time()`, `_verify_controller_signature()` |
| `root_trust.py` | `validate_issuer()`, `get_trust_anchor()`, `add_issuer()` |

You also have `test_integration.py` to understand the testing patterns already established.

You will produce **one file**: `vc_issuance.py`

You will also produce **one test file**: `test_ss4_vc_issuance.py`

---

## 2. Infrastructure Assumptions

- **Database**: CockroachDB (via psycopg2). Same connection pattern as `kms.py` and `did.py`.
  Read env vars: `CRDB_HOST`, `CRDB_PORT`, `CRDB_DB`, `CRDB_USER`, `CRDB_PASSWORD`, `CRDB_SSLMODE`.
  Use `RealDictCursor` for all queries. Use `with conn.cursor() as cur` pattern.
- **Vault**: HashiCorp Vault via the `vault_client` already in `kms.py`. Do not create another Vault client.
  Call `kms.sign_payload()` and `kms.get_public_key()` — never touch Vault directly.
- **Status List**: Sub-System 6 (`status_list.py`) does not exist yet.
  Your code must call `status_list.allocate_status_entry(vc_id, issuer_did)` which will return
  `{"statusListUrl": str, "bitIndex": int}`.
  Import it as `import status_list` and call it. When SS6 is built it will satisfy this interface.
  For the test file, mock this import.
- **Redis**: Not needed in SS4. SS6 owns Redis.
- **Kafka**: Not needed in SS4. SS6 owns Kafka.
- **Environment file**: Load `.env` from the same directory using python-dotenv, exactly as in `kms.py`.

---

## 3. The Six Credential Types — Schemas and Rules

Each VC type has its own schema, validity period, issuer authority requirements,
and revocation urgency. Implement a separate issuance function for each.

### 3.1 Role VC
**Purpose**: Attests organisational role.
**Issued by**: HR authority or platform management DID.
**Default validity**: 365 days.
**Required claims**:
```json
{
  "roleName":        "string  — e.g. FinancialRiskAnalystRole",
  "roleDescription": "string  — human-readable description",
  "organisationDID": "string  — DID of the employing organisation",
  "department":      "string  — optional",
  "reportingTo":     "string  — DID of supervising agent or human, optional"
}
```
**Revocation urgency**: Standard (bit flip within normal StatusList cache TTL).

### 3.2 Capability VC
**Purpose**: Attests technical certification.
**Issued by**: Technical governance DID.
**Default validity**: 180 days.
**Required claims**:
```json
{
  "capabilityName":    "string  — e.g. SalesDataAnalyticsCapability",
  "certifiedActions":  ["array of strings — specific actions certified"],
  "toolsDID":          ["array of DIDs — tools this agent is certified to use"],
  "modelVersionHash":  "string  — SHA3-256 of model weights this cert applies to",
  "certifyingBodyDID": "string  — DID of the technical governance body"
}
```
**Revocation urgency**: Standard.
**Special rule**: `modelVersionHash` in claims MUST match `modelHash` in the subject's
DID Document. If they differ, reject issuance with error:
`"Model hash mismatch: capability VC certified for different model version"`.

### 3.3 Compliance VC
**Purpose**: Attests regulatory certification.
**Issued by**: Audit authority DID.
**Default validity**: 365 days (SOX), 180 days (GDPR), 365 days (HIPAA), or as provided.
**Required claims**:
```json
{
  "complianceFramework": "string  — e.g. SOXComplianceCertified, GDPRDataProcessorApproved",
  "auditDate":           "string  — ISO 8601 date of last audit",
  "auditRef":            "string  — reference number / audit report ID",
  "auditBodyDID":        "string  — DID of auditing entity",
  "scope":               "string  — scope of compliance certification",
  "nextAuditDue":        "string  — ISO 8601 date, optional"
}
```
**Revocation urgency**: High — any compliance violation must propagate within seconds.
**Note**: An expired compliance VC is treated identically to a revoked one by the Verification
Service. Your job is just to set the right `expirationDate`.

### 3.4 Provenance VC
**Purpose**: Attests origin and lineage when an agent is spawned.
**Issued by**: Parent agent's DID OR platform management DID.
**Default validity**: Permanent (set `expiresAt` 99 years in future).
**Required claims**:
```json
{
  "parentDID":           "string  — DID of spawning agent",
  "spawnedAt":           "string  — ISO 8601 timestamp of spawn event",
  "spawnReason":         "string  — why this agent was created",
  "jobID":               "string  — job/workflow ID that triggered spawn, optional",
  "provenanceAttestation": "string — base64 signature from parent DID key, provided by DID Registry fork endpoint"
}
```
**Revocation urgency**: Low (lineage records are historical facts).
**Special rule**: `provenanceAttestation` is a signed payload produced by Person A's
`POST /dids/fork` endpoint. You receive it as part of the issuance request. Store it as-is
in the claims — do not re-verify it here (the Verification Service does that).

### 3.5 Reputation VC
**Purpose**: Peer-issued performance attestation after collaboration.
**Issued by**: Another agent's DID (NOT an authority DID).
**Default validity**: 365 days.
**Required claims**:
```json
{
  "reputationScore":    "number  — 0–100",
  "tasksCompleted":     "integer — number of tasks collaborated on",
  "violationCount":     "integer — policy violations observed, 0 or more",
  "collaborationJobIDs": ["array of job ID strings"],
  "assessmentSummary":  "string  — free-text performance summary",
  "peerDID":            "string  — DID of issuing peer agent"
}
```
**Revocation urgency**: Low.
**Special rule**: Reputation VCs are peer-issued. The `issuerDID` in this VC IS an agent DID,
not a governance DID. The trust anchor check is therefore DIFFERENT from other VC types:
instead of calling `root_trust.validate_issuer()`, you check that the issuing agent's own DID
Document is active (its `lifecycleStatus == "active"`). Add a `_validate_peer_issuer()`
internal function for this. Still call `root_trust.validate_issuer()` for logging purposes but
do NOT reject on its result for Reputation VCs.

### 3.6 JIT VC (Just-In-Time)
**Purpose**: Ultra-short-lived credential for a single specific tool invocation.
**Issued by**: Workflow engine DID.
**Default validity**: 15 minutes (configurable via env var `JIT_VC_MAX_MINUTES`, default 15,
maximum allowed 60). Reject requests with `validUntil` more than 60 minutes in the future.
**Required claims**:
```json
{
  "jobID":          "string  — workflow job identifier, REQUIRED",
  "toolDID":        "string  — DID of the specific tool being invoked, REQUIRED",
  "allowedAction":  "string  — the single action permitted, REQUIRED",
  "inputHandle":    "string  — input data handle/reference, REQUIRED",
  "outputHandle":   "string  — output data handle/reference, REQUIRED",
  "scopeNote":      "string  — human-readable description of this invocation, optional"
}
```
**Revocation urgency**: Extreme — these must be revocable in real time.
**Special rules**:
- All 5 required fields (`jobID`, `toolDID`, `allowedAction`, `inputHandle`, `outputHandle`)
  MUST be present and non-empty. Raise `ValueError` if any is missing.
- The `toolDID` MUST appear in the subject agent's DID Document `toolset` array.
  Resolve the subject's DID Document and verify this. If not found, reject with:
  `"toolDID not in subject agent's authorised toolset"`.
- JIT VCs must NEVER be issued with `valid_until` more than 60 minutes from now.

---

## 4. The Issuance Pipeline — Run for Every VC Type

Every call to any `issue_*()` function MUST execute these steps in this exact order.
Fail fast — raise an exception immediately on any step failure, do not proceed.

```
Step 1 — Authority check
    Call root_trust.validate_issuer(issuer_did, credential_type, trust_domain)
    If result["authorised"] is False → raise PermissionError(result["reason"])
    EXCEPTION: Reputation VCs use _validate_peer_issuer() instead (see §3.5)

Step 2 — Subject DID active check
    Call did.resolve_did_at_time(subject_did, datetime.now(utc).isoformat())
    This will raise ValueError if DID not found.
    Check did_document["lifecycleStatus"] == "active"
    If not → raise ValueError(f"Subject DID {subject_did} is not active: {status}")

Step 3 — Type-specific claim validation
    Call the appropriate _validate_claims_<type>() internal function.
    These perform the type-specific rules described in §3 above.
    Raise ValueError with a descriptive message on any failure.

Step 4 — Construct W3C VC JSON-LD
    Call _build_vc_document() — see §5 for exact structure.

Step 5 — Allocate StatusList2021 entry
    Call status_list.allocate_status_entry(vc_id, issuer_did)
    Returns {"statusListUrl": str, "bitIndex": int}
    Embed credentialStatus into the VC document:
    {
        "id":                   f"{statusListUrl}#{bitIndex}",
        "type":                 "StatusList2021Entry",
        "statusPurpose":        "revocation",
        "statusListIndex":      str(bitIndex),
        "statusListCredential": statusListUrl
    }

Step 6 — Sign the VC via KMS
    Serialize VC document to canonical JSON (json.dumps sorted keys, no whitespace).
    Call kms.sign_payload(key_id=issuer_key_id, payload=serialized_bytes)
    Embed the proof block into the VC document:
    {
        "type":               "Ed25519Signature2020",
        "created":            now_iso,
        "verificationMethod": f"{issuer_did}#{issuer_key_id}",
        "proofPurpose":       "assertionMethod",
        "proofValue":         signature["signature"]
    }

Step 7 — Persist to vc_log
    Write one row to the vc_credentials table (see §6).
    Commit the transaction.

Step 8 — Return
    Return the dict described in §7.
```

---

## 5. W3C VC Document Structure

`_build_vc_document()` must produce exactly this structure.
The `proof` and `credentialStatus` blocks are added AFTER this function returns,
in the pipeline steps above.

```python
def _build_vc_document(
    vc_id: str,
    issuer_did: str,
    subject_did: str,
    credential_type: str,   # e.g. "RoleVC"
    claims: dict,
    valid_from: datetime,
    valid_until: datetime,
) -> dict:
```

Returned dict must be:
```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/security/suites/ed25519-2020/v1",
    "https://w3id.org/vc-status-list-2021/v1"
  ],
  "id":   "<vc_id>",
  "type": ["VerifiableCredential", "<credential_type>"],
  "issuer": {
    "id": "<issuer_did>"
  },
  "issuanceDate":    "<valid_from ISO>",
  "expirationDate":  "<valid_until ISO>",
  "credentialSubject": {
    "id": "<subject_did>",
    "<all claims flattened here>"
  }
}
```

`vc_id` format: `"urn:uuid:" + str(uuid.uuid4())`

---

## 6. Database Schema — vc_credentials Table

Create a function `initialize_schema()` that creates this table if it doesn't exist.
Call it at module import time only if `AUTOCREATE_SCHEMA=true` in env (default false).
Otherwise expose it for manual calling.

```sql
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
```

`content_hash` is `hashlib.sha3_256(json.dumps(vc_document, sort_keys=True).encode()).hexdigest()`.
This must be computed BEFORE the proof block is added (sign the content, hash the content).

---

## 7. Function Signatures to Export

These are the exact names and signatures test code will import.
Do not rename them.

```python
# Main issuance functions — one per VC type
def issue_role_vc(
    subject_did: str,
    issuer_did: str,
    issuer_key_id: str,
    claims: dict,
    trust_domain: str = "enterprise",
    valid_until_iso: str = None,   # ISO string; default = now + 365 days
) -> dict: ...

def issue_capability_vc(
    subject_did: str,
    issuer_did: str,
    issuer_key_id: str,
    claims: dict,
    trust_domain: str = "enterprise",
    valid_until_iso: str = None,   # default = now + 180 days
) -> dict: ...

def issue_compliance_vc(
    subject_did: str,
    issuer_did: str,
    issuer_key_id: str,
    claims: dict,
    trust_domain: str = "enterprise",
    valid_until_iso: str = None,   # default = now + 365 days
) -> dict: ...

def issue_provenance_vc(
    subject_did: str,
    issuer_did: str,
    issuer_key_id: str,
    claims: dict,               # MUST include provenanceAttestation
    trust_domain: str = "enterprise",
) -> dict: ...

def issue_reputation_vc(
    subject_did: str,
    issuer_did: str,            # This is a peer agent DID, not an authority
    issuer_key_id: str,
    claims: dict,
    trust_domain: str = "enterprise",
    valid_until_iso: str = None,   # default = now + 365 days
) -> dict: ...

def issue_jit_vc(
    subject_did: str,
    issuer_did: str,
    issuer_key_id: str,
    claims: dict,               # MUST include all 5 required JIT fields
    trust_domain: str = "enterprise",
    valid_until_iso: str = None,   # default = now + 15 min; max = now + 60 min
) -> dict: ...

# Credential log query
def get_credential_log(
    subject_did: str,
    credential_type: str = None,   # optional filter
    issuer_did: str = None,        # optional filter
    include_expired: bool = False,
) -> list: ...

# DB helpers
def initialize_schema() -> None: ...
def get_db_connection(): ...           # same pattern as did.py
```

**Return value for all `issue_*` functions**:
```python
{
    "vcId":              str,    # urn:uuid:...
    "signedVC":          dict,   # full VC document with proof block
    "credentialType":    str,
    "subjectDID":        str,
    "issuerDID":         str,
    "issuedAt":          str,    # ISO
    "expiresAt":         str,    # ISO
    "statusListUrl":     str,
    "statusListIndex":   int,
    "contentHash":       str,    # sha3_256 hex
}
```

**Return value for `get_credential_log()`**:
```python
[
    {
        "vcId":            str,
        "credentialType":  str,
        "issuerDID":       str,
        "issuedAt":        str,
        "expiresAt":       str,
        "status":          str,   # "active" | "revoked" | "expired"
        "statusListIndex": int,
    },
    ...
]
```
Compute `"expired"` dynamically: if `expires_at < now` and `status == "active"`, return `"expired"`.

---

## 8. Internal Helper Functions

Implement all of these. They are not exported but must exist.

```python
def _build_vc_document(...) -> dict             # §5 above
def _validate_claims_role(claims: dict) -> None
def _validate_claims_capability(claims: dict, subject_did: str) -> None
def _validate_claims_compliance(claims: dict) -> None
def _validate_claims_provenance(claims: dict) -> None
def _validate_claims_reputation(claims: dict) -> None
def _validate_claims_jit(claims: dict, subject_did: str) -> None
def _validate_peer_issuer(issuer_did: str) -> None  # for reputation VCs
def _persist_vc(vc_result: dict, trust_domain: str) -> None
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
) -> dict
```

The `_run_issuance_pipeline()` function implements the 8 steps from §4.
Every `issue_*()` function MUST call `_run_issuance_pipeline()` and pass its
type-specific `claims_validator`. This avoids duplicating the pipeline logic 6 times.

---

## 9. Error Handling Rules

| Condition | Exception type | Message format |
|-----------|---------------|----------------|
| Issuer not authorised | `PermissionError` | From `root_trust` reason field |
| Subject DID not found | `ValueError` | `"Subject DID {did} not found"` |
| Subject DID not active | `ValueError` | `"Subject DID {did} is not active: {status}"` |
| Missing required claim | `ValueError` | `"Missing required claim: {field_name}"` |
| JIT validity > 60 min | `ValueError` | `"JIT VC validity exceeds maximum of 60 minutes"` |
| Tool not in toolset | `ValueError` | `"toolDID {tool_did} not in subject agent's authorised toolset"` |
| Model hash mismatch | `ValueError` | `"Model hash mismatch: capability VC certified for different model version"` |
| StatusList allocation failed | `RuntimeError` | `"StatusList allocation failed: {detail}"` |
| KMS signing failed | `RuntimeError` | `"KMS signing failed: {detail}"` |
| DB write failed | `RuntimeError` | `"VC log write failed: {detail}"` |

All exceptions must propagate up. No silent swallowing of errors.

---

## 10. Imports and Module-Level Setup

```python
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

import os, json, uuid, hashlib, logging
from datetime import datetime, timezone, timedelta
from contextlib import contextmanager

import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

import kms
import did as did_registry
import root_trust
import status_list   # Sub-System 6 — built separately; mock in tests

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
logger = logging.getLogger(__name__)
```

---

## 11. Test File Requirements — test_ss4_vc_issuance.py

Write comprehensive tests. Follow the exact patterns from `test_integration.py`
(session-scoped fixtures, clean_test_data autouse, pytest).

**Mock targets** (use `unittest.mock.patch` or `pytest-mock`):
- `vc_issuance.kms.sign_payload` → return `{"signature": "mocksig==", "algorithm": "Ed25519", "keyId": "test-key"}`
- `vc_issuance.kms.get_public_key` → return `{"keyId": "test-key", "publicKey": "mockpubkey==", "status": "active"}`
- `vc_issuance.did_registry.resolve_did_at_time` → return a valid mock DID Document (active)
- `vc_issuance.root_trust.validate_issuer` → return `{"authorised": True, "reason": "Issuer is authorized.", "validUntil": None}`
- `vc_issuance.status_list.allocate_status_entry` → return `{"statusListUrl": "https://status.example.com/list/1", "bitIndex": 42}`

**Test classes and cases to write**:

```
class TestRoleVCIssuance:
    test_issue_role_vc_success
    test_issue_role_vc_missing_required_claim
    test_issue_role_vc_unauthorised_issuer
    test_issue_role_vc_inactive_subject
    test_issue_role_vc_return_structure

class TestCapabilityVCIssuance:
    test_issue_capability_vc_success
    test_issue_capability_vc_model_hash_mismatch
    test_issue_capability_vc_missing_claim

class TestComplianceVCIssuance:
    test_issue_compliance_vc_success
    test_issue_compliance_vc_missing_audit_date

class TestProvenanceVCIssuance:
    test_issue_provenance_vc_success
    test_issue_provenance_vc_missing_attestation

class TestReputationVCIssuance:
    test_issue_reputation_vc_success
    test_issue_reputation_vc_peer_issuer_not_authority_check_bypassed
    test_issue_reputation_vc_invalid_score_range

class TestJITVCIssuance:
    test_issue_jit_vc_success
    test_issue_jit_vc_exceeds_60_min
    test_issue_jit_vc_missing_job_id
    test_issue_jit_vc_tool_not_in_toolset
    test_issue_jit_vc_all_required_fields_present

class TestVCDocumentStructure:
    test_vc_has_context
    test_vc_has_proof_block
    test_vc_has_credential_status
    test_vc_content_hash_matches

class TestCredentialLog:
    test_get_credential_log_returns_issued_vcs
    test_get_credential_log_filter_by_type
    test_get_credential_log_marks_expired
    test_get_credential_log_empty_for_unknown_did

class TestIssuancePipeline:
    test_pipeline_step_order_authority_before_did
    test_pipeline_rejects_on_step1_before_reaching_step2
```

For tests that hit the real DB (`pg` fixture), the DB must have `vc_credentials` table.
Create it in the `pg` fixture using `vc_issuance.initialize_schema()` after getting the connection.

---

## 12. Coding Style and Conventions

- Match the style of `kms.py` and `did.py` exactly:
  - Section headers as `# ── Section Name ─────` comments
  - Docstrings on every public function (Args / Returns)
  - Type hints on all function parameters and return types
  - `logger.info()` on success, `logger.warning()` on soft failures
- No Flask/FastAPI/HTTP layer. This is a pure Python library module.
  The HTTP layer (REST endpoints) will be added later as a separate file.
- No async. All functions are synchronous.
- `get_db_connection()` returns a raw psycopg2 connection (same as `did.py`).
  Use `with conn.cursor() as cur` and explicit `conn.commit()`.
- All timestamps are `datetime.now(timezone.utc).isoformat()` — timezone-aware, UTC.

---

## 13. File Naming and What to Produce

Produce exactly these two files:
```
vc_issuance.py
test_ss4_vc_issuance.py
```

Do not produce any other files. The schema SQL is for reference;
call `initialize_schema()` from within `vc_issuance.py` to create the table programmatically.
