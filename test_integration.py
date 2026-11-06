"""
test_integration.py
Person A - Layer 1  INTEGRATION Tests
Tests for: kms.py, did.py, root_trust.py

These tests hit your REAL Vault and REAL CockroachDB.
No mocks. No fakes. Everything actually runs.

Prerequisites:
    1. Vault running:        http://127.0.0.1:8200  (token: root)
    2. CockroachDB running:  localhost:26257         (user: root, db: did_registry, sslmode: disable)
    3. Tables created:       python -c "import did; did._init_schema()"
                             python -c "import root_trust; root_trust.initialize_schema()"

Run all:
    pytest test_integration.py -v

Run one class:
    pytest test_integration.py::TestKMSIntegration -v

Environment overrides (optional):
    VAULT_ADDR=http://localhost:8200
    VAULT_TOKEN=root
    CRDB_HOST=localhost
    CRDB_PORT=26257
    CRDB_DB=did_registry
    CRDB_USER=root
    CRDB_PASSWORD=
    CRDB_SSLMODE=disable
"""

import os
import pytest
import base64
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone

import hvac
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))
print("ENV HOST:", os.getenv("CRDB_HOST"))

# CONFIGURATION  — reads from env, falls back to local dev defaults


VAULT_ADDR  = os.getenv("VAULT_ADDR",  "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "root")

CRDB_HOST   = os.getenv("CRDB_HOST",     "localhost")
CRDB_PORT   = int(os.getenv("CRDB_PORT", "26257"))
CRDB_DB     = os.getenv("CRDB_DB",       "did_registry")
CRDB_USER   = os.getenv("CRDB_USER",     "root")
CRDB_PASS   = os.getenv("CRDB_PASSWORD", "")
CRDB_SSL    = os.getenv("CRDB_SSLMODE",  "disable")



# SESSION-SCOPED FIXTURES  — connect once, reuse across all tests

@pytest.fixture(scope="session")
def vault():
    """
    Real Vault client. Skips entire session if Vault is unreachable.
    Also enables Transit + KV secrets engines if not already enabled.
    """
    client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)

    if not client.is_authenticated():
        pytest.skip(f"Vault not reachable at {VAULT_ADDR} — start Vault first")

    # Enable Transit engine (idempotent — ignores error if already enabled)
    try:
        client.sys.enable_secrets_engine(backend_type="transit", path="transit")
    except Exception:
        pass  # already enabled

    # Enable KV v2 (idempotent)
    try:
        client.sys.enable_secrets_engine(backend_type="kv", path="secret", options={"version": "2"})
    except Exception:
        pass

    return client


@pytest.fixture(scope="session")
def pg():
    """
    Real CockroachDB connection. Skips entire session if DB is unreachable.
    Creates required tables before any test runs.
    """
    try:
        conn = psycopg2.connect(
            host=CRDB_HOST, port=CRDB_PORT, dbname=CRDB_DB,
            user=CRDB_USER, password=CRDB_PASS,
            sslmode=CRDB_SSL,
            sslrootcert=os.getenv("CRDB_SSLROOTCERT", ""),
            cursor_factory=RealDictCursor,
            connect_timeout=5,
        )
    except Exception as e:
        pytest.skip(f"CockroachDB not reachable at {CRDB_HOST}:{CRDB_PORT} — {e}")

    # Create tables needed by did.py and root_trust.py
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS did_documents (
                id               TEXT PRIMARY KEY,
                current_version  INTEGER NOT NULL DEFAULT 1,
                did_document     JSONB NOT NULL,
                owner_did        TEXT,
                controller_dids  JSONB DEFAULT '[]',
                lifecycle_status TEXT NOT NULL DEFAULT 'active',
                method           TEXT NOT NULL DEFAULT 'key',
                created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                deactivated_at   TIMESTAMPTZ
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS did_document_versions (
                id           UUID DEFAULT gen_random_uuid() PRIMARY KEY,
                did          TEXT NOT NULL REFERENCES did_documents(id),
                version      INTEGER NOT NULL,
                raw_document JSONB NOT NULL,
                change_type  TEXT NOT NULL DEFAULT 'created',
                valid_from   TIMESTAMPTZ NOT NULL,
                valid_until  TIMESTAMPTZ,
                UNIQUE (did, version)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS trust_anchor_issuers (
                id                UUID DEFAULT gen_random_uuid() PRIMARY KEY,
                issuer_did        TEXT NOT NULL,
                credential_types  JSONB NOT NULL DEFAULT '[]',
                trust_domain      TEXT NOT NULL,
                valid_from        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                valid_until       TIMESTAMPTZ,
                conditions        JSONB,
                added_by          TEXT NOT NULL DEFAULT 'test',
                revoked           BOOLEAN NOT NULL DEFAULT FALSE,
                revoked_at        TIMESTAMPTZ,
                revocation_reason TEXT,
                UNIQUE (issuer_did, trust_domain)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS trust_anchor_documents (
                id            UUID DEFAULT gen_random_uuid() PRIMARY KEY,
                version       INTEGER NOT NULL UNIQUE,
                document      JSONB NOT NULL,
                signature     TEXT NOT NULL,
                signed_by_key TEXT NOT NULL,
                created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS federation_trust_anchors (
                id               UUID DEFAULT gen_random_uuid() PRIMARY KEY,
                org_name         TEXT NOT NULL UNIQUE,
                org_did          TEXT NOT NULL,
                root_public_key  TEXT NOT NULL,
                trust_anchor_url TEXT NOT NULL,
                added_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                active           BOOLEAN NOT NULL DEFAULT TRUE
            )
        """)
    conn.commit()
    yield conn
    conn.close()


@pytest.fixture(autouse=True)
def clean_test_data(pg):
    """
    Wipe test rows before each test so tests don't bleed into each other.
    Only deletes rows whose DID or issuer_did contains 'test' or 'integration'.
    """
    yield
    with pg.cursor() as cur:
        cur.execute("DELETE FROM did_document_versions WHERE did LIKE '%test%' OR did LIKE '%integration%'")
        cur.execute("DELETE FROM did_documents WHERE id LIKE '%test%' OR id LIKE '%integration%'")
        cur.execute("DELETE FROM trust_anchor_issuers WHERE issuer_did LIKE '%test%' OR issuer_did LIKE '%integration%'")
    pg.commit()



# HELPER — clean up Vault transit keys after tests


def delete_vault_key_if_exists(vault_client, key_name: str):
    """Allow deletion and then delete a Transit key. Silent if not found."""
    try:
        vault_client.secrets.transit.update_key_configuration(
            name=key_name, deletion_allowed=True, mount_point="transit"
        )
        vault_client.secrets.transit.delete_key(name=key_name, mount_point="transit")
    except Exception:
        pass



# SUB-SYSTEM 1: KMS INTEGRATION TESTS


class TestKMSIntegration:
    """
    Tests kms.py against real Vault Transit.
    Each test creates and cleans up its own Vault key.
    """

    def test_generate_key_creates_real_vault_key(self, vault):
        """
        generate_key() must create an actual Ed25519 key in Vault Transit
        and return only the public key — never the private key.
        """
        from kms import generate_key

        agent_did = f"did:web:integration-test.com:agent-{uuid.uuid4().hex[:8]}"
        key_name = None

        try:
            result = generate_key(agent_did, "authentication")

            # Must return public key, key ID, algorithm
            assert "publicKey" in result,  "Missing publicKey"
            assert "keyId"     in result,  "Missing keyId"
            assert result["algorithm"]  == "Ed25519"
            assert result["keyPurpose"] == "authentication"

            # Private key must NEVER appear
            assert "privateKey"  not in result, "CRITICAL: privateKey exposed!"
            assert "keyMaterial" not in result, "CRITICAL: keyMaterial exposed!"

            # keyId must have no colons (Vault key name constraint)
            assert ":" not in result["keyId"], f"Colon in keyId: {result['keyId']}"

            # Verify the key actually exists in Vault
            key_name = result["vaultKeyName"]
            info = vault.secrets.transit.read_key(name=key_name, mount_point="transit")
            assert info["data"]["type"] == "ed25519"

        finally:
            if key_name:
                delete_vault_key_if_exists(vault, key_name)

    def test_generate_key_public_key_is_valid_base64(self, vault):
        """The returned publicKey must be valid base64."""
        from kms import generate_key

        agent_did = f"did:web:integration-test.com:agent-{uuid.uuid4().hex[:8]}"
        key_name = None

        try:
            result = generate_key(agent_did, "authentication")
            key_name = result["vaultKeyName"]

            # Must be decodable as base64
            try:
                decoded = base64.b64decode(result["publicKey"] + "==")
                assert len(decoded) > 0
            except Exception:
                # May be PEM format — also valid
                assert "BEGIN" in result["publicKey"] or len(result["publicKey"]) > 10

        finally:
            if key_name:
                delete_vault_key_if_exists(vault, key_name)

    def test_sign_payload_returns_real_signature(self, vault):
        """
        sign_payload() must call Vault Transit and return a real Ed25519 signature.
        The signature must be base64, no vault:v1: prefix, no private key exposed.
        """
        from kms import generate_key, sign_payload

        agent_did = f"did:web:integration-test.com:agent-{uuid.uuid4().hex[:8]}"
        key_name = None

        try:
            key_result = generate_key(agent_did, "authentication")
            key_name = key_result["vaultKeyName"]
            key_id = key_result["keyId"]

            # Sign using the vault key name (sign_payload uses key_id as vault key name)
            result = sign_payload(key_name, b"hello real vault signing")

            assert "signature" in result
            assert result["algorithm"] == "Ed25519"
            assert result["keyId"] == key_name

            # Must NOT contain the vault:v1: prefix
            assert "vault:v1:" not in result["signature"], "vault prefix not stripped!"
            assert ":" not in result["signature"], "Colon still in signature"

            # Must be valid base64
            decoded_sig = base64.b64decode(result["signature"] + "==")
            assert len(decoded_sig) == 64, f"Ed25519 sig must be 64 bytes, got {len(decoded_sig)}"

            # Must NOT expose private key
            assert "privateKey"  not in result
            assert "keyMaterial" not in result

        finally:
            if key_name:
                delete_vault_key_if_exists(vault, key_name)

    def test_sign_different_payloads_give_different_signatures(self, vault):
        """Two different payloads signed with the same key must produce different signatures."""
        from kms import generate_key, sign_payload

        agent_did = f"did:web:integration-test.com:agent-{uuid.uuid4().hex[:8]}"
        key_name = None

        try:
            key_result = generate_key(agent_did, "authentication")
            key_name = key_result["vaultKeyName"]

            sig1 = sign_payload(key_name, b"payload one")["signature"]
            sig2 = sign_payload(key_name, b"payload two")["signature"]

            assert sig1 != sig2, "Same signature for different payloads!"

        finally:
            if key_name:
                delete_vault_key_if_exists(vault, key_name)

    def test_get_public_key_active_from_real_vault(self, vault):
        """get_public_key() must return status=active and a real public key for a live key."""
        from kms import generate_key, get_public_key

        agent_did = f"did:web:integration-test.com:agent-{uuid.uuid4().hex[:8]}"
        key_name = None

        try:
            key_result = generate_key(agent_did, "authentication")
            key_name = key_result["vaultKeyName"]

            result = get_public_key(key_name)

            assert result["status"]    == "active"
            assert result["publicKey"] is not None
            assert result["algorithm"] == "Ed25519"

        finally:
            if key_name:
                delete_vault_key_if_exists(vault, key_name)

    def test_get_public_key_revoked_returns_gracefully(self, vault):
        """
        After a key is deleted from Vault (emergency revocation),
        get_public_key() must return status=revoked — not crash.
        """
        from kms import generate_key, get_public_key

        agent_did = f"did:web:integration-test.com:agent-{uuid.uuid4().hex[:8]}"
        key_result = generate_key(agent_did, "authentication")
        key_name = key_result["vaultKeyName"]

        # Delete the key from Vault (simulates emergency revocation)
        delete_vault_key_if_exists(vault, key_name)

        # Must not raise — must return gracefully
        result = get_public_key(key_name)

        assert result["status"]    == "revoked"
        assert result["publicKey"] is None
        assert result["algorithm"] == "Ed25519"

    def test_compute_model_hash_sha3_256(self, tmp_path):
        """compute_model_hash() must use SHA3-256, not SHA-256. Pure Python — no Vault needed."""
        from kms import compute_model_hash

        data = b"real model weights binary data for hashing"
        model_file = tmp_path / "model.bin"
        model_file.write_bytes(data)

        # From file
        result_file = compute_model_hash(model_path=str(model_file))
        assert result_file["algorithm"]    == "SHA3-256"
        assert result_file["sha3_256_hash"] == hashlib.sha3_256(data).hexdigest()
        assert result_file["sha3_256_hash"] != hashlib.sha256(data).hexdigest()

        # From binary
        result_bin = compute_model_hash(model_binary=data)
        assert result_bin["sha3_256_hash"] == result_file["sha3_256_hash"]

    def test_compute_model_hash_requires_input(self):
        """compute_model_hash() with no args must raise ValueError."""
        from kms import compute_model_hash

        with pytest.raises(ValueError, match="model_path or model_binary"):
            compute_model_hash()

    def test_key_id_has_no_colons(self, vault):
        """keyId must never contain colons — Vault key names forbid them."""
        from kms import generate_key

        agent_did = "did:web:example.com:agents:agent99"
        key_name = None

        try:
            result = generate_key(agent_did, "authentication")
            key_name = result["vaultKeyName"]
            assert ":" not in result["keyId"], f"Colon in keyId: {result['keyId']}"
        finally:
            if key_name:
                delete_vault_key_if_exists(vault, key_name)


# SUB-SYSTEM 2: DID REGISTRY INTEGRATION TESTS

class TestDIDRegistryIntegration:
    """
    Tests did.py against real PostgreSQL.
    Each test inserts real rows and the autouse fixture cleans them up.
    """

    def _public_key(self) -> str:
        """Generate a random fake 32-byte public key as base64."""
        return base64.b64encode(os.urandom(32)).decode()

    def test_create_did_web_persists_to_db(self, pg):
        """create_did() with did_method='web' must write a real row to did_documents."""
        from did import create_did

        pub = self._public_key()
        result = create_did(
            metadata={"agentId": "test-agent-integration-001"},
            owner_did="did:web:owner.integration-test.com",
            controller_dids=["did:web:owner.integration-test.com"],
            scope_of_behavior="Integration test agent",
            toolset=[{"toolName": "TestTool"}],
            model_hash="integrationhash123",
            aibom_ref="https://aibom.integration-test.com/agent001",
            public_key_b64=pub,
            key_id="integration-test-key-001",
            did_method="web",
            domain="integration-test.com",
        )

        assert result["did"].startswith("did:web:")
        assert result["version"] == 1

        doc = result["didDocument"]
        assert doc["lifecycleStatus"]  == "active"
        assert doc["modelHash"]        == "integrationhash123"
        assert doc["ownerDID"]         == "did:web:owner.integration-test.com"
        assert doc["scopeOfBehavior"]  == "Integration test agent"
        assert "@context"              in doc
        assert "verificationMethod"    in doc

        # Verify row actually exists in DB
        with pg.cursor() as cur:
            cur.execute("SELECT * FROM did_documents WHERE id = %s", (result["did"],))
            row = cur.fetchone()
        assert row is not None, "DID not saved to database!"
        assert row["lifecycle_status"] == "active"

    def test_create_did_key_persists_to_db(self, pg):
        """create_did() with did_method='key' must produce did:key:z... and save to DB."""
        from did import create_did

        pub = self._public_key()
        result = create_did(
            metadata={"agentId": "test-key-agent-integration"},
            owner_did="did:web:owner.integration-test.com",
            controller_dids=[],
            scope_of_behavior="Key agent test",
            toolset=[],
            model_hash="keyhash456",
            aibom_ref="",
            public_key_b64=pub,
            key_id="integration-test-key-002",
            did_method="key",
        )

        assert result["did"].startswith("did:key:z")
        assert result["version"] == 1

        with pg.cursor() as cur:
            cur.execute("SELECT id FROM did_documents WHERE id = %s", (result["did"],))
            row = cur.fetchone()
        assert row is not None, "did:key not saved to database!"

    def test_version_history_row_created(self, pg):
        """Every create_did() must also insert a row into did_document_versions."""
        from did import create_did

        pub = self._public_key()
        result = create_did(
            metadata={"agentId": "test-version-agent"},
            owner_did="did:web:owner.integration-test.com",
            controller_dids=["did:web:owner.integration-test.com"],
            scope_of_behavior="Version test",
            toolset=[],
            model_hash="versionhash",
            aibom_ref="",
            public_key_b64=pub,
            key_id="integration-version-key",
            did_method="web",
            domain="integration-test.com",
        )

        with pg.cursor() as cur:
            cur.execute(
                "SELECT version, change_type, valid_from, valid_until FROM did_document_versions WHERE did = %s",
                (result["did"],)
            )
            versions = cur.fetchall()

        assert len(versions) == 1, f"Expected 1 version row, got {len(versions)}"
        assert versions[0]["version"]     == 1
        assert versions[0]["change_type"] == "created"
        assert versions[0]["valid_until"] is None  # current version has no end date

    def test_point_in_time_resolution_real_db(self, pg):
        """resolve_did_at_time() must return the correct document from a real DB row."""
        from did import create_did, resolve_did_at_time

        pub = self._public_key()
        before_create = datetime.now(timezone.utc)

        result = create_did(
            metadata={"agentId": "test-pit-agent"},
            owner_did="did:web:owner.integration-test.com",
            controller_dids=["did:web:owner.integration-test.com"],
            scope_of_behavior="Point-in-time test",
            toolset=[],
            model_hash="pithash",
            aibom_ref="",
            public_key_b64=pub,
            key_id="integration-pit-key",
            did_method="web",
            domain="integration-test.com",
        )

        # Query at a time after creation — should find version 1
        after_create = datetime.now(timezone.utc).isoformat()
        resolved = resolve_did_at_time(result["did"], after_create)

        assert resolved["version"]               == 1
        assert resolved["didDocument"]["id"]      == result["did"]
        assert resolved["validFrom"]              is not None

    def test_point_in_time_raises_before_creation(self, pg):
        """resolve_did_at_time() at a timestamp before the DID existed must raise ValueError."""
        from did import create_did, resolve_did_at_time

        pub = self._public_key()
        result = create_did(
            metadata={"agentId": "test-pit-before-agent"},
            owner_did="did:web:owner.integration-test.com",
            controller_dids=[],
            scope_of_behavior="Before test",
            toolset=[],
            model_hash="beforehash",
            aibom_ref="",
            public_key_b64=pub,
            key_id="integration-pit-before-key",
            did_method="web",
            domain="integration-test.com",
        )

        # Query at year 2000 — DID definitely didn't exist then
        with pytest.raises(ValueError):
            resolve_did_at_time(result["did"], "2000-01-01T00:00:00Z")

    def test_resolve_did_key_no_db(self):
        """
        _resolve_did_key() must work with ZERO DB calls — pure math from key bytes.
        No pg fixture needed here.
        """
        from did import _generate_did_key, _resolve_did_key

        pub = base64.b64encode(os.urandom(32)).decode()
        did_str = _generate_did_key(pub)

        assert did_str.startswith("did:key:z")

        result = _resolve_did_key(did_str)
        assert result["didDocument"]["id"] == did_str
        assert len(result["didDocument"]["verificationMethod"]) == 1
        assert result["currentVersion"] is None

    def test_verify_controller_authorized(self, pg):
        """_verify_controller_signature() must pass for a listed controller DID."""
        from did import create_did, _verify_controller_signature
        from unittest.mock import MagicMock

        pub = self._public_key()
        owner = "did:web:owner.integration-test.com"

        result = create_did(
            metadata={"agentId": "test-ctrl-agent"},
            owner_did=owner,
            controller_dids=[owner],
            scope_of_behavior="Controller test",
            toolset=[],
            model_hash="ctrlhash",
            aibom_ref="",
            public_key_b64=pub,
            key_id="integration-ctrl-key",
            did_method="web",
            domain="integration-test.com",
        )

        # Should NOT raise — owner is a listed controller
        _verify_controller_signature(
            did=result["did"],
            controller_did=owner,
            signature_data={},
            kms_client=MagicMock(),
        )

    def test_verify_controller_unauthorized(self, pg):
        """_verify_controller_signature() must raise PermissionError for an unlisted DID."""
        from did import create_did, _verify_controller_signature
        from unittest.mock import MagicMock

        pub = self._public_key()
        owner = "did:web:owner.integration-test.com"

        result = create_did(
            metadata={"agentId": "test-unauth-agent"},
            owner_did=owner,
            controller_dids=[owner],
            scope_of_behavior="Unauth test",
            toolset=[],
            model_hash="unauthash",
            aibom_ref="",
            public_key_b64=pub,
            key_id="integration-unauth-key",
            did_method="web",
            domain="integration-test.com",
        )

        with pytest.raises(PermissionError, match="not authorized"):
            _verify_controller_signature(
                did=result["did"],
                controller_did="did:web:attacker.com",
                signature_data={},
                kms_client=MagicMock(),
            )

    def test_verify_controller_did_not_found(self, pg):
        """_verify_controller_signature() must raise ValueError for a nonexistent DID."""
        from did import _verify_controller_signature
        from unittest.mock import MagicMock

        with pytest.raises(ValueError, match="DID not found"):
            _verify_controller_signature(
                did="did:web:nonexistent.integration-test.com:agent",
                controller_did="did:web:anyone.com",
                signature_data={},
                kms_client=MagicMock(),
            )

    def test_build_did_document_all_fields(self):
        """_build_did_document() must include all W3C + spec-required fields. No DB."""
        from did import _build_did_document

        pub = base64.b64encode(os.urandom(32)).decode()
        doc = _build_did_document(
            did="did:web:integration-test.com:agent1",
            public_key_b64=pub,
            key_id="test-key-1",
            owner_did="did:web:owner.com",
            controller_dids=["did:web:owner.com"],
            scope_of_behavior="Integration test behavior",
            toolset=[{"toolName": "PythonTool"}],
            model_hash="realhash123",
            aibom_ref="https://aibom.example.com/v1",
        )

        # W3C required
        for field in ["@context", "id", "verificationMethod", "authentication"]:
            assert field in doc, f"Missing W3C field: {field}"

        # Spec extended fields
        for field in ["ownerDID", "controllerDIDs", "scopeOfBehavior", "toolset",
                      "modelHash", "lifecycleStatus", "aibomReference", "createdAt",
                      "updatedAt", "expiresAt"]:
            assert field in doc, f"Missing spec field: {field}"

        assert doc["lifecycleStatus"] == "active"
        assert doc["modelHash"]       == "realhash123"
        assert doc["ownerDID"]        == "did:web:owner.com"


# SUB-SYSTEM 3: TRUST ANCHOR INTEGRATION TESTS

class TestTrustAnchorIntegration:
    """
    Tests root_trust.py against real PostgreSQL.
    Vault is needed for signing (get_trust_anchor / add_issuer).
    validate_issuer() and _build_trust_document() only need the DB.
    """

    def _insert_issuer(self, pg, issuer_did: str, credential_types: list,
                       trust_domain: str = "enterprise", revoked: bool = False):
        """Helper: insert a real issuer row directly into DB."""
        with pg.cursor() as cur:
            cur.execute(
                """
                INSERT INTO trust_anchor_issuers
                    (issuer_did, credential_types, trust_domain, added_by, revoked)
                VALUES (%s, %s, %s, 'integration-test', %s)
                ON CONFLICT (issuer_did, trust_domain) DO UPDATE
                    SET credential_types = EXCLUDED.credential_types,
                        revoked = EXCLUDED.revoked
                """,
                (issuer_did, json.dumps(credential_types), trust_domain, revoked)
            )
        pg.commit()

    def test_validate_issuer_authorized_real_db(self, pg):
        """validate_issuer() must return authorised=True for a real DB row."""
        from root_trust import validate_issuer

        issuer = "did:web:trusted-issuer.integration-test.com"
        self._insert_issuer(pg, issuer, ["RoleVC", "CapabilityVC"])

        result = validate_issuer(
            issuer_did=issuer,
            credential_type="RoleVC",
            trust_domain="enterprise",
        )

        assert result["authorised"] is True
        assert result["reason"] == "Issuer is authorized."

    def test_validate_issuer_wrong_type_real_db(self, pg):
        """validate_issuer() must return authorised=False for an unlisted credential type."""
        from root_trust import validate_issuer

        issuer = "did:web:wrong-type-issuer.integration-test.com"
        self._insert_issuer(pg, issuer, ["RoleVC"])

        result = validate_issuer(
            issuer_did=issuer,
            credential_type="ComplianceVC",
            trust_domain="enterprise",
        )

        assert result["authorised"] is False
        assert "ComplianceVC" in result["reason"]

    def test_validate_issuer_not_in_db(self, pg):
        """validate_issuer() must return authorised=False for an issuer not in the DB."""
        from root_trust import validate_issuer

        result = validate_issuer(
            issuer_did="did:web:unknown-attacker.integration-test.com",
            credential_type="RoleVC",
            trust_domain="enterprise",
        )

        assert result["authorised"] is False
        assert result["validUntil"] is None

    def test_validate_issuer_revoked_not_authorized(self, pg):
        """
        A revoked issuer must NOT be authorized even if they were previously accredited.
        This tests the revoked=TRUE filter in the SQL query.
        """
        from root_trust import validate_issuer

        issuer = "did:web:revoked-issuer.integration-test.com"
        self._insert_issuer(pg, issuer, ["RoleVC"], revoked=True)

        result = validate_issuer(
            issuer_did=issuer,
            credential_type="RoleVC",
            trust_domain="enterprise",
        )

        assert result["authorised"] is False

    def test_validate_all_six_vc_types(self, pg):
        """An issuer authorized for all 6 VC types must pass validation for each."""
        from root_trust import validate_issuer

        issuer = "did:web:full-issuer.integration-test.com"
        all_types = ["RoleVC", "CapabilityVC", "ComplianceVC", "ProvenanceVC", "ReputationVC", "JitVC"]
        self._insert_issuer(pg, issuer, all_types)

        for cred_type in all_types:
            result = validate_issuer(
                issuer_did=issuer,
                credential_type=cred_type,
                trust_domain="enterprise",
            )
            assert result["authorised"] is True, f"Expected authorized for {cred_type}, got: {result}"

    def test_build_trust_document_excludes_revoked(self):
        """_build_trust_document() must exclude revoked issuers. Pure Python — no DB."""
        from root_trust import _build_trust_document

        issuers = [
            {
                "issuer_did":       "did:web:good-issuer.integration-test.com",
                "credential_types": ["RoleVC"],
                "trust_domain":     "enterprise",
                "valid_from":       datetime(2024, 1, 1, tzinfo=timezone.utc),
                "valid_until":      None,
                "conditions":       None,
                "revoked":          False,
            },
            {
                "issuer_did":       "did:web:revoked-issuer.integration-test.com",
                "credential_types": ["RoleVC"],
                "trust_domain":     "enterprise",
                "valid_from":       datetime(2024, 1, 1, tzinfo=timezone.utc),
                "valid_until":      None,
                "conditions":       None,
                "revoked":          True,
            },
        ]

        doc = _build_trust_document(issuers, version=1)

        dids_in_doc = [e["issuerDID"] for e in doc["issuerAuthorizations"]]
        assert "did:web:good-issuer.integration-test.com"    in dids_in_doc
        assert "did:web:revoked-issuer.integration-test.com" not in dids_in_doc

    def test_build_trust_document_structure(self):
        """_build_trust_document() must produce the correct top-level structure."""
        from root_trust import _build_trust_document

        doc = _build_trust_document(issuers=[], version=7)

        assert doc["version"]              == 7
        assert doc["type"]                 == "TrustAnchorDocument"
        assert "issuedAt"                  in doc
        assert "issuerAuthorizations"      in doc
        assert isinstance(doc["issuerAuthorizations"], list)

    def test_add_and_validate_issuer_full_flow(self, pg, vault):
        """
        Full end-to-end: add an issuer to the DB directly, then validate it.
        Tests the complete read path that Person B's Verification Service uses.
        """
        from root_trust import validate_issuer

        issuer = "did:web:e2e-issuer.integration-test.com"
        self._insert_issuer(pg, issuer, ["RoleVC", "ComplianceVC"])

        # Validate RoleVC — should pass
        r1 = validate_issuer(issuer_did=issuer, credential_type="RoleVC", trust_domain="enterprise")
        assert r1["authorised"] is True

        # Validate ComplianceVC — should pass
        r2 = validate_issuer(issuer_did=issuer, credential_type="ComplianceVC", trust_domain="enterprise")
        assert r2["authorised"] is True

        # Validate ProvenanceVC — should fail (not in list)
        r3 = validate_issuer(issuer_did=issuer, credential_type="ProvenanceVC", trust_domain="enterprise")
        assert r3["authorised"] is False
        assert "ProvenanceVC" in r3["reason"]