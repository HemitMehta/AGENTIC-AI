# Agent Wallet Service (SS7) — Secure Credential Container

Zero-Trust Agentic AI Layer 1 agent-facing identity wallet.

## Architecture

**6 HTTP Endpoints:**
- `POST /wallets/:did/init` — Wallet initialization
- `POST /wallets/:did/store` — Store encrypted credential
- `GET /wallets/:did/credentials` — Query stored credentials (metadata only)
- `POST /wallets/:did/present` — Present credentials as VP JWT
- `POST /wallets/:did/present-zkp` — Present with zero-knowledge proof
- `POST /reputation/issue` — Issue peer-signed reputation VC
- `DELETE /wallets/:did` — Soft-delete wallet

**Security Model:**
- Wallet encryption keys stored in Vault (Person A KMS), never on disk
- AES-256-GCM encryption for at-rest VC storage
- HKDF key derivation in-memory only; keys zeroed immediately after use
- Selective disclosure enforcement: only requested credential types included
- Peer-issued reputation VCs: signed by agent, logged by SS4 (no authority)

## Wallet Lifecycle

### Init: `POST /wallets/:did/init`

1. Check if wallet already exists (idempotent)
2. Generate new encryption key in KMS
3. Store only key ID in database (never the key itself)
4. Return success

```bash
curl -X POST http://localhost:8006/wallets/did:web:agent/init
```

### Store: `POST /wallets/:did/store`

Called by SS4 after issuing each credential.

1. Decode JWT, extract VC metadata
2. Derive AES key from KMS key material (in-memory)
3. Encrypt VC with AES-256-GCM
4. Store encrypted blob + IV in database
5. Zero derived key from memory
6. Return vc_id

```bash
curl -X POST http://localhost:8006/wallets/did:web:agent/store \
  -H "Content-Type: application/json" \
  -d '{"signed_vc": "ey..."}'
```

### Query: `GET /wallets/:did/credentials`

Return metadata only (no decryption).

Query params:
- `?type=RoleCredential` — Filter by credential type
- `?issuer=did:web:issuer` — Filter by issuer
- `?status=active` — Filter by status

```bash
curl "http://localhost:8006/wallets/did:web:agent/credentials?type=RoleCredential"
```

### Present: `POST /wallets/:did/present`

Build and sign a Verifiable Presentation.

1. Selective inclusion: verify all requested types are present
2. Decrypt only requested VCs (derive key, decrypt, zero key)
3. Build VP JSON
4. Sign via KMS
5. Return JWT

```bash
curl -X POST http://localhost:8006/wallets/did:web:agent/present \
  -H "Content-Type: application/json" \
  -d '{
    "required_types": ["RoleCredential"],
    "verifier_did": "did:web:verifier",
    "nonce": "nonce123"
  }'
```

### Present-ZKP: `POST /wallets/:did/present-zkp`

Generate zero-knowledge proof (BBS+ or Groth16).

**BBS+ path** (selective disclosure):
1. Fetch BBS+-signed VC
2. Decrypt
3. Call Node.js subprocess to generate derived proof

**zk-SNARK path** (compliance predicate):
1. Decrypt VC
2. Build private witness from VC claims
3. Call snarkjs to generate Groth16 proof

```bash
curl -X POST http://localhost:8006/wallets/did:web:agent/present-zkp \
  -H "Content-Type: application/json" \
  -d '{
    "required_type": "ComplianceCredential",
    "verifier_did": "did:web:verifier",
    "nonce": "nonce123",
    "predicate": {
      "proofType": "BbsBlsSignature2020",
      "disclosedAttributes": [0, 2, 4]
    }
  }'
```

### Reputation: `POST /reputation/issue`

Peer-issued reputation VC.

1. Verify both issuer and target DIDs are active
2. Build reputation VC JSON
3. Sign via KMS (agent's own key)
4. Log to SS4 (peer issuance, not authority)
5. Return signed JWT

```bash
curl -X POST http://localhost:8006/reputation/issue \
  -H "Content-Type: application/json" \
  -d '{
    "issuer_did": "did:web:issuer",
    "target_did": "did:web:target",
    "task_context": "collaborated on audit task",
    "claims": {"trustScore": 8.5, "reliability": "high"}
  }'
```

### Delete: `DELETE /wallets/:did`

Soft-delete wallet and revoke encryption key.

1. Verify controller signature
2. Set deleted_at timestamp
3. Revoke key in Vault (encrypted VCs become unreadable)
4. Return success

```bash
curl -X DELETE http://localhost:8006/wallets/did:web:agent \
  -H "Content-Type: application/json" \
  -d '{
    "controller_signature": "sig...",
    "reason": "agent compromise"
  }'
```

## Database Schema

**`wallets`:**
- agent_did (PK): Agent's DID
- kms_key_id: ID of encryption key in Vault
- created_at: Wallet creation timestamp
- deleted_at: Soft-delete timestamp (null = active)
- deletion_reason: Reason for deletion

**`wallet_credentials`:**
- id (PK): Credential ID
- agent_did (FK): Wallet owner
- vc_id (UNIQUE): Credential's own ID
- credential_type (array): ["VerifiableCredential", "RoleCredential"]
- issuer_did: Issuing authority
- issued_at: Issuance timestamp
- expires_at: Expiration (nullable)
- encrypted_vc (bytes): AES-256-GCM ciphertext
- iv (bytes): 12-byte nonce
- proof_type: "Ed25519Signature2020" or "BbsBlsSignature2020"
- bbs_binding (JSON): BBS+ metadata (non-null for BBS+ credentials)
- status: active | revoked | expired

Indices on: (agent_did, credential_type), (agent_did, issuer_did), (agent_did, issued_at DESC)

## Cryptography

### AES-256-GCM Encryption

Key derivation: PBKDF2(KMS_key_material, salt=agent_did_bytes, iterations=1, dklen=32)
Nonce: Random 12 bytes per encryption
Tag: Authentication tag included in ciphertext

**Critical**: Derived key exists only in function scope, zeroed immediately after use.

### VP JWT Signature

Header: `{ alg: "EdDSA", typ: "JWT" }`
Payload: VP JSON (canonical form)
Signature: Ed25519 from KMS (private key never leaves Vault)

### BBS+ Selective Disclosure

Generated via `@mattrglobal/bbs-signatures` Node library in subprocess.
Input: Encrypted VC, BBS+ public key, disclosed attribute indices, nonce
Output: Derived proof that reveals only selected attributes

### zk-SNARK Proofs

Generated via `snarkjs` Node library in subprocess.
Circuits compiled to `.wasm` and `.zkey` files.
Witness built from VC claims.
Public inputs determine what the proof asserts.

## Configuration

```bash
WALLET_SERVICE_PORT=8006
KMS_URL=http://localhost:8001
DID_REGISTRY_URL=http://localhost:8002
VC_ISSUANCE_URL=http://localhost:8004
DATABASE_URL=postgresql+asyncpg://...
CIRCUITS_BASE_PATH=./circuits
NODE_BINARY=node
BBS_SCRIPT_PATH=./bbs_derive_proof.js
SNARK_TIMEOUT_SECONDS=30
BBS_TIMEOUT_SECONDS=10
HKDF_ITERATIONS=1
```

## Security Notes

- **Key Derivation**: PBKDF2 with agent DID as salt ensures different keys per agent
- **In-Memory Zeroing**: `zero_key()` overwrites key bytes after use; called in finally blocks
- **No Key Persistence**: Wallet encryption keys live only in Vault, never on disk
- **Selective Inclusion**: Strict enforcement prevents credential leakage
- **Soft Delete**: Encrypted VCs preserved for audit; key revocation makes them unreadable
- **Peer Reputation**: Signed by agent, not authority; trust depends on agent's own credentials

## Integration with Other Services

| Service | Integration |
|---------|-------------|
| **SS4 (VC Issuance)** | SS4 calls `POST /wallets/:did/store` after issuance; calls `POST /reputation/issue` for peer VCs |
| **SS5 (VC Verification)** | SS5 verifies VPs from `POST /wallets/:did/present` and ZKPs from `POST /wallets/:did/present-zkp` |
| **SS6 (Status List)** | Used for revocation checking during VP verification |
| **KMS (Person A)** | Generates and manages wallet encryption keys; signs VPs and reputation VCs |
| **DID Registry (Person A)** | Resolves agent and controller DIDs for validation |

## Testing

```bash
# All tests
pytest wallet_service/tests/

# Specific test
pytest wallet_service/tests/test_wallet_lifecycle.py

# With coverage
pytest --cov=wallet_service wallet_service/tests/
```

## Docker

```bash
docker-compose up wallet_service
```

Depends on: kms, did_registry, vc_issuance, postgres, redis

## File Structure

```
wallet_service/
├── main.py                    # FastAPI app
├── config.py                  # Environment configuration
├── requirements.txt
├── bbs_derive_proof.js        # BBS+ subprocess helper
├── routers/                   # 6 HTTP routers
├── services/                  # 8 business logic services
├── clients/                   # 3 HTTP clients to upstream services
├── crypto/                    # Encryption, signing, key handling
├── db/                        # Database connection, migrations, queries
├── models/                    # Pydantic request/response models
├── circuits/                  # zk-SNARK circuit artifacts
│   └── compliance_predicate/
│       ├── circuit.wasm
│       ├── zkey
│       └── verification_key.json
└── tests/                     # Unit tests
```

---

*For details on Zero-Trust Agentic AI Layer 1 architecture, see the root README.*
