# VC Verification Service (Sub-System 5)

Verifies Verifiable Credentials and Verifiable Presentations in the Zero-Trust Agentic AI Layer 1 identity framework.

## Quick Start

### Installation

```bash
cd verification_service
pip install -r requirements.txt
```

### Running the Service

```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8004 --reload
```

Or use the CLI entry point:
```bash
python main.py
```

The service will be available at `http://localhost:8004`.

- Swagger docs: `http://localhost:8004/docs`
- ReDoc: `http://localhost:8004/redoc`

## Prerequisites

The verification service requires the following upstream services to be running:

1. **KMS (Key Management Service)** — http://localhost:8001
   - Provides public key lookups
2. **DID Registry** — http://localhost:8002
   - Resolves DID Documents
3. **Trust Anchor Service** — http://localhost:8003
   - Validates issuer authorization
4. **Status List Service** — http://localhost:8005
   - Serves revocation status lists
5. **Redis** — redis://localhost:6379
   - Caches nonces, status lists, and trust anchors

## Endpoints

### `POST /verify/nonce`
Generate a new nonce for use in presentation verification.

**Request:**
```json
{
  "verifierDID": "did:web:verifier.example.com:verifier:verifier-1",
  "purpose": "presentation_submission"
}
```

**Response:**
```json
{
  "nonce": "abcd1234...",
  "expiresAt": "2024-09-15T10:00:00+00:00"
}
```

### `POST /verify/presentation`
Verify a Verifiable Presentation and all credentials within it.

**Request:**
```json
{
  "vp_jwt": "eyJhbGc...",
  "nonce": "abcd1234...",
  "verifierDID": "did:web:verifier.example.com:verifier:verifier-1"
}
```

**Response (success):**
```json
{
  "valid": true,
  "verifiedClaims": {
    "roleName": {
      "value": "FinancialAnalyst",
      "vcId": "urn:uuid:...",
      "issuerDID": "did:web:hr.example.com:hr-authority",
      "expiresAt": "2025-09-15T00:00:00Z"
    }
  },
  "failedStep": null,
  "reason": null
}
```

**Response (failure):**
```json
{
  "valid": false,
  "verifiedClaims": null,
  "failedStep": "REVOCATION",
  "reason": "Credential urn:uuid:123 has been revoked"
}
```

### `POST /verify/credential`
Verify a standalone VC (without VP wrapper). Skips VP signature and nonce validation.

**Request:**
```json
{
  "vc_jwt": "eyJhbGc..."
}
```

**Response:**
```json
{
  "valid": true,
  "claims": { "roleName": "FinancialAnalyst", ... },
  "issuerDID": "did:web:hr.example.com:hr-authority",
  "expiresAt": "2025-09-15T00:00:00Z",
  "failedStep": null,
  "reason": null
}
```

## Verification Pipeline

The 6-step verification pipeline runs for every presentation:

1. **VP Signature Verification** — Verifies the VP JWT signature using Ed25519
2. **Nonce Validation** — Ensures nonce exists, hasn't expired, and matches verifier
3. **Per-VC Signature Verification** — Verifies each VC signature (Ed25519 or BBS+)
4. **Trust Anchor Validation** — Confirms issuer is authorized for each credential type
5. **Revocation Status Check** — Fetches and checks StatusList2021 bitstring
6. **Expiry Check** — Ensures no credentials have expired

Each step is executed sequentially. If any step fails, remaining steps are skipped and the failure reason is returned immediately.

## Security Configuration

### `STATUS_CACHE_TTL` (Security Parameter)

**Default:** 30 seconds

Controls how long revocation status lists are cached in Redis. This directly impacts revocation propagation latency:

- **TTL = 10s**: Revoked credentials may pass verification for up to 10 seconds after revocation (higher security)
- **TTL = 30s**: Revoked credentials may pass for up to 30 seconds (balance)
- **TTL = 60s**: Revoked credentials may pass for up to 60 seconds (only use if SLA allows 1-minute revocation latency)

Shorter TTLs increase Redis load and network calls. Adjust based on your security and performance requirements.

### `NONCE_TTL_SECONDS` (Default 300s)

How long nonces remain valid. Shorter TTLs reduce replay attack windows but make presentations time-sensitive. Default 5 minutes is reasonable for most use cases.

## Architecture

```
verification_service/
├── main.py                          # FastAPI app, lifespan events
├── config.py                        # Configuration and environment
├── routers/
│   ├── nonce.py                    # POST /verify/nonce
│   ├── presentation.py             # POST /verify/presentation
│   └── credential.py               # POST /verify/credential
├── services/
│   ├── pipeline.py                 # Verification pipeline orchestrator
│   ├── vp_sig_verifier.py          # Step 1: VP signature
│   ├── nonce_validator.py          # Step 2: Nonce validation
│   ├── vc_sig_verifier.py          # Step 3: VC signature
│   ├── trust_anchor_checker.py     # Step 4: Trust anchor
│   ├── revocation_checker.py       # Step 5: Revocation status
│   ├── expiry_checker.py           # Step 6: Expiry
│   ├── nonce_service.py            # Nonce generation
│   └── zkp_verifier.py             # BBS+ and zk-SNARK verification
├── clients/
│   ├── kms_client.py               # KMS HTTP client
│   ├── did_registry_client.py      # DID Registry HTTP client
│   └── trust_anchor_client.py      # Trust Anchor HTTP client
├── models/
│   ├── requests.py                 # Pydantic request models
│   └── responses.py                # Pydantic response models
├── cache/
│   └── redis_client.py             # Async Redis operations
└── tests/
    ├── test_nonce.py
    ├── test_pipeline.py
    ├── test_vp_verifier.py
    ├── test_vc_sig_verifier.py
    ├── test_revocation_checker.py
    └── test_zkp_verifier.py
```

## Testing

Run unit tests:
```bash
pytest tests/ -v
```

Run specific test file:
```bash
pytest tests/test_nonce.py -v
```

All tests use mocks for external services and Redis, so no real services need to be running.

## Future Work

- **BBS+ Support**: Integration with `@mattrglobal/bbs-signatures` for privacy-preserving derivations
- **zk-SNARK Support**: Integration with `snarkjs` for proof verification
- **Distributed Tracing**: Add correlation ID headers and OpenTelemetry instrumentation
- **Rate Limiting**: Protect against verification spam
- **Audit Logging**: Log all verification attempts (for security investigation)
- **Metrics**: Prometheus metrics for verification performance and error rates

## Related Services

- **VC Issuance Service (SS4)** — `../vc_issuance.py` — Issues VCs
- **DID Registry (SS2)** — Person A — Resolves DIDs
- **KMS (SS1)** — Person A — Manages keys
- **Trust Anchor Service (SS3)** — Person A — Governs issuer authorization
- **Status List Service (SS6)** — Provides revocation status

## References

- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [Status List 2021](https://w3c-ccg.github.io/vc-status-list-2021/)
- [Ed25519 Signature Suite 2020](https://w3c-ccg.github.io/ld-signatures-ed25519-2020/)
- [BBS+ Signatures](https://w3c-ccg.github.io/ld-signatures-bbs/)
