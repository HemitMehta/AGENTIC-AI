# Integration Testing Guide

This guide explains how to run comprehensive integration tests for the Zero-Trust Agentic AI Layer 1 system, specifically testing the interaction between SS4 (VC Issuance) and SS5 (VC Verification).

## Overview

**Integration tests validate:**

1. **SS4 → SS5 Complete Flow** — Issue a VC → Create VP → Request nonce → Verify presentation
2. **Multiple VC Types** — Role, Capability, Compliance, Provenance, Reputation, JIT
3. **All 6 Verification Steps** — VP signature, nonce, VC signature, trust anchor, revocation, expiry
4. **Error Paths** — Revoked credentials, expired credentials, unauthorized issuers
5. **Workflow Scenarios** — Multi-VC presentations, peer-issued credentials

## Quick Start

### Option 1: Run Integration Tests Locally (Recommended for Development)

**Requirements:**
- Python 3.11+
- pip
- Redis running locally (`redis-cli` accessible)

**Steps:**

```bash
# Windows
run-integration-tests.bat

# macOS/Linux
bash run-integration-tests.sh
```

**Expected Output:**
```
════════════════════════════════════════════════════════════════════════
Zero-Trust Agentic AI Integration Testing
════════════════════════════════════════════════════════════════════════

Checking prerequisites...
Python 3.11 found

 Installing dependencies...
Dependencies installed

 Running SS4 (VC Issuance) Unit Tests
...40 tests passed...

 Running SS5 (VC Verification) Unit Tests
...20 tests passed...
 Running Integration Tests (SS4 + SS5)
...5 integration tests passed...
...4 end-to-end workflow tests passed...

 Test Summary
✓ Unit Tests
✓ Integration Tests (SS4 + SS5)
✓ End-to-End Workflow Tests

 All tests passed!
```

### Option 2: Run Integration Tests with Docker Compose

**Requirements:**
- Docker & Docker Compose
- No local services needed (all containerized)

**Steps:**

```bash
# Start all services (KMS, DID Registry, Trust Anchor, Redis, SS4, SS5)
docker-compose up --build

# In another terminal, run tests
docker-compose exec vc_verification pytest tests/ -v
```

### Option 3: Run Specific Test Categories

```bash
# Unit tests only (no integration)
cd verification_service/tests
pytest test_nonce.py -v
pytest test_pipeline.py -v

# SS4/SS5 integration tests
pytest test_integration_ss4_ss5.py -v

# End-to-end workflow tests
pytest test_integration_end_to_end.py -v

# Single test
pytest test_integration_ss4_ss5.py::test_integration_issue_and_verify_role_vc -v
```

## Test Structure

### 1. **test_integration_ss4_ss5.py** — Direct SS4/SS5 Integration

Tests the core integration between credential issuance and verification:

- **`test_integration_issue_and_verify_role_vc`**
  - Issues Role VC via SS4 with mock pipeline
  - Creates VP containing the VC
  - Requests nonce from SS5
  - Presents VP to SS5
  - Verifies all 6 steps pass
  - Confirms verified claims contain roleName

- **`test_integration_issue_and_verify_jit_vc`**
  - Issues JIT VC with 30-minute expiry
  - Special handling for toolset validation
  - Verifies presentation succeeds

- **`test_integration_multiple_vcs_in_presentation`**
  - Issues two VCs (Role + Capability)
  - Presents both in single VP
  - Verifies merged claims from both

- **`test_integration_presentation_with_revoked_vc`**
  - VC marked as revoked in status list
  - Presentation fails at REVOCATION step
  - Error message includes VC ID and reason

- **`test_integration_presentation_with_expired_vc`**
  - VC has expirationDate in the past
  - Presentation fails at EXPIRY step
  - Error includes expiration date

### 2. **test_integration_end_to_end.py** — Complete Workflow Scenarios

Tests realistic multi-step workflows:

- **`test_complete_workflow_agent_presents_credentials_to_verifier`**
  - Authority issues Role VC to Agent (with department)
  - Authority issues Capability VC to Agent
  - Agent requests nonce from Verifier
  - Agent creates VP with both VCs
  - Agent signs VP and presents to Verifier
  - Verifier verifies and receives merged claims
  - Confirms claims from both VCs present with metadata

- **`test_workflow_with_peer_reputation_vc`**
  - Peer agent issues Reputation VC (not authority)
  - Reputation has score in range 0-100
  - Verification passes for peer-issued credential
  - Trust anchor validates peer issuer

- **`test_workflow_failure_unauthorized_issuer`**
  - Issuer is not in trust anchor for this credential type
  - VP presentation fails at TRUST_ANCHOR step
  - Error message indicates unauthorized issuer

## Test Execution Flow

Each integration test follows this pattern:

```
1. SETUP MOCKS
   ├─ Mock all upstream services (KMS, DID Registry, Trust Anchor, Redis, DB)
   ├─ Define issuer, subject, verifier DIDs
   └─ Set up sample responses

2. ISSUE PHASE (SS4)
   ├─ Create issuance request
   ├─ Mock vc_issuance._run_issuance_pipeline()
   ├─ Call issue_credential()
   └─ Assert VC created successfully

3. PRESENTATION PHASE
   ├─ Request nonce from SS5
   ├─ Create Verifiable Presentation JWT
   └─ Embed VC and proof challenge

4. VERIFICATION PHASE (SS5)
   ├─ Mock all 6 verification steps
   ├─ Call verify_presentation()
   └─ Verify early exit on first failure (if applicable)

5. ASSERTION PHASE
   ├─ Check valid=true/false
   ├─ Verify failed_step matches expected
   ├─ Validate claims structure
   └─ Confirm reason/error messages
```

## Mock Services

All tests use mocks to avoid external dependencies:

| Service | Mocked By | Behavior |
|---------|-----------|----------|
| KMS | `kms.sign_payload()` | Returns `"mocksignature=="` |
| DID Registry | `did_registry.resolve_did_at_time()` | Returns active DID document |
| Trust Anchor | `root_trust.validate_issuer()` | Returns `{"authorised": True}` |
| Status List | `status_list.allocate_status_entry()` | Returns status list URL + index |
| CockroachDB | `vc_issuance._persist_vc()` | Returns `None` (no DB call) |
| Redis | `redis_client` | Returns `None`/`True` for operations |

**Key:** Mocks use `@patch` decorator to replace functions during tests. External service URLs are never called.

## Expected Test Results

### Successful Run

```
test_integration_ss4_ss5.py::test_integration_issue_and_verify_role_vc PASSED    [20%]
test_integration_ss4_ss5.py::test_integration_issue_and_verify_jit_vc PASSED     [40%]
test_integration_ss4_ss5.py::test_integration_multiple_vcs_in_presentation PASSED [60%]
test_integration_ss4_ss5.py::test_integration_presentation_with_revoked_vc PASSED [80%]
test_integration_ss4_ss5.py::test_integration_presentation_with_expired_vc PASSED [100%]

test_integration_end_to_end.py::test_complete_workflow_agent_presents_credentials_to_verifier PASSED    [20%]
test_integration_end_to_end.py::test_workflow_with_peer_reputation_vc PASSED                           [40%]
test_integration_end_to_end.py::test_workflow_failure_unauthorized_issuer PASSED                       [60%]

========== 9 passed in 2.34s ==========
```

### Failure Cases

Tests validate that failures propagate correctly:

- **Revoked VC** → `valid=False, failedStep=REVOCATION`
- **Expired VC** → `valid=False, failedStep=EXPIRY`
- **Unauthorized Issuer** → `valid=False, failedStep=TRUST_ANCHOR`
- **Bad Signature** → `valid=False, failedStep=VP_SIGNATURE` or `VC_SIGNATURE`
- **Replay Attack (Nonce)** → `valid=False, failedStep=NONCE`

## Docker Compose Integration

The `docker-compose.yml` provides:

```yaml
Services:
  redis:6379           # Cache for nonces, status lists, trust anchors
  kms:8001            # Key Management (Person A)
  did_registry:8002   # DID Resolution (Person A)
  trust_anchor:8003   # Trust authorization (Person A)
  vc_issuance:8004    # SS4 - VC Issuance
  vc_verification:8005 # SS5 - VC Verification
```

**To run services in background:**

```bash
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f vc_verification

# Stop services
docker-compose down
```

**To run tests against running services:**

```bash
# Terminal 1: Start services
docker-compose up

# Terminal 2: Run integration tests
docker-compose exec vc_verification pytest tests/test_integration_ss4_ss5.py -v
```

## Troubleshooting

### "Redis connection refused"

**Problem:** Redis not running
**Solution:** 
```bash
# Start Redis locally
redis-server

# Or use Docker
docker run -d -p 6379:6379 redis:7-alpine
```

### "ModuleNotFoundError: No module named 'vc_issuance'"

**Problem:** Python path not configured
**Solution:** 
```bash
# Ensure you're running from workspace root
cd /path/to/Zero_trust-agentic-AI-Layer1

# Or add to sys.path in test
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
```

### "Fixtures not working"

**Problem:** pytest discovers tests but fixtures fail
**Solution:** Ensure `conftest.py` is in same directory as tests:
```
verification_service/
  tests/
    conftest.py       # ← Must be here
    test_nonce.py
    test_pipeline.py
    test_integration_ss4_ss5.py
```

### "Async test hangs"

**Problem:** `pytest-asyncio` not installed or configured
**Solution:**
```bash
pip install pytest-asyncio

# Or add pytest.ini
[pytest]
asyncio_mode = auto
```

## CI/CD Integration

For automated testing in CI/CD pipelines:

### GitHub Actions

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      redis:
        image: redis:7-alpine
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: pip install -r requirements.txt pytest pytest-asyncio
      
      - name: Run integration tests
        run: pytest verification_service/tests/test_integration_*.py -v
```

## Next Steps

After integration tests pass:

1. **Deploy to Staging** — Run services in container orchestration (K8s, Docker Swarm)
2. **Run Load Tests** — Verify performance under load (nonce generation, revocation checks)
3. **Run Security Tests** — Validate signature verification, replay attack prevention
4. **Integration with SS1-SS6** — Connect all subsystems end-to-end
5. **Production Deployment** — Deploy with monitoring, logging, tracing

## References

- [pytest Documentation](https://docs.pytest.org/)
- [pytest-asyncio](https://pytest-asyncio.readthedocs.io/)
- [W3C VC Verification Process](https://www.w3.org/TR/vc-data-model-2.0/#verify-algorithm)
- [Verifiable Presentations](https://www.w3.org/TR/vc-data-model-2.0/#presentations)
