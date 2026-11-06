#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# run_integration_test.sh -- spins up a mock Layer 1 + all 5 Layer 2 modules
# locally (no Docker required), runs the full discovery flow, asserts on the
# results, then tears everything down.
#
# Usage:
#   cd layer2_testing
#   pip install fastapi uvicorn pydantic httpx --break-system-packages   # if not already installed
#   bash run_integration_test.sh
#
# Exit code 0 = all assertions passed. Non-zero = something failed; check
# /tmp/layer2_test_logs/ for each service's stdout/stderr.
# ---------------------------------------------------------------------------
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="/tmp/layer2_test_logs"
mkdir -p "$LOG_DIR"
rm -f "$LOG_DIR"/*.log

PIDS=()
FAILURES=0

cleanup() {
  echo
  echo "--- tearing down all test processes ---"
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null
  done
  wait 2>/dev/null
}
trap cleanup EXIT

start_service() {
  local dir="$1" port="$2" name="$3"; shift 3
  ( cd "$dir" && env "$@" "${PYTHON_BIN:-python3}" -m uvicorn main:app --host 127.0.0.1 --port "$port" \
      > "$LOG_DIR/$name.log" 2>&1 & echo $! > "$LOG_DIR/$name.pid" )
  sleep 0.2
  PIDS+=("$(cat "$LOG_DIR/$name.pid")")
}

wait_healthy() {
  local port="$1" name="$2" tries=30
  until curl -s --max-time 1 "http://127.0.0.1:$port/health" > /dev/null 2>&1; do
    tries=$((tries - 1))
    if [ "$tries" -le 0 ]; then
      echo "FAIL: $name on port $port never became healthy. Log:"
      cat "$LOG_DIR/$name.log"
      exit 1
    fi
    sleep 0.3
  done
}

assert_contains() {
  local haystack="$1" needle="$2" label="$3"
  if echo "$haystack" | grep -qF "$needle"; then
    echo "  PASS: $label"
  else
    echo "  FAIL: $label"
    echo "        expected to find: $needle"
    echo "        got: $haystack"
    FAILURES=$((FAILURES + 1))
  fi
}

echo "=== Starting mock Layer 1 (ports 8001, 8002, 8004, 8005, 8006, 8007) ==="
start_service "$ROOT_DIR/layer2_testing/mock_layer1" 8001 mock_l1_8001
start_service "$ROOT_DIR/layer2_testing/mock_layer1" 8002 mock_l1_8002
start_service "$ROOT_DIR/layer2_testing/mock_layer1" 8004 mock_l1_8004
start_service "$ROOT_DIR/layer2_testing/mock_layer1" 8005 mock_l1_8005
start_service "$ROOT_DIR/layer2_testing/mock_layer1" 8006 mock_l1_8006
start_service "$ROOT_DIR/layer2_testing/mock_layer1" 8007 mock_l1_8007
for p in 8001 8002 8004 8005 8006 8007; do wait_healthy "$p" "mock_l1_$p"; done
echo "Mock Layer 1 is up."
echo

echo "=== Starting Layer 2 modules ==="
start_service "$ROOT_DIR/ans_registry_service" 8008 module1 \
  DID_REGISTRY_URL=http://127.0.0.1:8002 \
  ANS_REQUIRE_REGISTRATION_PROOF=false
wait_healthy 8008 module1

start_service "$ROOT_DIR/discovery_trust_policy_service" 8010 module3
wait_healthy 8010 module3

start_service "$ROOT_DIR/ans_resolver_service" 8009 module2 \
  ANS_REGISTRY_URL=http://127.0.0.1:8008 \
  VC_VERIFICATION_URL=http://127.0.0.1:8005 \
  WALLET_SERVICE_URL=http://127.0.0.1:8007 \
  KMS_URL=http://127.0.0.1:8001 \
  DOWNSTREAM_TIMEOUT_SECONDS=90
wait_healthy 8009 module2

start_service "$ROOT_DIR/reputation_service" 8011 module4 \
  VC_ISSUANCE_URL=http://127.0.0.1:8004 \
  VC_ISSUANCE_TIMEOUT_SECONDS=90
wait_healthy 8011 module4

start_service "$ROOT_DIR/discovery_gateway" 8012 module5 \
  TRUST_POLICY_URL=http://127.0.0.1:8010 \
  ANS_RESOLVER_URL=http://127.0.0.1:8009 \
  REPUTATION_SERVICE_URL=http://127.0.0.1:8011 \
  KMS_URL=http://127.0.0.1:8001 \
  DOWNSTREAM_TIMEOUT_SECONDS=90
wait_healthy 8012 module5

echo "All 5 Layer 2 modules are up."
echo

# ---------------------------------------------------------------------------
# Test 1 -- register an agent, requires the mock did_registry to say yes
# ---------------------------------------------------------------------------
echo "=== Test 1: register agent (Module 1) ==="
REG_RESP=$(curl -s -X POST http://127.0.0.1:8008/register -H "Content-Type: application/json" -d '{
  "ansName": "acp://RiskAnalyzerBot.FinancialRiskAnalysis.AcmeFinanceServices.v2.1.3.prod",
  "agentDid": "did:web:acme:agent:riskanalyzer:beta-007",
  "capability": "FinancialRiskAnalysis.CorporateReporting",
  "provider": "AcmeFinanceServices",
  "version": "2.1.3",
  "serviceEndpoint": "https://riskanalyzer.acmefinance.com/service",
  "protocolExtensions": [{"protocol": "acp", "details": {}}]
}')
assert_contains "$REG_RESP" '"status":"active"' "agent registered as active"

echo "=== Test 1b: registration REJECTED for an unresolvable DID ==="
BAD_REG_RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://127.0.0.1:8008/register -H "Content-Type: application/json" -d '{
  "ansName": "acp://Fake.Agent.v1",
  "agentDid": "did:web:does-not-exist:agent:999",
  "capability": "Fake.Capability",
  "provider": "NoOne",
  "version": "1.0.0",
  "serviceEndpoint": "https://nowhere.example.com"
}')
assert_contains "$BAD_REG_RESP" "400" "unresolvable DID rejected with 400"

# ---------------------------------------------------------------------------
# Test 2 -- reputation feedback + VC issuance
# ---------------------------------------------------------------------------
echo "=== Test 2: submit reputation feedback with VC issuance (Module 4) ==="
FEEDBACK_RESP=$(curl -s -X POST http://127.0.0.1:8011/feedback -H "Content-Type: application/json" -d '{
  "raterDid": "did:web:enterprise:agent:orchestrator:alpha-001",
  "ratedAgentDid": "did:web:acme:agent:riskanalyzer:beta-007",
  "rating": 5,
  "taskId": "task-1",
  "issueVc": true
}')
assert_contains "$FEEDBACK_RESP" '"issuedVcId":"vc:jwt:uri:reputation-service:mock-001"' "reputation VC issued"

echo "=== Test 3: aggregated reputation score ==="
SCORE_RESP=$(curl -s http://127.0.0.1:8011/reputation/did:web:acme:agent:riskanalyzer:beta-007)
assert_contains "$SCORE_RESP" '"score":100.0' "score aggregates to 100.0 from a single 5-star rating"

# ---------------------------------------------------------------------------
# Test 4 -- resolver: VC verification, revocation check, signing
# ---------------------------------------------------------------------------
echo "=== Test 4: resolve by capability with a valid, non-revoked attestation ==="
RESOLVE_RESP=$(curl -s -X POST http://127.0.0.1:8009/resolveByCapability -H "Content-Type: application/json" -d '{
  "capability": "FinancialRiskAnalysis.CorporateReporting",
  "requiredAttestations": ["SOXComplianceCertified"]
}')
assert_contains "$RESOLVE_RESP" '"resolutionStatus":"success"' "resolution succeeds"
assert_contains "$RESOLVE_RESP" '"verified":true' "attestation verified"
assert_contains "$RESOLVE_RESP" '"revoked":false' "attestation not revoked"
assert_contains "$RESOLVE_RESP" '"ansRecordSignature":"sha256:' "record was signed by kms"

echo "=== Test 4b: resolve REJECTS a revoked attestation ==="
REVOKED_RESP=$(curl -s -X POST http://127.0.0.1:8009/resolveByCapability -H "Content-Type: application/json" -d '{
  "capability": "FinancialRiskAnalysis.CorporateReporting",
  "requiredAttestations": ["RevokedCredentialTest"]
}')
assert_contains "$REVOKED_RESP" '"resolutionStatus":"no_matches"' "candidate with revoked VC is dropped"

# ---------------------------------------------------------------------------
# Test 5 -- Gateway: trust policy allow path
# ---------------------------------------------------------------------------
echo "=== Test 5: Gateway succeeds when nothing is restricted yet ==="
GATEWAY_OK=$(curl -s -X POST http://127.0.0.1:8012/discover -H "Content-Type: application/json" -d '{
  "capability": "FinancialRiskAnalysis.CorporateReporting",
  "requiredAttestations": ["SOXComplianceCertified"]
}')
assert_contains "$GATEWAY_OK" '"resolutionStatus":"success"' "gateway returns success"
assert_contains "$GATEWAY_OK" '"selectedAgent":"did:web:acme:agent:riskanalyzer:beta-007"' "gateway selects the right agent"
assert_contains "$GATEWAY_OK" '"gatewaySignature":"sha256:' "gateway response is signed"

# ---------------------------------------------------------------------------
# Test 6 -- Gateway: trust policy reject path
# ---------------------------------------------------------------------------
echo "=== Test 6: Gateway REJECTS once a conflicting capability-domain allowlist exists ==="
curl -s -X POST http://127.0.0.1:8010/capability-domains -H "Content-Type: application/json" \
  -d '{"domain": "OCR", "notes": "test-only restriction"}' > /dev/null

GATEWAY_REJECTED=$(curl -s -X POST http://127.0.0.1:8012/discover -H "Content-Type: application/json" -d '{
  "capability": "FinancialRiskAnalysis.CorporateReporting"
}')
assert_contains "$GATEWAY_REJECTED" '"resolutionStatus":"rejected_by_trust_policy"' "gateway rejects out-of-allowlist domain"

echo
echo "==============================================="
if [ "$FAILURES" -eq 0 ]; then
  echo "ALL TESTS PASSED"
  exit 0
else
  echo "$FAILURES TEST(S) FAILED -- see output above"
  exit 1
fi
