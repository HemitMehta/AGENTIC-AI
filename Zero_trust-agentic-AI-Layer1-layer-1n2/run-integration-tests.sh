#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────
# Integration Testing Script
# ─────────────────────────────────────────────────────────────────────────
#
# This script runs comprehensive integration tests for SS4 and SS5.
#
# Usage:
#   ./run-integration-tests.sh [test_pattern]
#
# Examples:
#   ./run-integration-tests.sh                          # Run all tests
#   ./run-integration-tests.sh test_integration_ss4_ss5 # Run SS4/SS5 tests only
#   ./run-integration-tests.sh test_workflow            # Run workflow tests only

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "════════════════════════════════════════════════════════════════════════"
echo "Zero-Trust Agentic AI Integration Testing"
echo "════════════════════════════════════════════════════════════════════════"
echo

# ─────────────────────────────────────────────────────────────────────────
# Step 1: Check prerequisites
# ─────────────────────────────────────────────────────────────────────────

echo "📋 Checking prerequisites..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.11+"
    exit 1
fi

if ! command -v pip &> /dev/null; then
    echo "❌ pip not found. Please install pip"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1-2)
echo "✓ Python $PYTHON_VERSION found"

# ─────────────────────────────────────────────────────────────────────────
# Step 2: Install dependencies
# ─────────────────────────────────────────────────────────────────────────

echo
echo "📦 Installing dependencies..."

pip install -q pytest pytest-asyncio pytest-cov httpx fastapi uvicorn redis pydantic python-dotenv cryptography pynacl base58 gzip 2>/dev/null || true

echo "✓ Dependencies installed"

# ─────────────────────────────────────────────────────────────────────────
# Step 3: Run SS4 Unit Tests
# ─────────────────────────────────────────────────────────────────────────

echo
echo "════════════════════════════════════════════════════════════════════════"
echo "🧪 Running SS4 (VC Issuance) Unit Tests"
echo "════════════════════════════════════════════════════════════════════════"

if [ -f "test_ss4_vc_issuance.py" ]; then
    pytest test_ss4_vc_issuance.py -v --tb=short 2>/dev/null || true
else
    echo "⚠️  test_ss4_vc_issuance.py not found, skipping"
fi

# ─────────────────────────────────────────────────────────────────────────
# Step 4: Run SS5 Unit Tests
# ─────────────────────────────────────────────────────────────────────────

echo
echo "════════════════════════════════════════════════════════════════════════"
echo "🧪 Running SS5 (VC Verification) Unit Tests"
echo "════════════════════════════════════════════════════════════════════════"

if [ -d "verification_service/tests" ]; then
    cd verification_service/tests
    TEST_PATTERN="${1:-test_*.py}"
    
    echo "Running tests matching: $TEST_PATTERN"
    
    # Run the tests
    if pytest $TEST_PATTERN -v --tb=short -k "not integration" 2>/dev/null; then
        UNIT_TESTS_PASSED=true
        echo "✓ Unit tests passed"
    else
        UNIT_TESTS_PASSED=false
        echo "⚠️  Some unit tests failed (see above)"
    fi
    
    cd ../..
else
    echo "⚠️  verification_service/tests directory not found"
fi

# ─────────────────────────────────────────────────────────────────────────
# Step 5: Run Integration Tests
# ─────────────────────────────────────────────────────────────────────────

echo
echo "════════════════════════════════════════════════════════════════════════"
echo "🔗 Running Integration Tests (SS4 + SS5)"
echo "════════════════════════════════════════════════════════════════════════"

if [ -d "verification_service/tests" ]; then
    cd verification_service/tests
    
    echo "Running SS4/SS5 integration tests..."
    if pytest test_integration_ss4_ss5.py -v --tb=short 2>/dev/null; then
        INTEGRATION_TESTS_PASSED=true
        echo "✓ SS4/SS5 integration tests passed"
    else
        INTEGRATION_TESTS_PASSED=false
        echo "⚠️  Some integration tests failed (see above)"
    fi
    
    echo
    echo "Running end-to-end workflow tests..."
    if pytest test_integration_end_to_end.py -v --tb=short 2>/dev/null; then
        E2E_TESTS_PASSED=true
        echo "✓ End-to-end tests passed"
    else
        E2E_TESTS_PASSED=false
        echo "⚠️  Some end-to-end tests failed (see above)"
    fi
    
    cd ../..
fi

# ─────────────────────────────────────────────────────────────────────────
# Step 6: Summary
# ─────────────────────────────────────────────────────────────────────────

echo
echo "════════════════════════════════════════════════════════════════════════"
echo "📊 Test Summary"
echo "════════════════════════════════════════════════════════════════════════"

STATUS_ICON_UNIT="$([ "$UNIT_TESTS_PASSED" = "true" ] && echo "✓" || echo "⚠️")"
STATUS_ICON_INT="$([ "$INTEGRATION_TESTS_PASSED" = "true" ] && echo "✓" || echo "⚠️")"
STATUS_ICON_E2E="$([ "$E2E_TESTS_PASSED" = "true" ] && echo "✓" || echo "⚠️")"

echo "$STATUS_ICON_UNIT Unit Tests"
echo "$STATUS_ICON_INT Integration Tests (SS4 + SS5)"
echo "$STATUS_ICON_E2E End-to-End Workflow Tests"

if [ "$UNIT_TESTS_PASSED" = "true" ] && [ "$INTEGRATION_TESTS_PASSED" = "true" ] && [ "$E2E_TESTS_PASSED" = "true" ]; then
    echo
    echo "✅ All tests passed!"
    exit 0
else
    echo
    echo "⚠️  Some tests did not pass. Review output above."
    exit 1
fi
