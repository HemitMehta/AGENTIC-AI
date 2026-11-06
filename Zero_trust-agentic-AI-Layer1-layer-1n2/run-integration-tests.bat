@echo off
REM ─────────────────────────────────────────────────────────────────────────
REM Integration Testing Script (Windows)
REM ─────────────────────────────────────────────────────────────────────────
REM
REM This script runs comprehensive integration tests for SS4 and SS5.
REM
REM Usage:
REM   run-integration-tests.bat [test_pattern]
REM
REM Examples:
REM   run-integration-tests.bat                          # Run all tests
REM   run-integration-tests.bat test_integration_ss4_ss5 # Run SS4/SS5 tests only

setlocal enabledelayedexpansion
cd /d %~dp0

echo ════════════════════════════════════════════════════════════════════════
echo Zero-Trust Agentic AI Integration Testing
echo ════════════════════════════════════════════════════════════════════════
echo.

REM ─────────────────────────────────────────────────────────────────────────
REM Step 1: Check prerequisites
REM ─────────────────────────────────────────────────────────────────────────

echo 📋 Checking prerequisites...

where python >nul 2>nul
if errorlevel 1 (
    echo ❌ Python not found. Please install Python 3.11+
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo ✓ Python %PYTHON_VERSION% found

REM ─────────────────────────────────────────────────────────────────────────
REM Step 2: Install dependencies
REM ─────────────────────────────────────────────────────────────────────────

echo.
echo 📦 Installing dependencies...

pip install -q pytest pytest-asyncio pytest-cov httpx fastapi uvicorn redis pydantic python-dotenv cryptography pynacl base58 >nul 2>&1

echo ✓ Dependencies installed

REM ─────────────────────────────────────────────────────────────────────────
REM Step 3: Run SS4 Unit Tests
REM ─────────────────────────────────────────────────────────────────────────

echo.
echo ════════════════════════════════════════════════════════════════════════
echo 🧪 Running SS4 (VC Issuance) Unit Tests
echo ════════════════════════════════════════════════════════════════════════

if exist "test_ss4_vc_issuance.py" (
    pytest test_ss4_vc_issuance.py -v --tb=short
) else (
    echo ⚠️  test_ss4_vc_issuance.py not found, skipping
)

REM ─────────────────────────────────────────────────────────────────────────
REM Step 4: Run SS5 Unit Tests
REM ─────────────────────────────────────────────────────────────────────────

echo.
echo ════════════════════════════════════════════════════════════════════════
echo 🧪 Running SS5 (VC Verification) Unit Tests
echo ════════════════════════════════════════════════════════════════════════

if exist "verification_service\tests" (
    cd verification_service\tests
    set TEST_PATTERN=%1
    if "!TEST_PATTERN!"=="" set TEST_PATTERN=test_*.py
    
    echo Running tests matching: !TEST_PATTERN!
    
    pytest !TEST_PATTERN! -v --tb=short -k "not integration"
    if errorlevel 0 (
        set UNIT_TESTS_PASSED=true
        echo ✓ Unit tests passed
    ) else (
        set UNIT_TESTS_PASSED=false
        echo ⚠️  Some unit tests failed (see above)
    )
    
    cd ..\..
) else (
    echo ⚠️  verification_service\tests directory not found
)

REM ─────────────────────────────────────────────────────────────────────────
REM Step 5: Run Integration Tests
REM ─────────────────────────────────────────────────────────────────────────

echo.
echo ════════════════════════════════════════════════════════════════════════
echo 🔗 Running Integration Tests (SS4 + SS5)
echo ════════════════════════════════════════════════════════════════════════

if exist "verification_service\tests" (
    cd verification_service\tests
    
    echo Running SS4/SS5 integration tests...
    pytest test_integration_ss4_ss5.py -v --tb=short
    if errorlevel 0 (
        set INTEGRATION_TESTS_PASSED=true
        echo ✓ SS4/SS5 integration tests passed
    ) else (
        set INTEGRATION_TESTS_PASSED=false
        echo ⚠️  Some integration tests failed (see above)
    )
    
    echo.
    echo Running end-to-end workflow tests...
    pytest test_integration_end_to_end.py -v --tb=short
    if errorlevel 0 (
        set E2E_TESTS_PASSED=true
        echo ✓ End-to-end tests passed
    ) else (
        set E2E_TESTS_PASSED=false
        echo ⚠️  Some end-to-end tests failed (see above)
    )
    
    cd ..\..
)

REM ─────────────────────────────────────────────────────────────────────────
REM Step 6: Summary
REM ─────────────────────────────────────────────────────────────────────────

echo.
echo ════════════════════════════════════════════════════════════════════════
echo 📊 Test Summary
echo ════════════════════════════════════════════════════════════════════════

set UNIT_ICON=✓
if "!UNIT_TESTS_PASSED!"=="false" set UNIT_ICON=⚠️

set INT_ICON=✓
if "!INTEGRATION_TESTS_PASSED!"=="false" set INT_ICON=⚠️

set E2E_ICON=✓
if "!E2E_TESTS_PASSED!"=="false" set E2E_ICON=⚠️

echo !UNIT_ICON! Unit Tests
echo !INT_ICON! Integration Tests (SS4 + SS5)
echo !E2E_ICON! End-to-End Workflow Tests

if "!UNIT_TESTS_PASSED!"=="true" if "!INTEGRATION_TESTS_PASSED!"=="true" if "!E2E_TESTS_PASSED!"=="true" (
    echo.
    echo ✅ All tests passed!
    exit /b 0
) else (
    echo.
    echo ⚠️  Some tests did not pass. Review output above.
    exit /b 1
)
