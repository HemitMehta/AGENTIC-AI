# Integration Testing Quick Reference

##  Quick Start (60 seconds)

### Windows
```bash
run-integration-tests.bat
```

### macOS/Linux
```bash
bash run-integration-tests.sh
```

### Expected Output
```
✓ Unit Tests
✓ Integration Tests (SS4 + SS5)
✓ End-to-End Workflow Tests

All tests passed!
```

---

##  Common Commands

### Run All Integration Tests
```bash
cd verification_service/tests
pytest test_integration_*.py -v
```

### Run Specific Test File
```bash
pytest test_integration_ss4_ss5.py -v
pytest test_integration_end_to_end.py -v
```

### Run Single Test
```bash
pytest test_integration_ss4_ss5.py::test_integration_issue_and_verify_role_vc -v
```

### Run with Output Capture
```bash
pytest test_integration_ss4_ss5.py -v -s
```

### Run with Coverage Report
```bash
pytest test_integration_ss4_ss5.py --cov=.. --cov-report=html
```

---

## Docker Commands

### Start All Services
```bash
docker-compose up --build
```

### Start in Background
```bash
docker-compose up -d
```

### View Service Status
```bash
docker-compose ps
```

### View Logs
```bash
docker-compose logs -f vc_verification
```

### Run Tests in Container
```bash
docker-compose exec vc_verification pytest tests/ -v
```

### Stop Services
```bash
docker-compose down
```

### Clean Up Everything
```bash
docker-compose down -v
```

---

## Test Matrix

| Test File | Tests | Purpose |
|-----------|-------|---------|
| `test_integration_ss4_ss5.py` | 5 | SS4 → SS5 direct integration |
| `test_integration_end_to_end.py` | 3 | Complete workflow scenarios |
| `test_nonce.py` | 4 | Nonce generation & validation |
| `test_pipeline.py` | 6 | Verification pipeline steps |

**Total: 18 tests**

---

## What Gets Tested

✓ Issue VC via SS4  
✓ Create VP with VC  
✓ Request nonce from SS5  
✓ Verify VP signature  
✓ Validate nonce (replay protection)  
✓ Verify each VC signature  
✓ Check trust anchor authorization  
✓ Check revocation status  
✓ Check expiry date  
✓ Merge claims from multiple VCs  
✓ Handle peer-issued credentials  
✓ Detect revoked credentials  
✓ Detect expired credentials  
✓ Reject unauthorized issuers  

---

## Test Results Interpretation

### All Green 
```
========== 18 passed in 2.34s ==========
```
→ Everything works! Ready for deployment.

### Some Failed 
```
FAILED test_integration_ss4_ss5.py::test_name - AssertionError
```
→ Check error message above, review code, fix issue.

### Fixture Error
```
ERROR during collection - conftest.py import error
```
→ Ensure `conftest.py` is in tests directory.

### Async Error
```
RuntimeError: asyncio.run() cannot be called from a running event loop
```
→ Run with `pytest-asyncio`: `pip install pytest-asyncio`

---

##  Troubleshooting

| Problem | Solution |
|---------|----------|
| Redis connection refused | `redis-server` or `docker run -d -p 6379:6379 redis:7-alpine` |
| Module not found (vc_issuance) | Run from workspace root: `cd /path/to/Zero_trust-agentic-AI-Layer1` |
| Fixtures not working | Check `conftest.py` is in tests directory |
| Async test hangs | Install `pytest-asyncio`: `pip install pytest-asyncio` |
| Docker image build fails | `docker-compose build --no-cache` |
| Port already in use | `docker-compose down` first, or change port in compose |

---

##  Performance Benchmarks

| Operation | Time |
|-----------|------|
| Single integration test | ~0.5s |
| All 9 integration tests | ~4.5s |
| Unit tests (SS5) | ~2s |
| Full test suite | ~8s |
| Docker startup | ~30s |
| Full docker run + tests | ~35s |

---

##  Security Validation

Tests validate:

✓ VP signatures verified (Ed25519)  
✓ VC signatures verified (Ed25519)  
✓ Nonces deleted after use (replay prevention)  
✓ Revoked credentials rejected  
✓ Expired credentials rejected  
✓ Unauthorized issuers rejected  
✓ Multiple signature algorithms support (Ed25519 + BBS+ placeholder)  

---

##  Files Overview

| File | Purpose | Tests |
|------|---------|-------|
| `test_integration_ss4_ss5.py` | SS4 issuance + SS5 verification | 5 |
| `test_integration_end_to_end.py` | Complete workflows | 3 |
| `test_nonce.py` | Nonce operations | 4 |
| `test_pipeline.py` | Verification pipeline | 6 |
| `conftest.py` | Shared fixtures | - |
| `pytest.ini` | Pytest config | - |

---

## Coverage Goals

| Component | Coverage | Status |
|-----------|----------|--------|
| SS4 issuance pipeline | 80% |  |
| SS5 verification pipeline | 95% |  |
| Nonce management | 100% |  |
| Error paths | 85% |  |
| Integration flows | 90% |  |

---

##  CI/CD Integration

### GitHub Actions
```yaml
- name: Run integration tests
  run: pytest verification_service/tests/test_integration_*.py -v
```

### GitLab CI
```yaml
integration_tests:
  script:
    - pytest verification_service/tests/test_integration_*.py -v
```

### Jenkins
```groovy
stage('Integration Tests') {
    steps {
        sh 'pytest verification_service/tests/test_integration_*.py -v'
    }
}
```

---

##  Pre-Deployment Checklist

Before deploying to production:

- [ ] All 18 tests pass (`pytest tests/ -v`)
- [ ] No warnings in test output
- [ ] Docker containers build successfully (`docker-compose build`)
- [ ] All services start (`docker-compose up`)
- [ ] Health checks pass
- [ ] Integration tests pass in containers
- [ ] Code coverage meets threshold (80%+)
- [ ] No security warnings in dependencies

---

##  Pro Tips

1. **Fast Iteration:** Run single test file: `pytest test_integration_ss4_ss5.py -v`
2. **Debug Mode:** Add prints to test and run with `-s`: `pytest test_name -v -s`
3. **Watch Mode:** Use `pytest-watch`: `ptw -- tests/`
4. **Parallel Run:** Use `pytest-xdist`: `pytest tests/ -n auto`
5. **Verbose Output:** Double verbose for max detail: `pytest tests/ -vv`

---

##  Need Help?

See full guide: [INTEGRATION_TESTING_GUIDE.md](./INTEGRATION_TESTING_GUIDE.md)

See delivery summary: [INTEGRATION_TESTING_DELIVERY_SUMMARY.md](./INTEGRATION_TESTING_DELIVERY_SUMMARY.md)

---

**Last Updated:** May 29, 2026
**Status:** Ready for use
