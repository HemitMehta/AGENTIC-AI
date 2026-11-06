# Zero Trust Agentic AI - Layers 1, 2, and 3

Layer 1 is the trust and credential foundation for the platform.
It includes Person A trust infrastructure (KMS, DID Registry, Trust Anchor) and Person B credential services (Issuance, Verification, Revocation, Wallet), all orchestrated with Docker Compose.

Layer 2 (Agent Discovery & Adaptive Trust Establishment) is combined into this same repo and `docker-compose.yml`. It answers "how does an agent find another agent capable of doing X, and how much should it be trusted before we even talk to it?" by querying Layer 1 services rather than duplicating any identity/credential logic. See "Layer 2 Services" below.

Layer 3 implements dynamic access control: governance-signed policy administration, verified attribute gathering, default-deny ABAC/PBAC decisions, JIT VC authorization, signed enforcement tokens, and persistent decision auditing.

## What We Have Done

### 1) Built the full Layer 1 service mesh
- KMS service for key generation/signing through Vault
- DID Registry for DID creation and resolution
- Trust Anchor for issuer authorization and trust domain checks
- VC Issuance service for issuing credentials
- VC Verification service for presentation verification
- Status List service for revocation and blocklist flows
- Wallet service for secure storage and presentation building

### 2) Added core infrastructure
- Redis for cache, nonce, and blocklist data
- PostgreSQL for persistent data
- Kafka + Zookeeper for eventing and revocation audit streams
- Vault (dev mode) for key operations

### 3) Added orchestration and automation
- Docker Compose orchestration for all services
- Startup scripts:
  - start-docker.bat (Windows)
  - start-docker.sh (macOS/Linux)
- Integration test runners:
  - run-integration-tests.bat
  - run-integration-tests.sh

### 4) Added testing and delivery documentation
- Integration test suites and test utilities
- Service-level docs and orchestration guides
- Delivery summaries for SS6 and SS7

## Architecture (Running Services)

### Infrastructure
- redis: 6379
- postgres: 5432
- vault: 8200
- kafka: 9092
- zookeeper: 2181

### Layer 1 Trust + Credential Services
- kms: 8001
- did_registry: 8002
- trust_anchor: 8003
- vc_issuance: 8004
- vc_verification: 8005
- status_list_service: 8006
- wallet_service: 8007

### Layer 2 Discovery + Trust Establishment Services
- ans_registry_service: 8008 (persistent capability registry; DID-key proof required for registration and mutation)
- ans_resolver_service: 8009 (resolve by capability; verifies candidate VCs via `vc_verification` / `status_list_service`; signs responses via `kms`)
- discovery_trust_policy_service: 8010 (allowlist of trusted ANS registries/providers/namespaces; config-driven, no Layer 1 dependency)
- reputation_service: 8011 (issues Reputation VCs via `vc_issuance`; aggregates/returns reputation scores)
- discovery_gateway: 8012 (single external entry point: trust policy check -> ANS resolve -> reputation lookup -> signed unified response, handed to Layer 3)

Call order inside the gateway: `discovery_gateway` -> `discovery_trust_policy_service` -> `ans_resolver_service` -> `ans_registry_service`, with `reputation_service` consulted alongside. Registry, trust-policy, and reputation state is persisted in PostgreSQL. Resolver records are signed by KMS and cryptographically verified by the gateway before an endpoint is returned.

### Layer 3 Dynamic Access Control Services
- policy_administration_service: 8013 (PAP; signed, versioned policies and resources)
- policy_information_service: 8014 (PIP; DID, VP/VC, resource, and request attribute gathering)
- policy_decision_service: 8015 (PDP; ABAC/PBAC evaluation, deny-overrides, default deny)
- access_control_service: 8016 (PEP; signed decisions, scoped tokens, introspection, audit persistence)

### Executable Agents
- task_orchestrator: 8017 (API-key protected task submission; independently verifies discovery and dispatches signed tasks)
- risk_analyzer: 8018 (DID-authenticated financial-summary worker; signs input-derived results and blocks replay)

These use the project-specific `signed-http-json` transport, not an ACP implementation.
See [the orchestrator Swagger walkthrough](layer2_testing/README.md#taskorchestrator-and-running-agent)
and run `agent_testing/run_real_orchestrator_test.ps1` for the real discovery-to-execution test.

## Prerequisites

- Docker Desktop (Windows/macOS) or Docker Engine (Linux)
- Docker Compose
- Optional for local testing outside Docker:
  - Python 3.11+
  - pip

## How To Run This Layer Entirely

## Option A (Recommended): Run Entire Layer with Docker Compose

### Windows
```bash
cd c:\Users\Disha\Zero_trust-agentic-AI-Layer1
start-docker.bat
```

### macOS/Linux
```bash
cd /path/to/Zero_trust-agentic-AI-Layer1
chmod +x start-docker.sh
./start-docker.sh
```

### Manual (all platforms)
```bash
cd /path/to/Zero_trust-agentic-AI-Layer1
docker-compose up --build
```

Expected startup time: ~3 to 5 minutes.

## Verify Everything Is Up

```bash
docker-compose ps
```

Check health endpoints:

```bash
curl http://localhost:8001/health
curl http://localhost:8002/health
curl http://localhost:8003/health
curl http://localhost:8004/health
curl http://localhost:8005/health
curl http://localhost:8006/health
curl http://localhost:8007/health
curl http://localhost:8008/health
curl http://localhost:8009/health
curl http://localhost:8010/health
curl http://localhost:8011/health
curl http://localhost:8012/health
curl http://localhost:8013/health
curl http://localhost:8014/health
curl http://localhost:8015/health
curl http://localhost:8016/health
```

Quick end-to-end Layer 2 smoke test (once every service above is healthy) — register an agent, submit feedback, then discover it through the gateway. Note: `ans_registry_service` will only accept a registration whose `agentDid` actually resolves via `did_registry`, so create/register that DID in Layer 1 first, then substitute it below:

ANS registration requires a canonical record signature made by the key in the agent's DID document. The real full-stack script creates that proof and then exercises registration, discovery, attestation verification, reputation, semantic-version filtering, and resolver-signature verification.

Every service exposes interactive Swagger docs at `/docs`. See `layer2_testing/README.md` and `layer3_testing/README.md` for the real full-stack tests and request flows.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\layer2_testing\run_real_full_stack_test.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\layer3_testing\run_real_layer3_test.ps1
```

## Run Integration Tests

### Windows
```bash
run-integration-tests.bat
```

### macOS/Linux
```bash
chmod +x run-integration-tests.sh
./run-integration-tests.sh
```

## Stop the Full Layer

```bash
docker-compose down
```

To remove containers and volumes:

```bash
docker-compose down -v
```

## Option B: Run Services Locally (Advanced)

Use this only if you want to run services outside Docker.

1. Start dependencies first (Postgres, Redis, Kafka, Vault).
2. Install requirements for root and service folders.
3. Start each API service on its configured port.
4. Run tests.

For detailed local commands, refer to:
- DOCKER_COMPOSE_GUIDE.md
- DOCKER_ORCHESTRATION_SUMMARY.md
- INTEGRATION_TESTING_GUIDE.md

## Key Project Files

- docker-compose.yml
- Dockerfile.kms
- Dockerfile.did_registry
- Dockerfile.trust_anchor
- Dockerfile.vc_issuance
- status_list_service/Dockerfile
- verification_service/Dockerfile
- wallet_service/Dockerfile
- ans_registry_service/Dockerfile (Layer 2, Module 1)
- ans_resolver_service/Dockerfile (Layer 2, Module 2)
- discovery_trust_policy_service/Dockerfile (Layer 2, Module 3)
- reputation_service/Dockerfile (Layer 2, Module 4)
- discovery_gateway/Dockerfile (Layer 2, Module 5)
- start-docker.bat
- start-docker.sh
- run-integration-tests.bat
- run-integration-tests.sh

## Note on `layer2_testing/`

`layer2_testing/mock_layer1` is a lightweight stand-in for the Layer 1 endpoints (`did_registry`, `vc_verification`, `status_list_service`, `kms`, `vc_issuance`) that Layer 2 was originally built and tested against in isolation. Now that real Layer 1 services run in this same `docker-compose.yml`, the mock is no longer required for a full stack run — it's kept only for fast, dependency-free local iteration on Layer 2 modules alone. Point Layer 2's `*_URL` environment variables at the mock (see `layer2_testing/README.md`) if you want to develop Layer 2 without booting the full Layer 1 stack.

## Notes

- This repo currently uses development-friendly defaults.
- Before production use, rotate secrets, lock down network/security policy, and disable dev mode Vault settings.
