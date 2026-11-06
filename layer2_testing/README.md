# Testing Layer 2

There are two useful ways to test Layer 2, depending on whether the real
Layer 1 services are running.

## Option A: Isolated Test

This starts a lightweight mock Layer 1 plus all five real Layer 2 modules as
local processes. It exercises the discovery flow and tears everything down
automatically.

```bash
cd layer2_testing
pip install fastapi uvicorn pydantic httpx psycopg2-binary
bash run_integration_test.sh
```

Expected output: 13 `PASS` lines and `ALL TESTS PASSED` with exit code `0`.
Logs for each process are written to `/tmp/layer2_test_logs/`.

This proves:

1. ANS registry accepts resolvable DIDs and rejects unresolvable DIDs.
2. Reputation service records feedback, issues a reputation VC, and aggregates scores.
3. ANS resolver verifies required attestations through wallet and presentation verification.
4. ANS resolver drops a candidate whose attestation is revoked.
5. Discovery gateway applies trust policy, enriches reputation, ranks, and signs the response.

## Option B: Full Stack Test

Run the actual Layer 1 and Layer 2 services together:

```bash
docker compose up --build
```

Then, in a second terminal, run the real full-stack script:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\layer2_testing\run_real_full_stack_test.ps1
```

This script creates real KMS keys, real DID documents, a real trust-anchor
issuer authorization, a real Role VC, a real wallet entry, a real VP
verification, a DID-key-signed ANS registration, real reputation feedback,
semantic-version filtering, and a Discovery Gateway query that verifies the
resolver's Ed25519 record signature.

You can also test manually with a DID that exists in the real DID registry:

```bash
curl -X POST http://localhost:8008/register -H "Content-Type: application/json" -d '{
  "ansName": "acp://YourAgent.YourCapability.YourProvider.v1.0.0.prod",
  "agentDid": "did:web:your-real-registered-did",
  "capability": "YourCapability.SubDomain",
  "provider": "YourProvider",
  "version": "1.0.0",
  "serviceEndpoint": "https://your-agent.example.com/service"
}'

curl -X POST http://localhost:8011/feedback -H "Content-Type: application/json" -d '{
  "raterDid": "did:web:some-rater",
  "ratedAgentDid": "did:web:your-real-registered-did",
  "rating": 5,
  "issueVc": true
}'

curl -X POST http://localhost:8012/discover -H "Content-Type: application/json" -d '{
  "capability": "YourCapability.SubDomain"
}'
```

The real integration path validates the Layer 2 contracts with
`did_registry`, `wallet_service`, `vc_verification`, `kms`, and `vc_issuance`.
If KMS cannot sign a resolver or gateway response, discovery fails closed with
HTTP 502. Required attestations that fail verification remove that candidate.

## Manual Testing

Each module exposes FastAPI docs at `/docs`, for example:

```text
http://localhost:8012/docs
```

## TaskOrchestrator and Running Agent

The PDF's final discovery arrow now has an executable path:
TaskOrchestratorAgent -> Discovery Gateway -> ANS -> signed task -> RiskAnalyzerBot.
The orchestrator verifies the gateway signature, its request challenge, the complete
resolver-signed record, the discovery criteria, and the endpoint allowlist. It does
not rely only on the gateway's `signatureVerified` boolean. The worker authenticates
the caller DID, rejects expired/tampered/replayed requests, computes a financial
summary from submitted data, and signs its response. The orchestrator verifies that
response against the discovered DID and original request hash before reporting success.

## Run and Test

Start Docker Desktop and run from the repository root containing `docker-compose.yml`:

```powershell
docker compose up --build -d
powershell -NoProfile -ExecutionPolicy Bypass -File .\agent_testing\run_real_orchestrator_test.ps1
```

Expect `REAL ORCHESTRATOR END-TO-END TEST PASSED`. This also runs the existing real
Layer 1/2 test, provisions an accredited issuer, issues a RoleVC to the live worker,
and creates a signed ANS registration pointing at the actual worker container.
The test checks input-dependent results, task persistence, API authentication,
credential/version filtering, altered signatures, and replay at both agents.

To provision Swagger data without running the agent execution tests:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\agent_testing\prepare_orchestrator_demo.ps1
```

The preparation helper still runs the existing Layer 1/2 checks. It exports
`agent_testing/swagger_demo/00-identifiers.json` and `01-submit-task.json`.
It gives this run a unique capability suffix so old test registrations cannot win
the discovery ranking. The worker's actual supported calculation does not change.

## Swagger Steps

1. Open <http://localhost:8017/docs> (TaskOrchestratorAgent).
2. Open `agent_testing/runtime/orchestrator/operator-token.txt` locally. Click
   **Authorize** in Swagger and enter its contents as `X-API-Key`, without a Bearer
   prefix. This token is generated randomly by the service; keep it private.
3. Expand `POST /tasks`, click **Try it out**, and replace the example body with
   `agent_testing/swagger_demo/01-submit-task.json`. Execute.
4. Expect `status: "completed"`, both discovery signature flags `true`, and
   `agentResponseSignatureVerified: true`. The signed result contains total revenue
   `180000.00`, expenses `164000.00`, net income `16000.00`, and loss-making period
   `2026-Q2`. These are calculated from the supplied test inputs, not fixed responses.
5. Copy `taskId` into `GET /tasks/{task_id}` to inspect the persisted outcome.
6. Change Q1 revenue to `110000.00` and submit again without a `taskId`. Expect net
   income `26000.00`. Omitting `taskId` generates a new ID for each submission.
7. Set `taskId` to an already completed task ID and resubmit. Expect HTTP 409.
8. Remove `taskId`, set `requiredAttestations` to `["SOXComplianceCertified"]`, and
   submit. Expect HTTP 404 because the fixture has RoleVC, not a SOX credential.
9. Restore `["RoleVC"]`, set `versionRange` to `">=9.0.0,<10.0.0"`, and submit.
   Expect HTTP 404. Failed requests report their task ID for inspection.

The worker's Swagger is <http://localhost:8018/docs>, but its `POST /tasks` accepts
only signed agent messages. Normally call the orchestrator, not the worker directly.
The worker endpoint in ANS is `http://risk_analyzer:8018/tasks`, reachable from the
orchestrator container; do not replace that Docker hostname with browser localhost.

## Scope and Operations

- Protocol is **`signed-http-json`**, a project-specific signed request/response
  transport. This is not an ACP, MCP, or A2A compatibility claim.
- RiskAnalyzerBot is a deterministic financial-summary worker, not an LLM or a
  financial adviser. It computes supplied revenue/expenses; it does not query a
  sales database or external market API.
- This implements the Layer 2 discovery-to-agent interaction. It does not complete
  the outstanding Layer 3 protected-database integration or Layer 4 global sessions.
- Only the configured orchestrator DID may invoke the worker. The operator API uses
  a generated API key. Signing keys remain in KMS/Vault. The broader existing KMS,
  registry, and wallet APIs still need production authentication and network controls.
- The gateway and orchestrator pin trusted signing-key IDs. The orchestrator allows
  only exact configured endpoint URLs, disables redirects/proxy inheritance, and
  requires HTTPS unless explicitly enabled for local Docker development. Use trusted
  DNS, egress controls, TLS and per-service credentials for production.
- Task requests have a 60-second validity window. Journals and duplicate protection
  persist in `agent_testing/runtime/` SQLite files. Run one worker process per service;
  multi-worker/replicated task ownership is not implemented. Do not delete the journals
  to retry a task: a timeout may mean execution occurred without its result arriving.
- Development Vault is ephemeral. Service DIDs include their key fingerprint, so a
  Vault reset produces new identities. Rerun preparation after a reset. Expired or
  revoked wallet credentials must be retired before reusing a long-lived identity;
  the existing wallet selector does not yet filter them out. The operator token
  and task journals persist until explicitly removed.
- Both new host ports bind to localhost. Existing services retain their previous
  development port bindings. Generated tokens, journals, and Swagger fixtures are
  gitignored and must not be committed or shared.

Offline focused tests (no Docker needed; install the agent dependencies and pytest):

```powershell
python -m pytest agent_testing/test_agents.py -q
```

Stop testing without deleting volumes or local journals:

```powershell
docker compose stop
docker desktop stop
```

---

