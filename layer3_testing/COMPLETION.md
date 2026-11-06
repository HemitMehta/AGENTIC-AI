# Layer 3 Scope and Acceptance

Scope is the **Dynamic Access Control Layer** on PDF pages 6-7, demonstrated
by the financial-data and temporary-access examples on pages 9-10. Completion
here means working application behavior and repeatable acceptance tests for
this scope. It does not mean production certification or a guarantee that
future changes cannot introduce defects.

## Requirements Mapped to Code

| PDF requirement | Implementation | Acceptance evidence |
| --- | --- | --- |
| PDP evaluates identity, credentials, resource, action, context | `policy_decision_service/main.py`, `layer3_common/policy.py` | Permit, default deny, explicit-deny precedence, invalid-policy rejection |
| PAP administers policies | `policy_administration_service/main.py` | Authorized DID signatures, tampering rejection, monotonic versions, history |
| PIP gathers verified attributes | `policy_information_service/main.py` | Active holder/issuer DIDs, VP challenge, fresh VC status, expiry, resource identity |
| ABAC and policy-based authorization | Typed JSON policies, selectors, conditions, credential-specific array predicates | Role/action/resource/job/toolset checks; boolean/numeric confusion rejected |
| Context-aware decisions | Server UTC clock and authenticated service/network context | Caller context cannot replace server context; current network origin rechecked |
| Temporary scoped JIT credentials | Existing real Layer 1 issuance/wallet/verification integrated into PIP/PEP | Grant lifetime bounded by evidence; wrong job/action/resource and revoked JIT denied |
| Enforcement example | `access_control_service` and `protected_sales_service` | Real parameterized SQL, proof of possession, single-use request, persisted grants |
| Discovery-to-protected-data example | TaskOrchestrator and RiskAnalyzer | Signed discovery/task/result; actual database-derived result; policy/JIT denial |
| Operational audit | PAP, PEP, sales transactional event chains | Administrative signatures retained; decisions/revocations/queries linked; mutation guards |

The PDF says policies can be defined *e.g.* in Rego/OPA. This implementation
uses its existing validated JSON policy language, not an OPA server. It does
not claim Rego, ACP, A2A, or MCP wire-protocol compatibility.

## Run the Complete Acceptance Suite

1. Start Docker Desktop and wait for the engine to be ready.
2. Open PowerShell in the inner repository directory containing
   `docker-compose.yml`. Python and the project's test dependencies must be
   installed; `python -m pytest --version` should work.
3. Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\layer3_testing\run_complete_layer3.ps1
```

The command builds/starts the real services, runs focused regression tests,
exercises authorization and SQL including restarts/outages/revocation, and
then exercises the complete protected TaskOrchestrator flow. It returns a
nonzero exit code on failure. Expect the final line `LAYER 3 ACCEPTANCE PASSED`.

Results are saved under `layer3_testing/runtime/`:

- `acceptance-report.json`: status, completed groups, timestamps, source hashes.
- `offline-tests.log`: focused security/agent regressions.
- `enforcement-tests.log`: real Layer 3 and database enforcement.
- `orchestrator-tests.log`: real discovery-to-database orchestration.

By default it stops this project's containers, preserving databases and keys.
It does not stop unrelated containers or close Docker Desktop. Add
`-LeaveRunning` for interactive Swagger afterwards. `-SkipBuild` is only for
an already running stack whose images match the source.

Tests create synthetic financial rows in real PostgreSQL, issue real local
credentials, and deliberately revoke their own test JIT credentials. They
also briefly stop services. Run only on a dedicated development stack.

For fresh Swagger data, run the following after starting the stack:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\agent_testing\run_protected_orchestrator_test.ps1 -PrepareOnly
Get-Content .\agent_testing\runtime\orchestrator\operator-token.txt
```

Open `http://localhost:8017/docs`, authorize with that operator token, then
submit `agent_testing/swagger_demo/02-protected-task.json` to `POST /tasks`.
The expected net income is `165000.00`, calculated from the prepared database
rows. See [README.md](README.md) for direct Layer 3 Swagger steps.

## Policy Semantics

- Missing attributes deny except an explicit `exists: false` condition.
- JSON booleans are not interchangeable with numeric `0`/`1`.
- `gte`/`lte` compare finite numbers, not strings. Use server
  `environment.unixTime`, `utcHour`, and `utcWeekday` for numeric time rules.
- `any` and `all` apply their list of conditions to each element of an array.
  Empty arrays match neither operator. All conditions inside one `any` must
  match the **same element**.
- `$.` addresses the root attribute document inside a nested predicate.
- `agent.credentials` contains verified per-credential type, issuer, subject,
  ID and expiry, preserving their association. `agent.claims` remains the
  backward-compatible merged view; conflicting values are rejected.
- `request.context` is caller-supplied business context. Bind jobs and handles
  to signed credential claims; do not treat it as verified network/device data.
- `environment.sourceIp` is the actual peer observed by PEP initially and by
  the authenticated resource adapter on use. Forwarded HTTP headers are not
  trusted. `environment.callerService` identifies the grant-requesting service,
  not the agent DID or an end user's device. Additional device posture or
  geographic evidence needs an authenticated attribute source.
- `ip_in_cidr` validates IPv4/IPv6 membership. A malformed policy set denies
  access as a whole, including when the malformed policy is a deny rule.

Example additional condition, with the expected issuer supplied by your
governance configuration:

```json
{
  "path": "agent.credentials",
  "operator": "any",
  "value": [
    {"path": "type", "operator": "contains", "value": "JITVC"},
    {"path": "credentialSubject.jobID", "operator": "equals_path", "value": "$.request.context.jobId"}
  ]
}
```

## Governance and Audit Inspection

All routes require the existing service authentication. In Swagger use the
operator credentials described in README; do not paste secrets into policies.

| Service | Routes |
| --- | --- |
| PAP, HTTPS 8013 | `/history/policies?policyId=...`, `/history/resources?resourceId=...`, `/governance/events`, `/governance/integrity` |
| PEP, HTTPS 8016 | `/audit?agentDid=...`, `/audit/{decision_id}`, `/audit/events`, `/audit/integrity` |
| Sales, HTTPS 8019 | `/audit/events`, `/audit/integrity` |

Event pagination uses `after=<last sequence>` and `limit`. Policy history
uses `beforeVersion`; decision history uses `before`. Histories retain the
original signed policy, while `currently_active` reports current activation.
`GET /policies?active=false` correctly reports inactive historical versions.
Resource history/signature retention starts with writes after this update;
older overwritten resource versions cannot be reconstructed.

Audit events are transactional, hash-linked, and protected against ordinary
UPDATE/DELETE/TRUNCATE operations. Decisions remain signed. Query audits
record IDs, dataset version and row count, never bearer tokens or returned
financial rows. Grant evidence remains encrypted outside audit records.
Integrity checks detect broken links/content changes, but cannot prove the
absence of a deleted tail without an externally retained checkpoint. A
database owner/superuser can disable guards. Export event heads and records
to independently controlled append-only storage for production assurance.

## Separate Work, Not Layer 3 Completion Claims

- Layer 4 global sessions, cross-protocol adapters, global logout, push
  invalidation and in-flight cancellation are a separate PDF layer.
- The running example uses the existing `signed-http-json` agent protocol and
  one protected SQL adapter. Every additional real tool must enforce access
  through its own adapter; no generic authorization service can protect an
  uninstrumented external API automatically.
- The wider stack still has development Vault and legacy Layer 1/2 HTTP and
  open administrative/signing interfaces. Those are **real production
  security blockers**, not something these tests certify as safe. Before
  deployment, harden those upstreams, use durable restricted KMS/Vault,
  network isolation, managed credentials, tested backups and external audit
  storage, and perform security/load reviews.
- Back up `layer3_data` with `layer3_testing/runtime/security`. Existing legacy
  Layer 3 tables are retained but not migrated into active grants. Reissue
  development fixtures instead of activating unverifiable old grants.

This document supersedes earlier blanket claims that the whole platform is
production-ready. Acceptance proves the listed functional/security cases on
the local stack, not every possible deployment or adversarial condition.
