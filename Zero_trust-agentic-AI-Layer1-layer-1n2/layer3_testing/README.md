# Testing Layer 3

For the PDF scope, completed capabilities, remaining deployment boundaries,
and the **single-command full acceptance suite**, start with
[COMPLETION.md](COMPLETION.md).

Layer 3 implements the PDF's Dynamic Access Control Layer with four control services and a protected SQL API:

- PAP (`8013`): versioned policies and resource attributes in PostgreSQL; writes require a governance-admin DID signature.
- PIP (`8014`): resolves the requesting DID, verifies its VP through Layer 1's six-step pipeline, and gathers resource attributes.
- PDP (`8015`): evaluates stored ABAC/PBAC policies with default deny and deny-overrides.
- PEP (`8016`): signs decisions, encrypts grant evidence, and revalidates existing tokens against current credentials, DIDs, policies, and resources.
- Protected sales API (`8019`): requires an active token plus an agent-signed, single-use request before executing parameterized SQL.


## New security setup

Ports 8013-8016 and 8019 now use **HTTPS**, not HTTP. Docker generates a local
CA, distinct service tokens, database passwords, and an evidence-encryption
key under `layer3_testing/runtime/security/`. Never commit or share that
directory. Back it up together with the `layer3_data` database volume.
Deleting the security directory while keeping the database will break access
to existing data; credentials are deliberately not silently reset.

The test client explicitly trusts only the generated local CA for Layer 3.
For browser Swagger on this trusted local development machine, inspect and
optionally trust that CA in your Windows **CurrentUser** certificate store:

```powershell
Import-Certificate -FilePath .\layer3_testing\runtime\security\ca.crt -CertStoreLocation Cert:\CurrentUser\Root
Get-Content .\layer3_testing\runtime\security\operator\client.key
```

In Swagger's **Authorize** dialog on ports 8013-8016, fill:
- `ServiceId`: `operator`
- `ServiceToken`: the generated value from the command above.

This account is privileged local test administration. PAP writes additionally
require the governance DID signature. Revalidation-only endpoints are internal
and reject the operator account. Do not disable TLS validation globally.

The isolated PostgreSQL instance has no published host port. PAP, PEP, and sales
have distinct roles and schemas; sales credentials cannot read private PEP
grant evidence. Old Layer 3 tables in the original `postgres_data` volume are
preserved, but are not automatically activated in this new database. Rerun the
fixture helper to create fresh signed resources and policies. Historical
pre-update access tokens cannot be used as persisted grants.

Local certificates renew near expiry when the provisioning service runs.
Restart the Layer 3 services after renewal so they load the new certificates.

## Full enforcement regression

### Integrated TaskOrchestrator and Layer 3

The running TaskOrchestrator now discovers RiskAnalyzer, verifies discovery,
sends a signed protected-data task, and verifies the signed financial result.
RiskAnalyzer selects the task's specific wallet credentials, obtains a fresh
VP and Layer 3 grant, verifies the PEP signature and scope, then signs a request
to the HTTPS-protected SQL API. No bearer token is stored in either task journal.

From the repository folder containing `docker-compose.yml`:

```powershell
docker compose up -d --build
powershell -NoProfile -ExecutionPolicy Bypass -File .\agent_testing\run_protected_orchestrator_test.ps1
```

Expect `REAL PROTECTED ORCHESTRATOR TEST PASSED`. It covers discovery,
authorization, database-derived results, changed database contents, query filters,
task replay, wrong job, disabled policy, and revoked JIT credentials. It uses
fresh synthetic sales data in the real database, not canned financial responses.
The negative test deliberately revokes its own JIT credential.

For fresh, non-revoked Swagger test data:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\agent_testing\run_protected_orchestrator_test.ps1 -PrepareOnly
Get-Content .\agent_testing\runtime\orchestrator\operator-token.txt
```

Open <http://localhost:8017/docs>, authorize **X-API-Key** with that operator
token, and submit `agent_testing/swagger_demo/02-protected-task.json` to
`POST /tasks`. The request names a resource, job, currency, and credential IDs;
it does not contain revenues or expenses. Expected net income is `165000.00`.
Inspect `agentResponse.result.dataAccess` for the PEP decision ID, dataset
version, and row count. Retrieve the saved result through `GET /tasks/{task_id}`.
The body omits taskId so Swagger can create a new task on each submission.

The old inline-period mode remains available, but it is not a database request
and does not claim Layer 3 authorization. Protected-data tasks never fall back
to it. Agent transport is still the existing local `signed-http-json` protocol;
it is not ACP/A2A compliance or production hardening of the legacy upstreams.

### Standalone Layer 3 Enforcement

```powershell
docker compose up -d --build
powershell -NoProfile -ExecutionPolicy Bypass -File .\layer3_testing\run_enforcement_test.ps1
python -m pytest layer3_testing/test_security.py agent_testing/test_agents.py -q
```

Expect `REAL LAYER 3 ENFORCEMENT TEST PASSED`. This includes the earlier
permit/deny test, then real SQL reads, signed-request tampering and replay,
SQL filter injection, scope enforcement, audit redaction, restart persistence,
explicit grant revocation, policy version rollback, policy/resource disable,
dependency failure/recovery, DID suspension, and immediate JIT revocation.
The script temporarily stops/restarts test services and revokes only the fresh
credentials it creates. Do not run it against a shared deployment.

## Swagger: read the real protected database

1. Run `prepare_swagger_demo.ps1` as described below. It also inserts two
   synthetic quarterly sales rows into the real PostgreSQL database.
2. Open <https://localhost:8019/docs>.
3. Run `python layer3_testing/prepare_protected_query.py`. It obtains a fresh
   nonce and VP, requests a PEP grant, and signs the database request with
   this run's agent key through KMS.
4. Open `swagger_demo/14-query-grant.json`. In Swagger's **Authorize** dialog,
   put its `accessToken` in **HTTPBearer**, without the word `Bearer`.
   The query endpoint does not require operator service credentials.
5. Within **60 seconds**, execute `POST /query` with the entire body from
   `swagger_demo/13-protected-query.json`.
6. Expect two rows, including Q1 revenue `250000.00` and expenses `175000.00`.
   These are test data read from SQL, not canned API responses.
7. Resubmit the exact same request: expect **409** (replay). Generate a fresh
   request, alter `limit` without re-signing, and expect **403** (tampering).
8. Run the helper again whenever you need a new proof/token. For manually
   obtained tokens, use `enforcement_flow.query_body(fixture, token)` to sign
   the same payload rather than editing the signed JSON.

A grant lasts at most 120 seconds and never beyond its credential/VP expiry.
Each database request rechecks current authorization. Policy/resource version
changes require a new grant. Revocation blocks the next request; this is not
an implementation of Layer 4 continuous monitoring or in-flight query cancellation.

## Deployment boundary

This is a real local enforcement implementation, **not a production-ready
security certification**. The wider repository still uses development Vault,
legacy Layer 1/2 HTTP services, and unprotected signing/registry/revocation
administration. Those upstream services are trusted dependencies of Layer 3.
Production requires authenticated/TLS-protected upstreams, restricted KMS
signing permissions, durable production Vault, managed secret/certificate
rotation, network isolation, backup/recovery, and load/security testing.

The protected service is a read-only adapter for the registered
`financial-database / Sales / QuarterlySummaries / QUERY_TABLE` resource.
It is not an arbitrary SQL proxy or automatic enforcement for every external
tool. Each additional tool needs its own enforcing adapter.

New issuance now persists the credential-to-status-bit mapping used by
revocation. Credentials issued before this fix may lack that mapping; reissue
those development fixtures rather than claiming their revocation was tested.

## Real end-to-end test

Start Docker Desktop, then run from the repository root:

```powershell
docker compose up --build -d
powershell -NoProfile -ExecutionPolicy Bypass -File .\layer3_testing\run_real_layer3_test.ps1
```

Expected final line:

```text
REAL LAYER 3 END-TO-END TEST PASSED
```

The script creates fresh KMS keys and DIDs, accredits an issuer through a signed governance operation, issues real RoleVC and JITVC credentials, stores them in the wallet, installs a signed resource and policy, and then tests:

1. Tampered governance data is rejected.
2. A valid VP passes all six Layer 1 verification stages.
3. Role, tool, action, job, resource, and DID toolset attributes produce a permit.
4. The PEP returns a signed, expiring token scoped to one resource and action.
5. A scope mismatch is rejected.
6. The signed decision is persisted in the audit database.
7. A context job ID not bound to the JIT VC receives default deny and no token.

Interactive API documentation is available at:

- `https://localhost:8013/docs`
- `https://localhost:8014/docs`
- `https://localhost:8015/docs`
- `https://localhost:8016/docs`

Stop the stack without deleting data:

```powershell
docker compose down
```

## Swagger walkthrough: discovery to access decision

This exercise uses the real local KMS, DID registry, trust anchor, issuance,
wallet, verification, ANS, and access-control services, not `mock_layer1`.
The signed credentials, presentations, decisions, and tokens are generated
by those services. The example organisation, model/AIBOM metadata, sales
resource, input/output handles, and ANS endpoint are test fixtures. There is
no running financial agent or sales database behind the example endpoint.
This is a local integration test, not a production-security certification.

### 1. Prepare fresh test data

Start Docker Desktop. In PowerShell, enter the inner repository folder
containing `docker-compose.yml`, then run:

```powershell
docker compose up --build -d
python --version
powershell -NoProfile -ExecutionPolicy Bypass -File .\layer3_testing\prepare_swagger_demo.ps1
```

Wait for `SWAGGER DEMO READY`. This helper automates the setup: it creates
issuer/agent keys and DIDs, accredits the issuer with the governance-admin
signature, issues and stores RoleVC and JITVC, installs a signed resource
and policy, tests permit/deny, and signs the same agent's ANS registration.
It then writes ready-to-paste request bodies into
`layer3_testing/swagger_demo/`. Setup is performed through service APIs;
the following interactive steps are the part you execute in Swagger.

Open `00-identifiers.json`. Its `agentDid`, `resourceId`, and `jobId` belong
to this run. The other JSON files already contain those exact identifiers.
Only `REPLACE_WITH_*` fields require values from your Swagger responses.
In Swagger, expand the endpoint, click **Try it out**, replace the entire
example request body with the indicated file's contents, and click **Execute**.
Read **Server response / Response body**, not the static Example Value.

The JIT credential normally lasts **15 minutes**. Check `jitExpiresAt` in
`00-identifiers.json`. Rerun the helper when expired or after recreating the
development Vault. Each run creates new test records and replaces the local
JSON files; never mix identifiers from different runs. Keep this dev stack
private: its bootstrap credentials and exposed signing APIs are not a
production deployment configuration.

### 2. Inspect the Layer 1 identity and credentials

1. Open <http://localhost:8002/docs>, execute `GET /dids/{did_id}` with
   `agentDid` from `00-identifiers.json`. Expect a DID document whose
   `toolset` includes this run's `resourceDid`.
2. Open <http://localhost:8003/docs>, execute `POST /trust-anchor/validate`
   with `09-validate-issuer.json`. Expect `authorised: true`. Change
   `credentialType` to `JITVC` and repeat; expect `true` again.
3. Open <http://localhost:8007/docs>, execute
   `GET /wallets/{did}/credentials` with that same `agentDid` as `did`.
   Leave optional type/issuer filters empty. Expect RoleVC and JITVC entries.
4. Open <https://localhost:8013/docs>, execute `GET /resources/{resource_id}`
   with `resourceId`. Expect sensitivity `High`, schema `Sales`, and table
   `QuarterlySummaries`. `GET /policies` includes `financial-jit-<run ID>`.

### 3. Discover the agent through Layer 2

Open <http://localhost:8012/docs>, execute `POST /discover` with
`01-discover.json`. Expect:

```json
{
  "resolutionStatus": "success",
  "selectedAgent": "<the agentDid in 00-identifiers.json>",
  "candidates": [{ "signatureVerified": true }]
}
```

This is an abbreviated response, not a request body. The returned endpoint
uses `example.invalid` intentionally; discovery returns directory metadata
and does not establish a network connection to a financial agent. Requiring
`RoleVC` exercises credential verification during discovery. This fixture
does not issue a SOX-compliance credential, so do not expect the PDF's
`SOXComplianceCertified` attestation to match it.

### 4. Obtain a fresh verifier challenge

Open <http://localhost:8005/docs>, execute `POST /verify/nonce` with
`02-nonce.json`. Copy the response's `nonce` string. The verifier must stay
`did:web:layer3:pdp`. Complete steps 5 and 6 within **five minutes**.

### 5. Build a signed presentation from the wallet

Open <http://localhost:8007/docs>, expand
`POST /wallets/{did}/present`. Set the path's `did` to the value
in `00-identifiers.json`. Paste `03-present.json`; replace
`REPLACE_WITH_NONCE` with step 4's nonce. Execute and copy `vp_jwt` from the
response. Leave the string unchanged, without adding another set of quotes.

### 6. Request access through Layer 3

Open <https://localhost:8016/docs>, execute `POST /access/check` with
`04-permit.json`. Replace `REPLACE_WITH_NONCE` with step 4's nonce and
`REPLACE_WITH_VP_JWT` with step 5's `vp_jwt`.

Expect `effect: "permit"`, a nonempty `accessToken`, a `decisionId`, and
`matchedPolicies` referencing this run's policy. Save the token and decision
ID for the next steps. This call goes through PEP -> PDP -> PIP -> Layer 1
verification and checks the stored resource/policy. You do not need to call
PIP or PDP separately.

**Do not call `/verify/presentation`, `/attributes/collect`, or `/decisions`
with this same VP before step 6.** They consume the nonce. A consumed nonce
cannot be reused for an access decision. HTTP 200 alone is not a permit:
always inspect `effect` and `accessToken`.

### 7. Check the scoped access token and audit record

Within **120 seconds** of step 6, use <https://localhost:8016/docs>:

1. Execute `POST /access/introspect` with `05-introspect.json`, replacing
   `REPLACE_WITH_ACCESS_TOKEN`. Expect `active: true` and claims bound to
   your agent, resource, and `QUERY_TABLE` action.
2. In that same request change only `action` to `DELETE_TABLE`. Expect
   `active: false`, reason `action scope mismatch`.
3. Restore `QUERY_TABLE`, but change `resourceId` to `not-this-resource`.
   Expect `active: false`, reason `resource scope mismatch`.
4. Execute `GET /audit/{decision_id}` with step 6's `decisionId`. Expect
   the stored decision and signature. The audit remains after token expiry.

These decision/introspection endpoints do not execute SQL. The protected SQL walkthrough below exercises actual database access.

### 8. Test rejection paths

| Test | What to submit | Expected result |
| --- | --- | --- |
| Wrong job | Repeat steps 4-5 for a fresh nonce and VP. Use `06-deny-job.json` at `/access/check`, replacing both placeholders. | `effect: "deny"`, `accessToken: null` |
| Wrong action | Repeat steps 4-5 again. Use `07-deny-action.json` at `/access/check`. | `effect: "deny"`, `accessToken: null` |
| Replay | Immediately resubmit the exact already-executed permit request, including its old nonce and VP. Do not obtain a fresh nonce for this test. | `effect: "deny"`, no token; nonce/replay verification failure |
| Token expiry | After its 120-second lifetime, introspect the original token with the original resource/action. | `active: false`, reason `token expired` |

For a standalone Layer 1 verification test, repeat steps 4-5 using a fresh
nonce/VP. Submit `08-verify-presentation.json` at port 8005's
`POST /verify/presentation`, replacing both placeholders. Expect
`valid: true`. That VP/nonce is now consumed; obtain another pair for Layer 3.

### 9. Optional: test signed governance writes

The helper exports signed, **not yet submitted** version-2 updates. At
<https://localhost:8013/docs>:

1. Paste `10-resource-update.json` into `POST /resources`. Change only
   `resource.attributes.dataSensitivity` from `High` to `Low`, leaving
   the signature unchanged. Expect HTTP **403** for a tampered signature.
2. Paste the original unmodified file again and execute. Expect HTTP **201**,
   `status: "stored"`, resource version **2**. Submit it again to see HTTP
   **409**, because a resource version must increase.
3. Submit unmodified `11-policy-update.json` to `POST /policies`. Expect
   HTTP **201**, `status: "stored"`, policy version **2**. Repeating it
   returns HTTP **409**. It keeps the same permit conditions.

Do not hand-edit signed payloads for a successful write: the canonical
payload must be signed again. This is why the helper generates these
signatures instead of asking you to invent them in Swagger.

### Troubleshooting

- **422**: inspect the validation error; paste the full correct JSON body,
  and keep `agent_did`/`vp_jwt` for wallet/verification versus
  `agentDid`/`vpJwt` for Layer 3. Replace all `REPLACE_WITH_*` strings.
- **Deny after an earlier successful verification**: the nonce was consumed.
  Repeat steps 4-5 before retrying access.
- **Expired VC**: rerun the preparation helper and use only its new files.
- **Expired token**: repeat steps 4-6, then introspect immediately.
- **502 or unreachable service**: run `docker compose ps` and inspect
  `docker compose logs --tail=100 access_control_service policy_decision_service policy_information_service vc_verification`.
