"""Live orchestrator -> discovery -> worker -> Layer 3 -> SQL integration."""
import base64
import copy
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "layer3_testing"))
from enforcement_flow import api, admin, canonical, passed, seed, sign, write
from secure_client import call


def prepare(fixture):
    worker = api(8018, "/identity")
    orchestrator = api(8017, "/identity")
    agent = worker["did"]
    issuer = fixture["issuerDid"]
    document = api(8002, f"/dids/{agent}")["data"]["didDocument"]
    toolset = sorted(set(document.get("toolset", []) + [fixture["resource"]["resourceDid"]]))
    api(8002, f"/dids/{agent}", {"updates": {"toolset": toolset}, "authoritySignature": ""}, method="PUT")
    role = api(8004, "/issue/role", {
        "subject_did": agent, "issuer_did": issuer, "issuer_key_id": fixture["issuerKeyId"],
        "trust_domain": "enterprise", "claims": {"roleName": "RiskAnalyzer", "roleDescription": "Protected SQL analysis",
                                                 "organisationDID": "did:web:demo.local:finance"}})
    jit = api(8004, "/issue/jit", {
        "subject_did": agent, "issuer_did": issuer, "issuer_key_id": fixture["issuerKeyId"],
        "trust_domain": "enterprise", "claims": {"jobID": fixture["jobId"], "toolDID": fixture["resource"]["resourceDid"],
                                                "allowedAction": "QUERY_TABLE", "inputHandle": fixture["resource"]["resourceId"],
                                                "outputHandle": "task-result:" + fixture["jobId"]}})
    for credential in (role, jit):
        api(8007, f"/wallets/{agent}/store", {"agent_did": agent, "signed_vc": credential["signedVC"]})
    policy = copy.deepcopy(fixture["policy"])
    policy["version"] += 1
    policy["conditions"].append({"path": "request.context.requesterDid", "operator": "eq", "value": orchestrator["did"]})
    write(fixture, "policies", policy)
    seed(fixture)
    capability = worker["capability"] + ".Protected." + uuid.uuid4().hex
    record = {"ansName": "signed-http-json://RiskAnalyzer." + uuid.uuid4().hex, "agentDid": agent,
              "capability": capability, "provider": worker["provider"], "version": worker["version"],
              "serviceEndpoint": worker["serviceEndpoint"],
              "protocolExtensions": [{"protocol": worker["protocol"], "details": {"action": "analyze_financials"}}]}
    registration = {**record, "registrationProof": {
        "verificationMethod": worker["verificationMethod"],
        "signature": sign(worker["keyId"], {"action": "ans.register", "record": record})}}
    api(8008, "/register", registration, expected=201)
    submission = {"discovery": {"capability": capability, "provider": worker["provider"],
                                "protocol": worker["protocol"], "versionRange": ">=1.0.0,<2.0.0",
                                "requiredAttestations": ["RoleVC"], "maxCandidates": 10},
                  "input": {"source": "protected-sales", "resourceId": fixture["resource"]["resourceId"],
                            "jobId": fixture["jobId"], "credentialIds": [role["vc_id"], jit["vc_id"]],
                            "currency": "USD", "period": None, "limit": 100}}
    fixture.update(worker=worker, orchestrator=orchestrator, policy=policy, jitVcId=jit["vc_id"])
    destination = ROOT / "agent_testing" / "swagger_demo"
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "02-protected-task.json").write_text(json.dumps(submission, indent=2), encoding="utf-8")
    (destination / "03-protected-identifiers.json").write_text(json.dumps({
        "workerDid": agent, "orchestratorDid": orchestrator["did"], "resourceId": fixture["resource"]["resourceId"],
        "jobId": fixture["jobId"], "jitVcId": jit["vc_id"], "jitExpiresAt": jit["signedVC"]["expirationDate"],
        "operatorTokenFile": "agent_testing/runtime/orchestrator/operator-token.txt"}, indent=2), encoding="utf-8")
    return submission


def operator_headers():
    path = ROOT / "agent_testing" / "runtime" / "orchestrator" / "operator-token.txt"
    return {"X-API-Key": path.read_text().strip()}


def submit(submission, expected=200):
    body = {**copy.deepcopy(submission), "taskId": str(uuid.uuid4())}
    result = api(8017, "/tasks", body, expected=expected, headers=operator_headers())
    return body, result


def test(fixture, submission):
    body, result = submit(submission)
    analysis = result["agentResponse"]["result"]
    assert result["agentResponseSignatureVerified"] and result["discovery"]["ansRecordSignatureVerified"]
    assert analysis["totalRevenue"] == "530000.00" and analysis["netIncome"] == "165000.00", analysis
    assert analysis["dataAccess"]["rowCount"] == 2 and analysis["dataAccess"]["datasetVersion"] == 1
    audit = api(8016, "/audit/" + analysis["dataAccess"]["decisionId"])
    assert audit["agentDid"] == fixture["worker"]["did"] and audit["effect"] == "permit"
    assert "accessToken" not in json.dumps(result) and "vpJwt" not in json.dumps(result)
    passed("discovered worker obtains Layer 3 permit, queries real SQL, signs result; orchestrator verifies it")
    api(8017, "/tasks", body, expected=409, headers=operator_headers())
    passed("integrated task replay rejected")
    saved = api(8017, "/tasks/" + body["taskId"], headers=operator_headers())
    assert saved["status"] == "completed"
    passed("completed protected task can be retrieved without re-execution")

    wrong_job = copy.deepcopy(submission)
    wrong_job["input"]["jobId"] += "-wrong"
    rejected, _ = submit(wrong_job, expected=403)
    assert api(8017, "/tasks/" + rejected["taskId"], headers=operator_headers())["status"] == "failed"
    passed("job not authorized by JIT denied and stored as failed")

    # Show the worker reads the database on each new task, not the earlier example input.
    dataset = {"resourceId": fixture["resource"]["resourceId"], "version": 2,
               "rows": [{"period": "2026-Q1", "currency": "USD", "revenue": "260000.00", "expenses": "175000.00"},
                        {"period": "2026-Q2", "currency": "USD", "revenue": "280000.00", "expenses": "190000.00"}]}
    api(8019, "/datasets", {"dataset": dataset, "adminAuthorization": admin(fixture, {
        "action": "sales.upsertDataset", "dataset": dataset})}, expected=201)
    _, updated = submit(submission)
    assert updated["agentResponse"]["result"]["netIncome"] == "175000.00"
    assert updated["agentResponse"]["result"]["dataAccess"]["datasetVersion"] == 2
    passed("changed SQL data changes the computed result on the next task")

    filtered = copy.deepcopy(submission)
    filtered["input"]["period"] = "2026-Q2"
    _, result = submit(filtered)
    assert result["agentResponse"]["result"]["netIncome"] == "90000.00"
    assert result["agentResponse"]["result"]["dataAccess"]["rowCount"] == 1
    passed("database filters propagate through orchestration")

    fixture["policy"]["version"] += 1
    fixture["policy"]["active"] = False
    write(fixture, "policies", fixture["policy"])
    submit(submission, expected=403)
    passed("disabled Layer 3 policy blocks a newly orchestrated task")
    fixture["policy"]["version"] += 1
    fixture["policy"]["active"] = True
    write(fixture, "policies", fixture["policy"])

    api(8006, "/status-lists/revoke", {"vc_id": fixture["jitVcId"], "reason": "Integrated agent regression test",
                                     "authority_did": fixture["issuerDid"]})
    submit(submission, expected=403)
    passed("revoked JIT blocks orchestrated execution without falling back to inline input")
    print("REAL PROTECTED ORCHESTRATOR TEST PASSED", flush=True)


if __name__ == "__main__":
    fixture = json.loads(base64.b64decode(sys.argv[1]))
    submission = prepare(fixture)
    if "--prepare-only" in sys.argv:
        print("PROTECTED ORCHESTRATOR SWAGGER READY: agent_testing/swagger_demo/02-protected-task.json")
    else:
        test(fixture, submission)
