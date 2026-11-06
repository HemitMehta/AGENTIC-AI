"""Real API/database enforcement checks. Run through run_enforcement_test.ps1."""
import base64
import copy
import hashlib
import json
import subprocess
import sys
import time
import uuid
from pathlib import Path

from secure_client import call

BASE = "http://127.0.0.1"
ROOT = Path(__file__).resolve().parents[1]


def api(port, path, body=None, method=None, expected=200, **kwargs):
    status, result = call(method or ("POST" if body is not None else "GET"), f"{BASE}:{port}{path}", body, **kwargs)
    assert status == expected, f"{port}{path}: expected {expected}, got {status}: {result}"
    return result


def passed(label):
    print("PASS: " + label, flush=True)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sign(key_id, payload):
    return api(8001, f"/keys/{key_id}/sign", {"payload": base64.b64encode(canonical(payload)).decode()})["signature"]


def admin(fixture, payload):
    return {"adminDID": fixture["adminDid"], "verificationMethod": fixture["adminDid"] + "#" + fixture["adminKeyId"],
            "signature": sign(fixture["adminKeyId"], payload)}


def write(fixture, kind, value, expected=201):
    action, singular = ("pap.upsertResource", "resource") if kind == "resources" else ("pap.upsertPolicy", "policy")
    return api(8013, "/" + kind, {singular: value, "adminAuthorization": admin(fixture, {"action": action, singular: value})},
               expected=expected)


def grant(fixture):
    nonce = api(8005, "/verify/nonce", {"verifierDID": "did:web:layer3:pdp", "purpose": "enforcement_test"})["nonce"]
    vp = api(8007, f"/wallets/{fixture['agentDid']}/present",
             {"agent_did": fixture["agentDid"], "required_types": ["RoleVC", "JITVC"],
              "verifier_did": "did:web:layer3:pdp", "nonce": nonce})["vp_jwt"]
    result = api(8016, "/access/check", {"agentDid": fixture["agentDid"], "vpJwt": vp, "nonce": nonce,
                                       "resourceId": fixture["resource"]["resourceId"], "action": "QUERY_TABLE",
                                       "context": {"jobId": fixture["jobId"]}})
    assert result["effect"] == "permit", result
    return result


def introspect(fixture, token):
    return api(8016, "/access/introspect", {"token": token, "resourceId": fixture["resource"]["resourceId"],
                                         "action": "QUERY_TABLE"})


def query_body(fixture, token, **overrides):
    now = int(time.time())
    payload = {"resourceId": fixture["resource"]["resourceId"], "agentDid": fixture["agentDid"],
               "requestId": str(uuid.uuid4()), "issuedAt": now, "expiresAt": now + 60,
               "tokenHash": hashlib.sha256(token.encode()).hexdigest(), "period": None, "currency": None, "limit": 100,
               **overrides}
    return {**payload, "proof": {"verificationMethod": fixture["agentDid"] + "#" + fixture["agentKeyId"],
                                "signature": sign(fixture["agentKeyId"], {"action": "sales.query", **payload})}}


def query(fixture, token, body=None, expected=200):
    return api(8019, "/query", body or query_body(fixture, token), expected=expected, authenticated=False,
               headers={"Authorization": "Bearer " + token})


def seed(fixture):
    dataset = {"resourceId": fixture["resource"]["resourceId"], "version": 1,
               "rows": [{"period": "2026-Q1", "currency": "USD", "revenue": "250000.00", "expenses": "175000.00"},
                        {"period": "2026-Q2", "currency": "USD", "revenue": "280000.00", "expenses": "190000.00"}]}
    api(8019, "/datasets", {"dataset": dataset,
                           "adminAuthorization": admin(fixture, {"action": "sales.upsertDataset", "dataset": dataset})},
        expected=201)


def compose(*args):
    subprocess.run(["docker", "compose", *args], cwd=ROOT, check=True, capture_output=True)


def wait(port):
    for _ in range(60):
        try:
            api(port, "/health")
            return
        except Exception:
            time.sleep(1)
    raise AssertionError(f"Service on {port} failed to recover")


def database_checks(fixture):
    code = '''
import sys
import psycopg2
from protected_sales_service.main import _db
resource = sys.argv[1]
with _db() as conn, conn.cursor() as cur:
    cur.execute("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()")
    assert cur.fetchone()["ssl"]
for statement in ("UPDATE layer3_security_events SET event=event WHERE FALSE",
                  "DELETE FROM layer3_security_events WHERE FALSE",
                  "TRUNCATE layer3_security_events"):
    conn = _db()
    try:
        with conn.cursor() as cur:
            cur.execute(statement)
        raise AssertionError("Audit mutation was allowed")
    except psycopg2.errors.RaiseException:
        pass
    finally:
        conn.rollback()
        conn.close()
conn = _db()
try:
    with conn.cursor() as cur:
        cur.execute("SELECT * FROM pep.layer3_grants LIMIT 1")
    raise AssertionError("Sales role read PEP credential evidence")
except psycopg2.errors.InsufficientPrivilege:
    pass
finally:
    conn.rollback()
    conn.close()
first, second = _db(), _db()
try:
    with first.cursor() as cur:
        cur.execute("SELECT version FROM sales_datasets WHERE resource_id=%s FOR SHARE", (resource,))
        assert cur.fetchone()
    try:
        with second.cursor() as cur:
            cur.execute("SET LOCAL lock_timeout='200ms'")
            cur.execute("UPDATE sales_datasets SET version=version WHERE resource_id=%s", (resource,))
        raise AssertionError("Dataset changed while its version was locked for reading")
    except psycopg2.errors.LockNotAvailable:
        second.rollback()
finally:
    first.rollback()
    first.close()
    second.close()
print("PASS: database TLS, audit mutation guards, schema isolation, and consistent dataset locking")
'''
    subprocess.run(["docker", "compose", "exec", "-T", "protected_sales_service", "python", "-c", code,
                    fixture["resource"]["resourceId"]], cwd=ROOT, check=True)


def test(fixture):
    seed(fixture)
    hardened = copy.deepcopy(fixture["policy"])
    hardened["version"] = 2
    hardened["conditions"].extend([
        {"path": "agent.credentials", "operator": "any", "value": [
            {"path": "type", "operator": "contains", "value": "JITVC"},
            {"path": "issuer", "operator": "eq", "value": fixture["issuerDid"]},
            {"path": "credentialSubject.jobID", "operator": "equals_path", "value": "$.request.context.jobId"},
        ]},
        {"path": "environment.callerService", "operator": "eq", "value": "operator"},
        {"path": "environment.sourceIp", "operator": "exists", "value": True},
        {"path": "environment.unixTime", "operator": "gte", "value": 1},
    ])
    malformed = copy.deepcopy(hardened)
    malformed["conditions"].append({"path": "environment.utcHour", "operator": "gte", "value": True})
    write(fixture, "policies", malformed, expected=422)
    write(fixture, "policies", hardened)
    passed("invalid policy rejected; credential-specific and server-context policy installed")
    permitted = grant(fixture)
    token = permitted["accessToken"]
    api(8013, "/policies", expected=401, authenticated=False)
    api(8016, "/audit/" + permitted["decisionId"], expected=401, authenticated=False)
    passed("Layer 3 administrative and audit routes require service authentication")
    audit = api(8016, "/audit/" + permitted["decisionId"])
    assert "accessToken" not in audit and "authorizationState" not in audit
    passed("audit contains neither bearer token nor private credential evidence")
    history = api(8013, "/history/policies?policyId=" + fixture["policy"]["policyId"])["versions"]
    assert history[0]["policy"]["version"] == 2 and history[0]["currently_active"]
    assert history[1]["policy"]["version"] == 1 and not history[1]["currently_active"]
    inactive = api(8013, "/policies?active=false")["policies"]
    assert all(not policy["active"] for policy in inactive)
    events = api(8013, "/history/resources?resourceId=" + fixture["resource"]["resourceId"])["events"]
    assert events and events[-1]["event"]["payload"]["adminAuthorization"]["signature"]
    assert api(8013, "/governance/integrity")["valid"]
    assert api(8016, "/audit/integrity")["valid"]
    assert api(8016, "/audit?agentDid=" + fixture["agentDid"])["decisions"]
    passed("governance signatures/history, inactive policy state, and linked decision audits verified")
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
    assert claims["exp"] <= int(time.time()) + 120
    assert claims["exp"] <= fixture["jitExpiry"]
    passed("token lifetime bounded by configured TTL and JIT evidence expiry")

    body = query_body(fixture, token)
    result = query(fixture, token, body)
    assert len(result["rows"]) == 2 and result["rows"][0]["revenue"] == "250000.00", result
    passed("agent-signed request reads actual seeded PostgreSQL rows")
    assert api(8019, "/audit/integrity")["valid"]
    database_checks(fixture)
    query(fixture, token, body, expected=409)
    passed("replayed proof rejected")
    changed = query_body(fixture, token)
    changed["limit"] = 1
    query(fixture, token, changed, expected=403)
    passed("tampered signed query rejected")
    query(fixture, token + "x", query_body(fixture, token), expected=403)
    passed("proof cannot be transferred to a different token")
    injected = query(fixture, token, query_body(fixture, token, period="' OR 1=1 --"))
    assert injected["rows"] == []
    passed("SQL injection string treated only as a filter value")
    scoped = query(fixture, token, query_body(fixture, token, period="2026-Q2", limit=1))
    assert len(scoped["rows"]) == 1 and scoped["rows"][0]["period"] == "2026-Q2"
    passed("parameterized query filters and row limits enforced")

    forged = {**claims, "jti": str(uuid.uuid4())}
    encoded = base64.urlsafe_b64encode(canonical(forged)).decode().rstrip("=")
    signature = api(8001, "/keys/layer3-pep-signing-key/sign",
                    {"payload": base64.b64encode(encoded.encode()).decode()})["signature"]
    fake_token = encoded + "." + base64.urlsafe_b64encode(base64.b64decode(signature)).decode().rstrip("=")
    assert not introspect(fixture, fake_token)["active"]
    passed("even a KMS-signed token without a persisted PEP grant is rejected")

    compose("restart", "access_control_service", "protected_sales_service")
    wait(8016)
    wait(8019)
    query(fixture, token, body, expected=409)
    query(fixture, token)
    passed("grants, database rows, and replay records survive service restart")
    api(8016, "/access/revoke", {"decisionId": permitted["decisionId"]})
    query(fixture, token, expected=403)
    compose("restart", "access_control_service")
    wait(8016)
    assert not introspect(fixture, token)["active"]
    cursor, found = 0, False
    while not found:
        revoke_events = api(8016, f"/audit/events?after={cursor}&limit=1000")["events"]
        assert revoke_events, "Revocation event missing"
        found = any(event["event"]["action"] == "pep.revoke" and
                    event["event"]["payload"]["decisionId"] == permitted["decisionId"] for event in revoke_events)
        cursor = revoke_events[-1]["sequence"]
    passed("explicit token revocation enforced and survives PEP restart")

    permitted = grant(fixture)
    token = permitted["accessToken"]
    policy = copy.deepcopy(fixture["policy"])
    policy["version"] = 3
    write(fixture, "policies", policy)
    assert not introspect(fixture, token)["active"]
    rollback = {**policy, "version": 2}
    write(fixture, "policies", rollback, expected=409)
    passed("policy version changes invalidate old tokens; unused older versions cannot roll back policy")
    permitted = grant(fixture)
    token = permitted["accessToken"]
    policy.update(version=4, active=False)
    write(fixture, "policies", policy)
    query(fixture, token, expected=403)
    passed("disabled policy stops an already-issued token")
    policy.update(version=5, active=True)
    write(fixture, "policies", policy)

    permitted = grant(fixture)
    token = permitted["accessToken"]
    resource = copy.deepcopy(fixture["resource"])
    resource.update(version=2, active=False)
    write(fixture, "resources", resource)
    query(fixture, token, expected=403)
    resource.update(version=3, active=True)
    write(fixture, "resources", resource)
    passed("resource deactivation stops an already-issued token")

    permitted = grant(fixture)
    token = permitted["accessToken"]
    try:
        compose("stop", "policy_information_service")
        query(fixture, token, expected=403)
        passed("protected SQL access fails closed when attribute service is unavailable")
    finally:
        compose("start", "policy_information_service")
        wait(8014)
    query(fixture, token)
    passed("valid authorization works again after dependency recovery")

    agent = fixture["agentDid"]
    api(8002, f"/dids/{agent}", {"updates": {"lifecycleStatus": "suspended"}, "authoritySignature": ""}, method="PUT")
    try:
        query(fixture, token, expected=403)
        passed("holder DID suspension stops an already-issued token")
    finally:
        api(8002, f"/dids/{agent}", {"updates": {"lifecycleStatus": "active"}, "authoritySignature": ""}, method="PUT")

    assert introspect(fixture, token)["active"]
    api(8006, "/status-lists/revoke", {"vc_id": fixture["jitVcId"], "reason": "Layer 3 enforcement regression test",
                                     "authority_did": fixture["issuerDid"]})
    query(fixture, token, expected=403)
    passed("JIT revocation stops existing token immediately without waiting for verification cache TTL")
    print("REAL LAYER 3 ENFORCEMENT TEST PASSED", flush=True)


if __name__ == "__main__":
    fixture = json.loads(base64.b64decode(sys.argv[1]))
    if "--prepare" in sys.argv:
        seed(fixture)
        destination = ROOT / "layer3_testing" / "swagger_demo" / "12-enforcement-fixture.json"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(fixture, indent=2), encoding="utf-8")
        passed("real sales dataset prepared for Swagger")
    else:
        test(fixture)
