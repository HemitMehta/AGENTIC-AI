import asyncio
import base64
import copy
import json
import time
from datetime import datetime, timezone
from decimal import Decimal
from uuid import uuid4

import base58
import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from agent_services.common import TaskStore, canonical, identity_did, operator_token, register_identity, validate_endpoint
from agent_services.models import FinancialInput
from agent_services.orchestrator import app as orchestrator
from agent_services.risk_agent import analyze, app as worker


def signed(key, body):
    return base64.b64encode(key.sign(canonical(body))).decode()


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("KMS_URL", "http://kms")
    monkeypatch.setenv("DID_REGISTRY_URL", "http://registry")
    monkeypatch.setenv("DISCOVERY_GATEWAY_URL", "http://gateway")
    monkeypatch.setenv("TRUSTED_GATEWAY_KEY_ID", "gateway")
    monkeypatch.setenv("TRUSTED_RESOLVER_KEY_ID", "resolver")
    monkeypatch.setenv("ALLOWED_AGENT_ENDPOINTS", "http://worker/tasks")
    monkeypatch.setenv("ALLOW_HTTP_AGENT_ENDPOINTS", "true")
    keys = {name: Ed25519PrivateKey.generate() for name in ("gateway", "resolver", "orch", "risk")}
    identities = {name: {"did": f"did:web:test:agents:{name}", "keyId": name,
                         "verificationMethod": f"did:web:test:agents:{name}#{name}"} for name in ("orch", "risk")}
    state = {"scenario": "ok", "workerCalls": 0, "keys": keys, "identities": identities}

    async def handler(request):
        path = request.url.path
        if request.url.host == "kms":
            key_id = path.split("/")[2]
            key = keys[key_id]
            if path.endswith("/public"):
                raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                return httpx.Response(200, json={"keyStatus": "active", "keyId": key_id,
                                                 "publicKey": base64.b64encode(raw).decode()})
            data = json.loads(request.content)
            return httpx.Response(200, json={"signature": base64.b64encode(key.sign(base64.b64decode(data["payload"]))).decode()})
        if request.url.host == "registry":
            did = path.removeprefix("/dids/")
            name = did.rsplit(":", 1)[-1]
            raw = keys[name].public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            vm = identities[name]["verificationMethod"]
            document = {"id": did, "lifecycleStatus": "active", "authentication": [vm],
                        "verificationMethod": [{"id": vm, "controller": did,
                            "publicKeyMultibase": "z" + base58.b58encode(b"\xed\x01" + raw).decode()}]}
            if state["scenario"] == "revoked_worker" and name == "risk":
                document["lifecycleStatus"] = "revoked"
            return httpx.Response(200, json={"data": {"didDocument": document}})
        if request.url.host == "gateway":
            query = json.loads(request.content)
            if state["scenario"] == "no_matches":
                return httpx.Response(200, json={"resolutionStatus": "no_matches"})
            if state["scenario"] == "gateway_down":
                return httpx.Response(503)
            record = {"ansName": "signed-http-json://risk.test", "agentDid": identities["risk"]["did"],
                      "serviceEndpoint": "http://worker/tasks", "provider": "TestProvider",
                      "capability": query["capability"], "version": "1.0.0",
                      "protocolExtensions": [{"protocol": "signed-http-json", "details": {}}],
                      "relevantVcSnippets": [{"type": "RoleVC", "verified": True, "revoked": False}],
                      "signingKeyId": "resolver", "signatureAlgorithm": "Ed25519"}
            if state["scenario"] == "missing_attestation":
                record["relevantVcSnippets"] = []
            if state["scenario"] == "wrong_capability":
                record["capability"] += ".Different"
            if state["scenario"] == "wrong_version":
                record["version"] = "9.0.0"
            if state["scenario"] == "ssrf":
                record["serviceEndpoint"] = "http://169.254.169.254/latest/meta-data"
            if state["scenario"] == "wrong_resolver":
                record["signingKeyId"] = "risk"
            record["ansRecordSignature"] = signed(keys[record["signingKeyId"]], record)
            if state["scenario"] == "ans_tamper":
                record["version"] = "1.1.0"
            response = {"resolutionStatus": "success", "requestId": query["requestId"],
                        "selectedAgent": record["agentDid"], "endpoint": record["serviceEndpoint"],
                        "resolvedAt": datetime.now(timezone.utc).isoformat(),
                        "candidates": [{"agentDid": record["agentDid"], "serviceEndpoint": record["serviceEndpoint"],
                                        "signatureVerified": True, "ansRecord": record}]}
            if state["scenario"] == "wrong_challenge":
                response["requestId"] = str(uuid4())
            if state["scenario"] == "stale_discovery":
                response["resolvedAt"] = "2000-01-01T00:00:00+00:00"
            wire = json.dumps(response, sort_keys=True).encode()
            response["gatewaySignature"] = base64.b64encode(keys["gateway"].sign(wire)).decode()
            if state["scenario"] == "gateway_tamper":
                response["endpoint"] = "http://attacker/tasks"
            return httpx.Response(200, json=response)
        if request.url.host == "worker":
            state["workerCalls"] += 1
            state["message"] = json.loads(request.content)
            if state["scenario"] == "worker_down":
                raise httpx.ConnectError("worker unavailable", request=request)
            if state["scenario"] == "redirect":
                return httpx.Response(307, headers={"location": "http://attacker/tasks"})
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=worker), base_url="http://worker") as internal:
                response = await internal.post("/tasks", json=state["message"])
            if state["scenario"] == "result_tamper":
                result = response.json()
                result["result"]["netIncome"] = "999999"
                return httpx.Response(200, json=result)
            if state["scenario"] == "wrong_result_binding":
                result = response.json()
                result["requestHash"] = "0" * 64
                payload = {k: v for k, v in result.items() if k != "proof"}
                result["proof"]["signature"] = signed(keys["risk"], payload)
                return httpx.Response(200, json=result)
            return response
        raise AssertionError(f"Unexpected outbound request: {request.url}")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)
    orchestrator.state.client = worker.state.client = client
    orchestrator.state.identity = identities["orch"]
    worker.state.identity = identities["risk"]
    worker.state.trusted_orchestrator = identities["orch"]["did"]
    orchestrator.state.token = "test-only-operator-token"
    orchestrator.state.store = TaskStore(tmp_path / "orch.sqlite3")
    worker.state.store = TaskStore(tmp_path / "worker.sqlite3")
    state["client"] = TestClient(orchestrator)
    state["worker"] = TestClient(worker)
    state["headers"] = {"X-API-Key": orchestrator.state.token}
    state["submission"] = {"taskId": str(uuid4()), "discovery": {
        "capability": "FinancialRiskAnalysis.CorporateReporting", "provider": "TestProvider",
        "protocol": "signed-http-json", "versionRange": ">=1.0.0,<2.0.0", "requiredAttestations": ["RoleVC"]},
        "input": {"currency": "USD", "periods": [{"period": "2026-Q1", "revenue": "100.10", "expenses": "70.05"},
                                                  {"period": "2026-Q2", "revenue": "20.00", "expenses": "30.00"}]}}
    yield state
    state["client"].close()
    state["worker"].close()
    asyncio.run(client.aclose())


def submit(runtime):
    return runtime["client"].post("/tasks", json=runtime["submission"], headers=runtime["headers"])


def test_real_signature_roundtrip_and_input_driven_calculation(runtime):
    response = submit(runtime)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["discovery"]["ansRecordSignatureVerified"] is True
    assert body["agentResponseSignatureVerified"] is True
    assert Decimal(body["agentResponse"]["result"]["netIncome"]) == Decimal("20.05")
    assert body["agentResponse"]["result"]["lossMakingPeriods"] == ["2026-Q2"]
    audit = runtime["client"].get(f"/tasks/{body['taskId']}", headers=runtime["headers"])
    assert audit.json()["result"] == body
    runtime["submission"]["taskId"] = str(uuid4())
    runtime["submission"]["input"]["periods"][0]["revenue"] = "200.10"
    assert Decimal(submit(runtime).json()["agentResponse"]["result"]["netIncome"]) == Decimal("120.05")


def test_unauthenticated_operator_rejected_without_discovery(runtime):
    assert runtime["client"].post("/tasks", json=runtime["submission"]).status_code == 401
    assert runtime["workerCalls"] == 0
    assert runtime["client"].get(f"/tasks/{uuid4()}").status_code == 401


@pytest.mark.parametrize("scenario,expected", [
    ("gateway_tamper", 403), ("ans_tamper", 403), ("wrong_resolver", 403),
    ("wrong_challenge", 403), ("stale_discovery", 403), ("missing_attestation", 403),
    ("wrong_capability", 403), ("wrong_version", 403), ("ssrf", 403),
    ("no_matches", 404), ("gateway_down", 502),
])
def test_discovery_rejected_before_dispatch(runtime, scenario, expected):
    runtime["scenario"] = scenario
    response = submit(runtime)
    assert response.status_code == expected, response.text
    assert runtime["workerCalls"] == 0
    stored = orchestrator.state.store.get(runtime["submission"]["taskId"])
    assert stored["status"] == "failed"


@pytest.mark.parametrize("scenario,expected", [
    ("result_tamper", 403), ("wrong_result_binding", 403), ("revoked_worker", 403),
    ("worker_down", 502), ("redirect", 502),
])
def test_execution_fails_closed(runtime, scenario, expected):
    runtime["scenario"] = scenario
    response = submit(runtime)
    assert response.status_code == expected, response.text
    assert runtime["workerCalls"] == 1


def test_duplicate_tasks_rejected_at_both_agents(runtime):
    assert submit(runtime).status_code == 200
    assert submit(runtime).status_code == 409
    assert runtime["workerCalls"] == 1
    replay = runtime["worker"].post("/tasks", json=runtime["message"])
    assert replay.status_code == 409


@pytest.mark.parametrize("change", ["payload", "audience", "sender", "expired", "future"])
def test_worker_authentication_checks(runtime, change):
    assert submit(runtime).status_code == 200
    message = copy.deepcopy(runtime["message"])
    if change == "payload":
        message["input"]["periods"][0]["revenue"] = "999.00"
    elif change == "audience":
        message["audienceDid"] = "did:web:wrong"
    elif change == "sender":
        message["issuerDid"] = "did:web:attacker"
    elif change == "expired":
        message["issuedAt"] = int(time.time()) - 70
        message["expiresAt"] = int(time.time()) - 10
    else:
        message["issuedAt"] = int(time.time()) + 30
        message["expiresAt"] = int(time.time()) + 60
    assert runtime["worker"].post("/tasks", json=message).status_code == 403


def test_endpoint_rules_and_exact_allowlist():
    with pytest.raises(HTTPException):
        validate_endpoint("http://worker/tasks", {"http://worker/tasks"})
    for url in ["http://worker.evil/tasks", "http://worker/tasks/other", "file:///etc/passwd",
                "http://user:password@worker/tasks", "http://worker/tasks?url=http://attacker", "http://worker/tasks#x"]:
        with pytest.raises(HTTPException):
            validate_endpoint(url, {"http://worker/tasks"}, allow_http=True)
    assert validate_endpoint("https://worker/tasks", {"https://worker/tasks"}) == "https://worker/tasks"


def test_persistent_replay_protection_and_interrupted_task(tmp_path):
    path = tmp_path / "tasks.sqlite3"
    first = TaskStore(path)
    first.reserve("a", {"input": 1})
    first.reserve("b", {"input": 2})
    first.finish("b", result={"value": 2})
    second = TaskStore(path)
    assert second.get("a")["status"] == "interrupted"
    assert second.get("b")["status"] == "completed"
    with pytest.raises(HTTPException) as error:
        second.reserve("b", {"input": 3})
    assert error.value.status_code == 409


def test_financial_validation_and_zero_revenue():
    data = FinancialInput(currency="USD", periods=[{"period": "Q1", "revenue": "0", "expenses": "3.00"}])
    assert Decimal(analyze(data)["netIncome"]) == Decimal("-3")
    for value in ["NaN", "Infinity", "-1", "0.001"]:
        with pytest.raises(ValidationError):
            FinancialInput(currency="USD", periods=[{"period": "Q1", "revenue": value, "expenses": "1"}])
    with pytest.raises(ValidationError):
        FinancialInput(currency="USD", periods=[{"period": "Q1", "revenue": 1, "expenses": 0}] * 2)


@pytest.mark.parametrize("status", ["active", "revoked"])
def test_startup_does_not_overwrite_existing_identity(monkeypatch, status):
    monkeypatch.setenv("KMS_URL", "http://kms")
    monkeypatch.setenv("DID_REGISTRY_URL", "http://registry")
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    public = base64.b64encode(raw).decode()
    did = identity_did(public, "task-orchestrator", "demo.local")
    vm = f"{did}#orch"

    async def handler(request):
        if request.url.path.endswith("/public"):
            return httpx.Response(200, json={"keyStatus": "active", "keyId": "orch", "publicKey": public})
        if request.url.path.endswith("/sign"):
            payload = base64.b64decode(json.loads(request.content)["payload"])
            return httpx.Response(200, json={"signature": base64.b64encode(key.sign(payload)).decode()})
        assert request.method == "GET", "Startup must not overwrite the existing DID"
        return httpx.Response(200, json={"data": {"didDocument": {
            "id": did, "lifecycleStatus": status, "authentication": [vm],
            "verificationMethod": [{"id": vm, "controller": did,
                "publicKeyMultibase": "z" + base58.b58encode(b"\xed\x01" + raw).decode()}]}}})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await register_identity(client, "orch", "task-orchestrator", "demo.local")

    if status == "active":
        assert asyncio.run(run())["did"] == did
    else:
        with pytest.raises(HTTPException) as error:
            asyncio.run(run())
        assert error.value.status_code == 403


def test_operator_token_is_generated_once_and_persists(tmp_path):
    path = tmp_path / "operator-token.txt"
    first = operator_token(path)
    assert len(first) >= 32
    assert operator_token(path) == first
