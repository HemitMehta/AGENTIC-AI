import asyncio
import base64
import copy
import json
import time
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from pydantic import ValidationError

from agent_services import protected_sales as protected
from agent_services.common import canonical, digest
from agent_services.models import ProtectedSalesInput, TaskMessage, TaskSubmission


def encoded(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


@pytest.fixture
def environment(monkeypatch):
    keys = {name: Ed25519PrivateKey.generate() for name in ("pep", "risk")}
    monkeypatch.setenv("KMS_URL", "http://kms")
    monkeypatch.setenv("TRUSTED_PEP_KEY_ID", "pep")
    monkeypatch.setattr(protected, "service_headers", lambda: {"X-Service-ID": "risk_agent", "X-Service-Token": "test"})
    identity = {"did": "did:risk", "keyId": "risk", "verificationMethod": "did:risk#risk"}
    task = TaskMessage(taskId=uuid4(), issuerDid="did:orchestrator", audienceDid="did:risk",
                       issuedAt=int(time.time()), expiresAt=int(time.time()) + 60,
                       input={"source": "protected-sales", "resourceId": "sales", "jobId": "job",
                              "currency": "USD", "credentialIds": ["role", "jit"]},
                       proof={"verificationMethod": "did:orchestrator#key", "signature": "test"})
    state = {"scenario": "ok", "sqlCalls": 0}

    async def handler(request):
        body = json.loads(request.content) if request.content else {}
        path = request.url.path
        if request.url.host == "kms":
            key = keys[path.split("/")[2]]
            if path.endswith("/public"):
                return httpx.Response(200, json={"keyId": "pep", "keyStatus": "active",
                    "publicKey": base64.b64encode(key.public_key().public_bytes(
                        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()})
            return httpx.Response(200, json={"signature": base64.b64encode(key.sign(base64.b64decode(body["payload"]))).decode()})
        if path == "/verify/nonce":
            return httpx.Response(200, json={"nonce": "nonce"})
        if path.endswith("/present"):
            assert body["credential_ids"] == ["role", "jit"]
            assert body["agent_did"] == "did:risk"
            return httpx.Response(200, json={"vp_jwt": "vp"})
        if path == "/access/check":
            assert request.headers["X-Service-ID"] == "risk_agent"
            assert body["context"]["taskId"] == str(task.taskId)
            decision = {"decisionId": "decision", "effect": "deny" if state["scenario"] == "deny" else "permit",
                        "agentDid": "did:risk", "resourceId": "sales", "action": "QUERY_TABLE",
                        "contextHash": digest(body["context"]), "matchedPolicies": [{"policyId": "policy", "version": 1}]}
            if state["scenario"] == "wrong_decision":
                decision["resourceId"] = "other"
            signature = base64.b64encode(keys["pep"].sign(canonical(decision))).decode()
            claims = {"jti": "decision", "sub": "did:risk", "resourceId": "sales", "action": "QUERY_TABLE",
                      "contextHash": digest(body["context"]), "exp": int(time.time()) + 60}
            if state["scenario"] == "wrong_token":
                claims["sub"] = "did:other"
            if state["scenario"] == "expired_token":
                claims["exp"] = 1
            token = encoded(canonical(claims))
            token += "." + encoded(keys["pep"].sign(token.encode()))
            response = {**decision, "decisionSignature": signature, "accessToken": token,
                        "signingKeyId": "pep", "signatureAlgorithm": "Ed25519"}
            if state["scenario"] == "tampered_decision":
                response["contextHash"] = "tampered"
            if state["scenario"] == "untrusted_signer":
                response["signingKeyId"] = "risk"
            return httpx.Response(200, json=response)
        if path == "/query":
            state["sqlCalls"] += 1
            assert "X-Service-Token" not in request.headers
            assert request.headers["Authorization"].startswith("Bearer ")
            signed = {"action": "sales.query", **{k: v for k, v in body.items() if k != "proof"}}
            keys["risk"].public_key().verify(base64.b64decode(body["proof"]["signature"]), canonical(signed))
            if state["scenario"] == "revoked_at_sql":
                return httpx.Response(403, json={"detail": "inactive grant"})
            if state["scenario"] == "sql_down":
                raise httpx.ConnectError("unavailable", request=request)
            result = {"resourceId": "sales", "decisionId": "decision", "requestId": body["requestId"], "datasetVersion": 2,
                      "rows": [{"period": "Q1", "currency": "USD", "revenue": "100.00", "expenses": "70.00"}]}
            if state["scenario"] == "wrong_response":
                result["decisionId"] = "other"
            if state["scenario"] == "wrong_currency":
                result["rows"][0]["currency"] = "EUR"
            return httpx.Response(200, json=result)
        raise AssertionError(request.url)

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(protected, "tls_client", lambda: httpx.AsyncClient(transport=transport))
    return state, identity, task, transport


def execute(environment):
    state, identity, task, transport = environment
    async def run():
        async with httpx.AsyncClient(transport=transport) as client:
            return await protected.read_sales(client, identity, task)
    return asyncio.run(run())


def test_protected_read_uses_selected_credentials_signed_query_and_provenance(environment):
    financials, source = execute(environment)
    assert str(financials.periods[0].revenue) == "100.00"
    assert source["decisionId"] == "decision" and source["datasetVersion"] == 2
    assert environment[0]["sqlCalls"] == 1
    assert "accessToken" not in json.dumps(source)


@pytest.mark.parametrize("scenario", ["deny", "wrong_decision", "wrong_token", "expired_token",
                                     "tampered_decision", "untrusted_signer"])
def test_invalid_authorization_never_reaches_sql(environment, scenario):
    environment[0]["scenario"] = scenario
    with pytest.raises(HTTPException):
        execute(environment)
    assert environment[0]["sqlCalls"] == 0


@pytest.mark.parametrize("scenario", ["revoked_at_sql", "sql_down", "wrong_response", "wrong_currency"])
def test_protected_resource_failure_never_falls_back(environment, scenario):
    environment[0]["scenario"] = scenario
    with pytest.raises(HTTPException):
        execute(environment)


def test_no_inline_numbers_or_arbitrary_url_in_protected_input(environment):
    data = environment[2].input.model_dump()
    for key, value in [("periods", []), ("endpoint", "http://attacker"), ("credentialIds", ["role", "role"])]:
        with pytest.raises(ValidationError):
            ProtectedSalesInput(**{**data, key: value})


def test_plaintext_protected_endpoint_rejected(monkeypatch):
    monkeypatch.setenv("PEP_URL", "http://pep")
    with pytest.raises(HTTPException):
        protected.endpoint("PEP_URL", "https://pep")
