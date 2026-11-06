"""Focused offline tests; the separate PowerShell suite exercises real services."""
import asyncio
import base64
import copy
import hashlib
import json
import time
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from layer3_common import security
from layer3_common.crypto import canonical, fingerprint
from layer3_common.provision import provision
from policy_decision_service.main import _condition_matches, _evaluate
from policy_information_service import main as pip
from access_control_service import main as pep
from protected_sales_service import main as sales


def run(awaitable):
    return asyncio.run(awaitable)


@pytest.mark.parametrize("operator", ["eq", "neq", "equals_path", "gte", "lte", "contains", "in"])
def test_missing_attribute_cannot_match(operator):
    assert not _condition_matches({"path": "missing", "operator": operator, "value": None}, {})


def test_explicit_deny_overrides_permit():
    attributes = {"resource": {"resourceId": "r"}, "request": {"action": "QUERY_TABLE"}, "agent": {}}
    policies = [{"policyId": name, "version": 1, "effect": name, "actions": ["QUERY_TABLE"]}
                for name in ["permit", "deny"]]
    assert _evaluate(policies, attributes)[0] == "deny"
    assert _evaluate([], attributes)[0] == "deny"


@pytest.fixture
def security_dir(tmp_path, monkeypatch):
    provision(tmp_path)
    monkeypatch.setenv("LAYER3_SECURITY_DIR", str(tmp_path / "pap"))
    monkeypatch.setenv("LAYER3_SERVICE_ID", "pap")
    return tmp_path


def test_provision_persists_keys_and_distinct_roles(security_dir):
    before = (security_dir / "pep" / "evidence.key").read_bytes()
    provision(security_dir)
    assert before == (security_dir / "pep" / "evidence.key").read_bytes()
    assert (security_dir / "pap" / "database.key").read_bytes() != (security_dir / "pep" / "database.key").read_bytes()
    assert "hostnossl all all all reject" in (security_dir / "database" / "pg_hba.conf").read_text()


def test_service_authentication_and_roles(security_dir):
    app = FastAPI()
    security.install(app, "pap")
    app.get("/policies")(lambda: {})
    app.post("/policies")(lambda: {})
    with TestClient(app) as client:
        assert client.get("/policies").status_code == 401
        headers = {"X-Service-ID": "pip", "X-Service-Token": (security_dir / "pip" / "client.key").read_text()}
        assert client.get("/policies", headers=headers).status_code == 200
        assert client.post("/policies", headers=headers).status_code == 403
        headers["X-Service-ID"] = "operator"
        assert client.post("/policies", headers=headers).status_code == 401


def test_no_unencrypted_layer3_connections(security_dir):
    with pytest.raises(HTTPException) as error:
        run(security.request("GET", "http://policy_decision_service:8015/decisions"))
    assert error.value.status_code == 503


def test_worker_service_can_request_grant_but_cannot_administer(security_dir):
    app = FastAPI()
    security.install(app, "pep")
    app.post("/access/check")(lambda: {})
    app.post("/access/revoke")(lambda: {})
    app.get("/audit/example")(lambda: {})
    headers = {"X-Service-ID": "risk_agent",
               "X-Service-Token": (security_dir / "risk_agent" / "client.key").read_text()}
    with TestClient(app) as client:
        assert client.post("/access/check", headers=headers).status_code == 200
        assert client.post("/access/revoke", headers=headers).status_code == 403
        assert client.get("/audit/example", headers=headers).status_code == 403


@pytest.fixture
def pip_evidence(monkeypatch):
    doc = {"id": "did:agent", "lifecycleStatus": "active", "verificationMethod": [], "authentication": []}
    monkeypatch.setattr(pip, "did_document", AsyncMock(return_value=doc))
    credential = {"id": "vc:1", "issuer": {"id": "did:issuer"}, "type": ["VerifiableCredential", "RoleVC"],
                  "credentialSubject": {"id": "did:agent", "roleName": "RiskAnalyzer"},
                  "credentialStatus": {"statusListCredential": "http://status/list", "statusListIndex": "0"},
                  "expirationDate": "2099-01-01T00:00:00Z"}
    async def request(method, url, **kwargs):
        data = {"resourceId": "r", "version": 1} if method == "GET" else {"valid": True}
        return httpx.Response(200, json=data, request=httpx.Request(method, url))
    monkeypatch.setattr(pip, "http_request", AsyncMock(side_effect=request))
    return doc, credential


def test_fresh_status_and_expiry_bound(pip_evidence):
    _, credential = pip_evidence
    expires = int(time.time()) + 30
    attributes = run(pip.gather("did:agent", "r", "QUERY_TABLE", {}, [credential], upper_expiry=expires))
    assert attributes["authorizationState"]["expiresAt"] == expires
    assert pip.http_request.call_args.kwargs["json"]["fresh_status"] is True


@pytest.mark.parametrize("change", ["holder", "expiry", "missing_status", "key_change", "conflicting_claims"])
def test_pip_rejects_unusable_evidence(pip_evidence, change):
    _, credential = pip_evidence
    credentials, key = [credential], None
    if change == "holder":
        credential["credentialSubject"]["id"] = "did:other"
    elif change == "expiry":
        credential["expirationDate"] = "2000-01-01T00:00:00Z"
    elif change == "missing_status":
        credential.pop("credentialStatus")
    elif change == "key_change":
        key = "changed"
    elif change == "conflicting_claims":
        other = copy.deepcopy(credential)
        other["credentialSubject"]["roleName"] = "Admin"
        credentials.append(other)
    with pytest.raises(HTTPException):
        run(pip.gather("did:agent", "r", "QUERY_TABLE", {}, credentials, expected_key=key))


@pytest.fixture
def grant(monkeypatch):
    key = Ed25519PrivateKey.generate()
    cipher_key = Fernet.generate_key()
    claims = {"jti": "j", "sub": "did:a", "resourceId": "r", "action": "QUERY_TABLE",
              "exp": int(time.time()) + 60}
    encoded = pep._b64url(canonical(claims))
    token = encoded + "." + pep._b64url(key.sign(encoded.encode()))
    row = {"token_hash": pep.token_hash(token), "evidence": Fernet(cipher_key).encrypt(b"{}").decode(),
           "resource_version": 1, "policy_refs": [{"policyId": "p", "version": 1}], "revoked_at": None}
    decision = {"effect": "permit", "resourceVersion": 1, "matchedPolicies": row["policy_refs"],
                "resource": {"resourceId": "r"}}
    monkeypatch.setattr(pep, "_public_key", AsyncMock(return_value=key.public_key()))
    monkeypatch.setattr(pep, "secret", lambda _: cipher_key.decode())
    monkeypatch.setattr(pep, "_grant", lambda _: row)
    async def request(*args, **kwargs):
        return httpx.Response(200, json=decision, request=httpx.Request("POST", "https://pdp"))
    monkeypatch.setattr(pep, "http_request", AsyncMock(side_effect=request))
    return token, row, decision


def test_live_grant_revalidation(grant):
    token, _, _ = grant
    assert run(pep.introspect(pep.IntrospectionRequest(token=token)))["active"]
    assert pep.http_request.call_args.args[1].endswith("/decisions/revalidate")


@pytest.mark.parametrize("caller,supplied,expected", [("sales", "192.0.2.2", "192.0.2.2"),
                                                     ("operator", "10.0.0.1", "192.0.2.1")])
def test_live_network_context_cannot_reuse_grant_origin(grant, caller, supplied, expected):
    from types import SimpleNamespace
    token, _, _ = grant
    http = SimpleNamespace(state=SimpleNamespace(caller=caller), client=SimpleNamespace(host="192.0.2.1"))
    assert run(pep.introspect(pep.IntrospectionRequest(token=token, sourceIp=supplied), http))["active"]
    assert pep.http_request.call_args.kwargs["json"]["trustedContext"]["sourceIp"] == expected


def test_resource_must_supply_observed_origin(grant):
    from types import SimpleNamespace
    token, _, _ = grant
    http = SimpleNamespace(state=SimpleNamespace(caller="sales"))
    assert not run(pep.introspect(pep.IntrospectionRequest(token=token), http))["active"]


@pytest.mark.parametrize("change", ["revoked", "unknown_hash", "policy", "resource", "deny", "outage", "scope"])
def test_existing_grant_fail_closed(grant, monkeypatch, change):
    token, row, decision = grant
    request = pep.IntrospectionRequest(token=token)
    if change == "revoked":
        row["revoked_at"] = "now"
    elif change == "unknown_hash":
        row["token_hash"] = "unknown"
    elif change == "policy":
        decision["matchedPolicies"] = [{"policyId": "p", "version": 2}]
    elif change == "resource":
        decision["resourceVersion"] = 2
    elif change == "deny":
        decision["effect"] = "deny"
    elif change == "outage":
        monkeypatch.setattr(pep, "http_request", AsyncMock(side_effect=httpx.ConnectError("offline")))
    elif change == "scope":
        request.action = "DELETE_TABLE"
    assert not run(pep.introspect(request))["active"]


def test_invalid_token_rejected(grant):
    token, _, _ = grant
    assert not run(pep.introspect(pep.IntrospectionRequest(token=token + "tampered")))["active"]


@pytest.mark.parametrize("offset,duration", [(-70, 60), (10, 20), (0, 61), (0, 0)])
def test_signed_query_time_window(offset, duration):
    from types import SimpleNamespace
    issued = int(time.time()) + offset
    with pytest.raises(HTTPException):
        sales.validate_window(SimpleNamespace(issuedAt=issued, expiresAt=issued + duration))


def test_query_requires_bearer():
    client = TestClient(sales.app, raise_server_exceptions=False)
    assert client.post("/query", json={}).status_code == 403
