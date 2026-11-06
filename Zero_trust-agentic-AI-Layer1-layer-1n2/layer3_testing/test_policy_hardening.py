import asyncio
import copy
import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from pydantic import ValidationError

from layer3_common.audit import GENESIS, verify_rows
from layer3_common.crypto import canonical
from layer3_common.models import AccessRequest, VerifiedAccessRequest
from layer3_common.policy import Condition, Policy, condition_matches, equal
from policy_decision_service import main as pdp
from policy_information_service import main as pip
from access_control_service import main as pep


def run(value):
    return asyncio.run(value)


@pytest.mark.parametrize("condition", [
    {"path": "agent.role", "operator": "exists", "value": "false"},
    {"path": "agent.role", "operator": "contains", "value": None},
    {"path": "agent.role", "operator": "in", "value": "admin"},
    {"path": "agent.role", "operator": "gte", "value": True},
    {"path": "agent.role", "operator": "gte", "value": "10"},
    {"path": "agent.role", "operator": "gte", "value": float("inf")},
    {"path": "agent..role", "operator": "exists", "value": True},
    {"path": "agent.role", "operator": "equals_path", "value": {}},
    {"path": "agent.role", "operator": "any", "value": []},
    {"path": "agent.role", "operator": "any", "value": [{"path": "x", "operator": "unknown"}]},
    {"path": "agent.role", "operator": "any", "value": [{"path": "x", "operator": []}]},
    {"path": "environment.sourceIp", "operator": "ip_in_cidr", "value": "not-a-network"},
])
def test_invalid_condition_rejected(condition):
    with pytest.raises(ValidationError):
        Condition.model_validate(condition)


@pytest.mark.parametrize("left,right", [(True, 1), ([True], [1]), ({"x": True}, {"x": 1}), ("1", 1)])
def test_json_types_cannot_be_confused(left, right):
    assert not equal(left, right)
    assert not condition_matches({"path": "x", "operator": "eq", "value": right}, {"x": left})


@pytest.mark.parametrize("actual,expected", [(True, 1), ("20", 10), (float("nan"), 1)])
def test_ordered_conditions_require_finite_numbers(actual, expected):
    assert not condition_matches({"path": "x", "operator": "gte", "value": expected}, {"x": actual})


def test_contains_wrong_type_denies_without_exception():
    for value in ("abc", {"abc": 1}):
        assert not condition_matches({"path": "x", "operator": "contains", "value": []}, {"x": value})


def test_same_credential_must_satisfy_all_predicates():
    attributes = {"agent": {"credentials": [
        {"type": ["RoleVC"], "issuer": "did:untrusted", "credentialSubject": {"role": "Analyst"}},
        {"type": ["OtherVC"], "issuer": "did:hr", "credentialSubject": {"role": "Analyst"}},
    ]}, "resource": {"role": "Analyst"}}
    condition = {"path": "agent.credentials", "operator": "any", "value": [
        {"path": "type", "operator": "contains", "value": "RoleVC"},
        {"path": "issuer", "operator": "eq", "value": "did:hr"},
        {"path": "credentialSubject.role", "operator": "equals_path", "value": "$.resource.role"},
    ]}
    assert not condition_matches(condition, attributes)
    attributes["agent"]["credentials"][0]["issuer"] = "did:hr"
    assert condition_matches(condition, attributes)


@pytest.mark.parametrize("operator", ["any", "all"])
def test_empty_array_does_not_satisfy_predicate(operator):
    assert not condition_matches({"path": "tools", "operator": operator, "value": [
        {"path": "name", "operator": "eq", "value": "SQL"}]}, {"tools": []})


def test_network_condition_uses_real_cidr_semantics():
    condition = {"path": "environment.sourceIp", "operator": "ip_in_cidr", "value": "10.0.0.0/8"}
    assert condition_matches(condition, {"environment": {"sourceIp": "10.2.3.4"}})
    assert not condition_matches(condition, {"environment": {"sourceIp": "110.2.3.4"}})
    assert not condition_matches(condition, {"environment": {"sourceIp": "garbage"}})


def test_malformed_deny_cannot_be_skipped():
    permit = {"policyId": "p", "version": 1, "effect": "permit", "actions": ["read"]}
    deny = {**permit, "effect": "deny", "conditions": [{"path": "x", "operator": "exists", "value": "true"}]}
    attributes = {"agent": {}, "resource": {}, "request": {"action": "read"}}
    assert pdp._evaluate([permit, deny], attributes)[0] == "deny"
    assert pdp._evaluate([{**permit, "active": False}], attributes)[0] == "deny"


def test_unknown_policy_field_and_boolean_version_rejected():
    policy = {"policyId": "p", "version": 1, "effect": "permit", "actions": ["read"]}
    for change in ({"version": True}, {"conditons": []}, {"actions": ["read", "read"]}):
        with pytest.raises(ValidationError):
            Policy.model_validate({**policy, **change})


def access_body():
    return {"agentDid": "did:a", "resourceId": "r", "action": "read", "context": {}, "vpJwt": "vp", "nonce": "n"}


def test_public_access_request_cannot_supply_trusted_context():
    with pytest.raises(ValidationError):
        AccessRequest.model_validate({**access_body(), "trustedContext": {"callerService": "admin"}})


def test_pep_observes_context_instead_of_using_agent_claim(monkeypatch):
    body = access_body()
    body["context"] = {"sourceIp": "10.0.0.1", "callerService": "admin"}
    response = {"decisionId": "d", "effect": "deny", "agentDid": "did:a", "resourceId": "r", "action": "read"}
    call = AsyncMock(return_value=httpx.Response(200, json=response, request=httpx.Request("POST", "https://pdp")))
    monkeypatch.setattr(pep, "http_request", call)
    monkeypatch.setattr(pep, "_sign", AsyncMock(return_value="signature"))
    monkeypatch.setattr(pep, "_record", lambda *args: None)
    http = SimpleNamespace(client=SimpleNamespace(host="192.0.2.1"), state=SimpleNamespace(caller="risk_agent"))
    run(pep.check_access(AccessRequest(**body), http))
    assert call.call_args.kwargs["json"]["trustedContext"] == {"sourceIp": "192.0.2.1", "callerService": "risk_agent"}


def test_pip_refreshes_server_clock_and_preserves_claim_provenance(monkeypatch):
    credential = {"id": "vc:1", "issuer": "did:hr", "type": ["VerifiableCredential", "RoleVC"],
                  "credentialSubject": {"id": "did:a", "role": "Analyst"}, "expirationDate": "2099-01-01T00:00:00Z",
                  "credentialStatus": {"statusListCredential": "status", "statusListIndex": "0"}}
    monkeypatch.setattr(pip, "did_document", AsyncMock(return_value={"id": "did:a"}))
    async def request(method, url, **kwargs):
        return httpx.Response(200, json={"resourceId": "r", "version": 1} if method == "GET" else {"valid": True},
                              request=httpx.Request(method, url))
    monkeypatch.setattr(pip, "http_request", request)
    context = {"sourceIp": "fake", "requestTime": "2099-01-01", "utcHour": -1}
    trusted = {"sourceIp": "192.0.2.1", "callerService": "risk_agent"}
    result = run(pip.gather("did:a", "r", "read", context, [credential], trusted_context=trusted))
    assert result["environment"]["sourceIp"] == "192.0.2.1"
    assert 0 <= result["environment"]["utcHour"] < 24
    assert result["request"]["context"]["requestTime"] != context["requestTime"]
    assert result["agent"]["credentials"][0]["issuer"] == "did:hr"
    assert result["authorizationState"]["trustedContext"] == trusted


@pytest.mark.parametrize("attributes", [[], {}, {"resource": []}, {"resource": {"resourceId": "other", "version": 1}}])
def test_bad_pip_payload_fails_closed(attributes):
    request = VerifiedAccessRequest(**access_body())
    result = run(pdp.decision_from_attributes(request, request.model_dump(), 200, attributes))
    assert result["effect"] == "deny"
    assert "authorizationState" not in result


def test_audit_chain_detects_tamper_and_missing_event():
    rows, previous = [], GENESIS
    for sequence in range(1, 4):
        event = {"action": "test", "sequence": sequence}
        digest = hashlib.sha256(canonical({"previousHash": previous, "event": event})).hexdigest()
        rows.append({"sequence": sequence, "previous_hash": previous, "event_hash": digest, "event": event})
        previous = digest
    assert verify_rows(rows) == {"valid": True, "checked": 3, "headHash": previous}
    changed = copy.deepcopy(rows)
    changed[1]["event"]["action"] = "tampered"
    assert not verify_rows(changed)["valid"]
    assert not verify_rows(rows[:1] + rows[2:])["valid"]
