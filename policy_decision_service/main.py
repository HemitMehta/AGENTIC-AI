"""Layer 3 Policy Decision Point (PDP) with default-deny ABAC/PBAC evaluation."""

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, Request
from pydantic import BaseModel, Field
from layer3_common.security import install, request as http_request
from layer3_common.models import RevalidationRequest
from layer3_common.policy import Policy, condition_matches as _condition_matches, path_value as _path
from layer3_common.models import VerifiedAccessRequest, TrustedContext

PAP_URL = os.getenv("PAP_URL", "https://policy_administration_service:8013")
PIP_URL = os.getenv("PIP_URL", "https://policy_information_service:8014")
TIMEOUT = float(os.getenv("DOWNSTREAM_TIMEOUT_SECONDS", "5"))

app = FastAPI(title="Layer 3 Policy Decision Point", version="1.0.0")
install(app, "pdp")


DecisionRequest = VerifiedAccessRequest


def _selector_matches(policy: dict, attributes: dict) -> bool:
    resource = attributes["resource"]
    action = attributes["request"]["action"]
    if policy.get("resourceIds") and resource.get("resourceId") not in policy["resourceIds"]:
        return False
    if policy.get("resourceTypes") and resource.get("resourceType") not in policy["resourceTypes"]:
        return False
    if action not in policy.get("actions", []) and "*" not in policy.get("actions", []):
        return False
    required = set(policy.get("requiredCredentialTypes", []))
    presented = set(attributes["agent"].get("credentialTypes", []))
    return required.issubset(presented)


def _evaluate(policies: list[dict], attributes: dict) -> tuple[str, list[dict], list[str]]:
    # A malformed deny policy must never disappear while a permit remains usable.
    try:
        if not isinstance(policies, list):
            raise ValueError("Expected a policy list")
        policies = [Policy.model_validate(policy).model_dump(mode="json") for policy in policies]
    except (ValueError, TypeError):
        return "deny", [], ["Invalid policy set; default deny applied"]
    matched: list[dict] = []
    for policy in policies:
        if policy["active"] and _selector_matches(policy, attributes) and all(
            _condition_matches(condition, attributes) for condition in policy.get("conditions", [])
        ):
            matched.append(policy)

    denying = [policy for policy in matched if policy["effect"] == "deny"]
    if denying:
        refs = [{"policyId": p["policyId"], "version": p["version"]} for p in denying]
        return "deny", refs, ["An explicit deny policy matched"]
    permitting = [policy for policy in matched if policy["effect"] == "permit"]
    if permitting:
        refs = [{"policyId": p["policyId"], "version": p["version"]} for p in permitting]
        return "permit", refs, ["All required attributes and policy conditions matched"]
    return "deny", [], ["No active permit policy matched; default deny applied"]


async def _post_json(url: str, body: dict) -> tuple[int, dict]:
    try:
        response = await http_request("POST", url, json=body)
        try:
            data = response.json()
        except ValueError:
            data = {"detail": response.text}
        return response.status_code, data
    except httpx.RequestError as exc:
        return 503, {"detail": str(exc)}


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "policy_decision_point", "combiningAlgorithm": "deny-overrides"}


@app.post("/decisions")
async def decide(request: DecisionRequest, http: Request):
    if http.state.caller != "pep":
        request.trustedContext = TrustedContext(sourceIp=http.client.host if http.client else None,
                                               callerService=http.state.caller)
    request_body = request.model_dump(mode="json")
    status_code, attributes = await _post_json(f"{PIP_URL}/attributes/collect", request_body)
    return await decision_from_attributes(request, request_body, status_code, attributes)


@app.post("/decisions/revalidate")
async def revalidate(request: RevalidationRequest):
    body = request.model_dump(mode="json")
    status, attributes = await _post_json(f"{PIP_URL}/attributes/revalidate", body)
    return await decision_from_attributes(request, body, status, attributes)


async def decision_from_attributes(request, request_body, status_code, attributes):
    decision_id = str(uuid.uuid4())
    evaluated_at = datetime.now(timezone.utc)
    context_hash = hashlib.sha256(
        json.dumps(request_body["context"], sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if status_code != 200:
        return {
            "decisionId": decision_id, "effect": "deny", "agentDid": request.agentDid,
            "resourceId": request.resourceId, "action": request.action, "matchedPolicies": [],
            "reasons": ["PIP could not establish verified attributes"],
            "contextHash": context_hash, "evaluatedAt": evaluated_at,
        }

    if (not isinstance(attributes, dict) or not isinstance(attributes.get("resource"), dict)
            or attributes["resource"].get("resourceId") != request.resourceId
            or type(attributes["resource"].get("version")) is not int
            or not isinstance(attributes.get("agent"), dict) or attributes["agent"].get("did") != request.agentDid
            or not isinstance(attributes.get("request"), dict) or attributes["request"].get("action") != request.action):
        return await decision_from_attributes(request, request_body, 503, {})

    try:
        response = await http_request("GET", f"{PAP_URL}/policies", params={"active": "true"})
        response.raise_for_status()
        policies = response.json().get("policies", [])
        effect, matched, reasons = _evaluate(policies, attributes)
    except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
        effect, matched, reasons = "deny", [], ["PAP unavailable or returned invalid policy data"]

    return {
        "decisionId": decision_id, "effect": effect, "agentDid": request.agentDid,
        "resourceId": request.resourceId, "action": request.action, "matchedPolicies": matched,
        "reasons": reasons, "contextHash": context_hash, "evaluatedAt": evaluated_at,
        "resourceVersion": attributes["resource"]["version"],
        "resource": attributes["resource"],
        "authorizationState": attributes.get("authorizationState") if effect == "permit" else None,
    }
