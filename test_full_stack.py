#!/usr/bin/env python3
"""
test_full_stack.py -- End-to-end smoke test across the combined Layer 1 +
Layer 2 docker-compose stack.

Run AFTER `docker-compose up --build` has all 17 services healthy:

    python3 test_full_stack.py

What it does, in order:
  1. KMS (8001):        generate an Ed25519 key for a test agent.
  2. DID Registry(8002): register a did:key DID using that key.
  3. ANS Registry(8008): register the agent under a capability.
  4. Reputation(8011):   submit feedback for that agent (best-effort VC).
  5. Gateway (8012):     discover the agent by capability -- this is the
                         one call that exercises the full Layer 1 + Layer 2
                         chain together.

Each step prints its HTTP status and response so you can see exactly where
things stand if something in your environment differs from what's assumed
here (see the "IMPORTANT -- contract assumption" notes left in
ans_resolver_service/main.py and discovery_gateway/main.py for the two
known, documented gaps: VC-attestation verification and revocation lookup
are not yet wired to the real vc_verification / status_list_service data
model, so requiredAttestations will currently always come back
unverified -- everything else in this script exercises real, working
contracts).
"""

import base64
import json
import sys
import time
import uuid

import httpx

BASE = "http://localhost"


def call(method: str, port: int, path: str, **kwargs) -> httpx.Response:
    url = f"{BASE}:{port}{path}"
    resp = httpx.request(method, url, timeout=10, **kwargs)
    print(f"{method} {url} -> {resp.status_code}")
    try:
        print(json.dumps(resp.json(), indent=2)[:2000])
    except Exception:
        print(resp.text[:500])
    print("-" * 70)
    return resp


def main() -> int:
    agent_label = f"test-agent-{uuid.uuid4().hex[:8]}"

    # ------------------------------------------------------------------
    # 1. KMS: generate a key for the agent
    # ------------------------------------------------------------------
    resp = call(
        "POST", 8001, "/keys/generate",
        json={"agent_did": agent_label, "key_purpose": "authentication"},
    )
    if resp.status_code != 200:
        print("KMS key generation failed -- is the stack up and healthy?")
        return 1
    key_info = resp.json()
    public_key_b64 = key_info["publicKey"]
    key_id = key_info["keyId"]

    # ------------------------------------------------------------------
    # 2. DID Registry: register a did:key DID for this agent
    # ------------------------------------------------------------------
    resp = call(
        "POST", 8002, "/dids/register",
        json={
            "public_key_b64": public_key_b64,
            "key_id": key_id,
            "owner_did": "did:web:test-owner",
            "controller_dids": [],
            "scope_of_behavior": {"description": "full-stack smoke test agent"},
            "toolset": [],
            "model_hash": "",
            "aibom_ref": "",
            "did_method": "key",
            "metadata": {"agentId": agent_label},
        },
    )
    if resp.status_code != 200:
        print("DID registration failed.")
        return 1
    agent_did = resp.json()["did"]
    print(f"Registered DID: {agent_did}")

    # ------------------------------------------------------------------
    # 3. ANS Registry: register the agent under a capability
    # ------------------------------------------------------------------
    capability = "SmokeTest.FullStack"
    resp = call(
        "POST", 8008, "/register",
        json={
            "ansName": f"acp://{agent_label}.SmokeTest.FullStack.TestProvider.v1.0.0.dev",
            "agentDid": agent_did,
            "capability": capability,
            "provider": "TestProvider",
            "version": "1.0.0",
            "serviceEndpoint": "https://example.invalid/agent",
        },
    )
    if resp.status_code not in (200, 201):
        print("ANS registration failed -- did_registry may not have resolved the DID in time.")
        return 1

    # ------------------------------------------------------------------
    # 4. Reputation: submit feedback (best-effort VC issuance)
    # ------------------------------------------------------------------
    call(
        "POST", 8011, "/feedback",
        json={
            "raterDid": "did:web:test-rater",
            "ratedAgentDid": agent_did,
            "rating": 5,
            "ansCapabilityContext": capability,
            "taskId": "smoke-test-task-1",
            "comment": "full stack smoke test",
            "issueVc": True,
        },
    )

    # ------------------------------------------------------------------
    # 5. Discovery Gateway: the real end-to-end call
    # ------------------------------------------------------------------
    resp = call(
        "POST", 8012, "/discover",
        json={"capability": capability},
    )
    if resp.status_code != 200:
        print("Gateway discovery failed.")
        return 1

    body = resp.json()
    ok = (
        body.get("resolutionStatus") == "success"
        and body.get("selectedAgent") == agent_did
    )
    print("RESULT:", "PASS" if ok else "UNEXPECTED RESPONSE (see above)")
    print("gatewaySignature present:", bool(body.get("gatewaySignature")))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())