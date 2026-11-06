#!/usr/bin/env python3
"""
test_attestation.py -- proves the fixed VC-attestation check in
ans_resolver_service actually verifies a real credential, using Layer 1's
real wallet_service + vc_verification + vc_issuance + trust_anchor
contracts (see ans_resolver_service/main.py's module docstring for the
full rationale of what was wrong before and what this now exercises).

Run AFTER `docker-compose up --build` has all 17 services healthy.

One-time setup this script needs that ISN'T yet automatic in Layer 1:
  trust_anchor's own signing key (env var ROOT_TRUST_KEY_ID, default
  "root-trust-anchor-key") is never auto-generated in KMS -- same class
  of gap as the ans_resolver/discovery_gateway signing keys you already
  fixed. Without it, POST /trust-anchor/issuers (needed to authorise a VC
  issuer) fails.

This script detects that on first run, generates the key, and tells you
exactly what to put in docker-compose.yml -- same pattern as before:

    python3 test_attestation.py          # first run: prints setup instructions
    # edit docker-compose.yml, restart trust_anchor
    python3 test_attestation.py          # second run: full PASS
"""

import base64
import json
import sys
import uuid

import httpx

BASE = "http://localhost"


def call(method: str, port: int, path: str, **kwargs) -> httpx.Response:
    url = f"{BASE}:{port}{path}"
    resp = httpx.request(method, url, timeout=15, **kwargs)
    print(f"{method} {url} -> {resp.status_code}")
    try:
        print(json.dumps(resp.json(), indent=2)[:1500])
    except Exception:
        print(resp.text[:500])
    print("-" * 70)
    return resp


def generate_key(agent_did: str, purpose: str = "assertionMethod") -> str:
    resp = call("POST", 8001, "/keys/generate", json={"agent_did": agent_did, "key_purpose": purpose})
    resp.raise_for_status()
    return resp.json()["keyId"]


def register_did(public_key_b64: str, key_id: str, owner_did: str, agent_label: str) -> str:
    resp = call(
        "POST", 8002, "/dids/register",
        json={
            "public_key_b64": public_key_b64,
            "key_id": key_id,
            "owner_did": owner_did,
            "controller_dids": [],
            "scope_of_behavior": {"description": f"{agent_label} for attestation test"},
            "toolset": [],
            "model_hash": "",
            "aibom_ref": "",
            "did_method": "key",
            "metadata": {"agentId": agent_label},
        },
    )
    resp.raise_for_status()
    return resp.json()["did"]


def main() -> int:
    label = uuid.uuid4().hex[:8]

    # ------------------------------------------------------------------
    # 0. One-time check: does trust_anchor's own signing key exist yet?
    #    We probe this indirectly by attempting the real add_issuer call
    #    later; if it fails specifically on signing, we stop and explain.
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # 1. Create the ISSUER identity (an audit authority that will issue
    #    a ComplianceVC) -- needs its own key + DID, same as any agent.
    # ------------------------------------------------------------------
    issuer_key_info = call("POST", 8001, "/keys/generate",
                            json={"agent_did": f"issuer-{label}", "key_purpose": "assertionMethod"})
    issuer_key_info.raise_for_status()
    issuer_key = issuer_key_info.json()
    issuer_did = register_did(issuer_key["publicKey"], issuer_key["keyId"], "did:web:test-owner", f"issuer-{label}")
    print(f"Issuer DID: {issuer_did}  (key_id={issuer_key['keyId']})")

    # ------------------------------------------------------------------
    # 2. Authorise the issuer in trust_anchor for ComplianceVC/enterprise.
    #    This is the step that needs trust_anchor's ROOT_TRUST_KEY_ID to
    #    already exist in KMS.
    # ------------------------------------------------------------------
    resp = call(
        "POST", 8003, "/trust-anchor/issuers",
        json={"issuerDID": issuer_did, "credentialTypes": ["ComplianceVC"], "trustDomain": "enterprise"},
    )
    if resp.status_code != 200:
        root_key_id = generate_key("root-trust-anchor", "assertionMethod")
        print("=" * 70)
        print("SETUP NEEDED: trust_anchor could not sign the updated trust")
        print("document because its own signing key doesn't exist in KMS yet.")
        print()
        print(f"A key has now been generated for you: {root_key_id}")
        print()
        print("In docker-compose.yml, under the `trust_anchor` service's")
        print("`environment:` block, add:")
        print(f"    - ROOT_TRUST_KEY_ID={root_key_id}")
        print()
        print("Then restart just that service:")
        print("    docker-compose up -d --build trust_anchor")
        print()
        print("...and re-run this script.")
        print("=" * 70)
        return 1

    # ------------------------------------------------------------------
    # 3. Create the SUBJECT agent (the one being discovered/attested).
    # ------------------------------------------------------------------
    agent_key_info = call("POST", 8001, "/keys/generate",
                           json={"agent_did": f"agent-{label}", "key_purpose": "authentication"})
    agent_key_info.raise_for_status()
    agent_key = agent_key_info.json()
    agent_did = register_did(agent_key["publicKey"], agent_key["keyId"], "did:web:test-owner", f"agent-{label}")
    print(f"Subject DID: {agent_did}")

    # ------------------------------------------------------------------
    # 4. Initialise the agent's wallet.
    # ------------------------------------------------------------------
    resp = call("POST", 8007, f"/wallets/{agent_did}/init")
    if resp.status_code != 200:
        print("Wallet init failed -- see wallet_service logs.")
        return 1

    # ------------------------------------------------------------------
    # 5. Issue a ComplianceVC to the agent, signed by the issuer.
    # ------------------------------------------------------------------
    resp = call(
        "POST", 8004, "/issue/compliance",
        json={
            "subject_did": agent_did,
            "issuer_did": issuer_did,
            "issuer_key_id": issuer_key["keyId"],
            "claims": {
                "complianceFramework": "SOX",
                "auditDate": "2026-01-01",
                "auditRef": f"audit-{label}",
                "auditBodyDID": issuer_did,
                "scope": "attestation-smoke-test",
            },
            "trust_domain": "enterprise",
        },
    )
    if resp.status_code != 200:
        print("VC issuance failed -- check vc_issuance logs (likely trust_anchor rejected the issuer).")
        return 1
    signed_vc = resp.json()["signedVC"]

    # ------------------------------------------------------------------
    # 6. Store the signed VC in the agent's wallet.
    # ------------------------------------------------------------------
    resp = call("POST", 8007, f"/wallets/{agent_did}/store",
                json={"agent_did": agent_did, "signed_vc": signed_vc})
    if resp.status_code != 200:
        print("Storing VC in wallet failed.")
        return 1

    # ------------------------------------------------------------------
    # 7. Register the agent in the ANS.
    # ------------------------------------------------------------------
    capability = "SmokeTest.AttestationCheck"
    resp = call(
        "POST", 8008, "/register",
        json={
            "ansName": f"acp://attest-agent-{label}.SmokeTest.AttestationCheck.TestProvider.v1.0.0.dev",
            "agentDid": agent_did,
            "capability": capability,
            "provider": "TestProvider",
            "version": "1.0.0",
            "serviceEndpoint": "https://example.invalid/agent",
        },
    )
    if resp.status_code not in (200, 201):
        print("ANS registration failed.")
        return 1

    # ------------------------------------------------------------------
    # 8. Diagnostic: call the ANS Resolver directly first, so we can see
    #    the actual relevantVcSnippets (verified/revoked/issuer) rather
    #    than just the Gateway's opaque resolutionStatus. If verified
    #    comes back false, check `docker-compose logs ans_resolver_service`
    #    for the specific pipeline step/reason it failed on.
    # ------------------------------------------------------------------
    call(
        "POST", 8009, "/resolveByCapability",
        json={"capability": capability, "requiredAttestations": ["ComplianceVC"]},
    )

    # ------------------------------------------------------------------
    # 9. Discover WITH requiredAttestations -- the real test, via the
    #    Gateway (the actual entry point Layer 3 will call).
    # ------------------------------------------------------------------
    resp = call(
        "POST", 8012, "/discover",
        json={"capability": capability, "requiredAttestations": ["ComplianceVC"]},
    )
    if resp.status_code != 200:
        print("Gateway discovery failed.")
        return 1

    body = resp.json()
    ok = body.get("resolutionStatus") == "success" and body.get("selectedAgent") == agent_did
    print("RESULT:", "PASS" if ok else "FAIL (see response above)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())