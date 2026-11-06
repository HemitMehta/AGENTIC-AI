import json
import time
from datetime import datetime

from fastapi import HTTPException
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .common import canonical, check_signature, key_from_kms, kms_public


async def verify_discovery(client, response, query, gateway_key, resolver_key):
    if response.get("resolutionStatus") != "success":
        raise HTTPException(404, "No trusted agent matched the discovery criteria")
    gateway_payload = {k: v for k, v in response.items() if k != "gatewaySignature"}
    gateway_public = key_from_kms(await kms_public(client, gateway_key))
    # The gateway's existing wire signature uses Python JSON's default separators.
    check_signature(gateway_public, response.get("gatewaySignature"),
                    json.dumps(gateway_payload, sort_keys=True).encode("utf-8"))
    if response.get("requestId") != query["requestId"]:
        raise HTTPException(403, "Discovery response belongs to another request")
    try:
        timestamp = datetime.fromisoformat(response["resolvedAt"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None or not -5 <= time.time() - timestamp.timestamp() <= 60:
            raise ValueError("Stale discovery response")
    except (KeyError, TypeError, ValueError) as exc:
        raise HTTPException(403, "Discovery response is stale or has no timestamp") from exc
    selected = next((c for c in response.get("candidates", [])
                     if c.get("agentDid") == response.get("selectedAgent")
                     and c.get("serviceEndpoint") == response.get("endpoint")), None)
    record = selected.get("ansRecord") if selected else None
    if not record or record.get("signingKeyId") != resolver_key or record.get("signatureAlgorithm") != "Ed25519":
        raise HTTPException(403, "Missing record signed by the trusted ANS resolver")
    record_public = key_from_kms(await kms_public(client, resolver_key))
    check_signature(record_public, record.get("ansRecordSignature"),
                    canonical({k: v for k, v in record.items() if k != "ansRecordSignature"}))
    if record.get("agentDid") != response["selectedAgent"] or record.get("serviceEndpoint") != response["endpoint"]:
        raise HTTPException(403, "Selected endpoint does not match the signed ANS record")
    if record.get("capability") != query["capability"]:
        raise HTTPException(403, "Agent capability does not match")
    if query.get("provider") and record.get("provider") != query["provider"]:
        raise HTTPException(403, "Agent provider does not match")
    if query.get("protocol") not in [p.get("protocol") for p in record.get("protocolExtensions", [])]:
        raise HTTPException(403, "Agent does not advertise the required protocol")
    version = record.get("version", "")
    if query.get("versionPrefix") and not version.startswith(query["versionPrefix"]):
        raise HTTPException(403, "Agent version prefix does not match")
    try:
        if query.get("versionRange") and Version(version) not in SpecifierSet(query["versionRange"].replace(" ", ",")):
            raise HTTPException(403, "Agent version is outside the required range")
    except (InvalidSpecifier, InvalidVersion) as exc:
        raise HTTPException(422, "Invalid version constraint") from exc
    verified = {s.get("type") for s in record.get("relevantVcSnippets", [])
                if s.get("verified") is True and s.get("revoked") is False}
    if not set(query["requiredAttestations"]).issubset(verified):
        raise HTTPException(403, "Required attestation is not verified")
    return record
