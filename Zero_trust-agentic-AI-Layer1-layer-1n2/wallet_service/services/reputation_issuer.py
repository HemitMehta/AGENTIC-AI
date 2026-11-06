"""
wallet_service/services/reputation_issuer.py

Peer-issued reputation VC generation.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from clients import kms_client, did_registry_client, vc_issuance_client

logger = logging.getLogger(__name__)


async def issue_reputation_vc(
    issuer_did: str,
    target_did: str,
    task_context: str,
    claims: dict
) -> str:
    """
    Issue a peer-signed reputation VC.

    Args:
        issuer_did: Agent issuing the reputation (must be resolved and active)
        target_did: Agent being praised (must be resolved and exist)
        task_context: Context of the task/relationship
        claims: Custom reputation claims

    Returns:
        Signed VC JWT
    """

    # Verify both DIDs exist and are active
    issuer_doc = await did_registry_client.resolve_did(issuer_did)
    target_doc = await did_registry_client.resolve_did(target_did)

    if issuer_doc.get("lifecycleStatus") != "active":
        raise ValueError(f"Issuer {issuer_did} is not active")

    # Build reputation VC JSON
    vc_id = f"urn:uuid:{uuid.uuid4()}"
    now_iso = datetime.now(timezone.utc).isoformat()

    vc_json = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": vc_id,
        "type": ["VerifiableCredential", "ReputationCredential"],
        "issuer": issuer_did,
        "issuanceDate": now_iso,
        "credentialSubject": {
            "id": target_did,
            "taskContext": task_context,
            "claims": claims
        }
    }

    # Sign via KMS
    vc_json_bytes = json.dumps(vc_json, separators=(',', ':'), sort_keys=True).encode()
    signature_b64 = await kms_client.sign_payload(kms_client, vc_json_bytes)

    # Build JWT (header.payload.signature)
    import base64
    header = {"alg": "EdDSA", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(vc_json_bytes).decode().rstrip('=')
    vp_jwt = f"{header_b64}.{payload_b64}.{signature_b64}"

    # Log to SS4 (peer issuance, not authority)
    # FIX: log_reputation_vc() now requires subject_did/issuer_did, since
    # the corrected server-side endpoint (POST /credentials/log/peer-issued)
    # needs them to persist the audit record -- the old {"signedVC": ...}
    # -only payload never provided them. See vc_issuance_client.py.
    await vc_issuance_client.log_reputation_vc(vp_jwt, target_did, issuer_did)

    logger.info(f"Reputation VC issued by {issuer_did} for {target_did}")
    return vp_jwt
