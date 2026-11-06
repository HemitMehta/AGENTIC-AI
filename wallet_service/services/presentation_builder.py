"""
wallet_service/services/presentation_builder.py

Construct and sign VPs.

--------------------------------------------------------------------------
FIX (combined Layer 1 + Layer 2 integration): this previously signed the
raw JSON bytes of the full VP payload (`json.dumps(vp_json, ...)`.encode())
and then separately re-encoded that same payload as base64url inside
serialize_vp_jwt(). But verification_service's vp_sig_verifier.py verifies
the signature over `f"{header_b64}.{payload_b64}"` -- the standard compact
JWT signing input -- not over the raw JSON bytes. Those are different byte
sequences, so the signature could never actually verify. Fixed to encode
header+payload to base64url FIRST (jwt_builder.header_and_payload_b64),
sign exactly that dot-joined string, then assemble the final JWT from the
already-encoded parts plus the resulting signature.

Also fixed: kms_client.sign_payload() returns a signature as STANDARD
base64 (see kms.py's own docstring: "raw base64 (colon-free)"), but this
file decoded it with `base64.urlsafe_b64decode` -- the wrong alphabet
(`+`/`/` vs `-`/`_`), which corrupts or outright fails to decode any
signature containing those characters. Changed to `base64.b64decode`.
--------------------------------------------------------------------------
"""

import json
import logging
import base64
from datetime import datetime, timezone
from db.connection import get_session
from db.queries.wallet_queries import get_wallet
from db.queries.credential_queries import get_credential_by_vc_id
from crypto import key_handle, aes_gcm, jwt_builder
from clients import kms_client, did_registry_client

logger = logging.getLogger(__name__)


async def _get_did_signing_key_id(agent_did: str) -> str:
    """
    Return the KMS key id referenced by the agent's DID verification method.

    Wallet storage has its own KMS key for encryption. Presentations must be
    signed with the key advertised in the DID document, because verifiers
    resolve the DID and check the VP signature against that public key.
    """
    did_response = await did_registry_client.resolve_did(agent_did)
    did_data = did_response.get("data", did_response)
    did_document = did_data.get("didDocument", did_data)

    auth_methods = did_document.get("authentication", [])
    verification_methods = did_document.get("verificationMethod", [])
    if not verification_methods:
        raise ValueError(f"DID document for {agent_did} has no verificationMethod")

    method_id = auth_methods[0] if auth_methods else verification_methods[0].get("id")
    if isinstance(method_id, dict):
        method_id = method_id.get("id")
    if not method_id:
        raise ValueError(f"DID document for {agent_did} has no authentication method")

    matching_method = next(
        (method for method in verification_methods if method.get("id") == method_id),
        verification_methods[0],
    )
    method_id = matching_method.get("id", method_id)
    if "#" not in method_id:
        raise ValueError(f"DID verification method id has no key fragment: {method_id}")

    return method_id.rsplit("#", 1)[1]


async def build_presentation(
    agent_did: str,
    required_types: list,
    verifier_did: str,
    nonce: str,
    credentials: list  # credential rows from selective_disclosure
) -> str:
    """
    Build and sign a Verifiable Presentation.

    Returns: VP JWT
    """
    session = await get_session()

    try:
        # Get wallet
        wallet = await get_wallet(session, agent_did)
        if not wallet:
            raise ValueError(f"Wallet not found for {agent_did}")

        kms_key_id = wallet[1]

        # Decrypt each credential
        decrypted_vcs = []
        for row in credentials:
            encrypted_vc = row[8]  # encrypted_vc column
            iv = row[9]  # iv column

            # Derive key
            context_salt = agent_did.encode()
            derived_key = await key_handle.get_derived_key(kms_client, kms_key_id, context_salt)

            try:
                vc_bytes = aes_gcm.decrypt(encrypted_vc, derived_key, iv)
                vc_json = json.loads(vc_bytes)
                decrypted_vcs.append(vc_json)
            finally:
                key_handle.zero_key(bytearray(derived_key))

        # Build VP JSON
        vp_json = jwt_builder.build_vp_json(
            verifiable_credentials=decrypted_vcs,
            nonce=nonce,
            verifier_did=verifier_did,
            issuer_did=agent_did
        )

        # Encode header + payload BEFORE signing -- sign exactly the bytes
        # a verifier will reconstruct and check (see module docstring).
        header = {"alg": "EdDSA", "typ": "JWT"}
        header_b64, payload_b64 = jwt_builder.header_and_payload_b64(header, vp_json)
        signing_input = f"{header_b64}.{payload_b64}".encode()

        signing_key_id = await _get_did_signing_key_id(agent_did)
        signature_b64_str = await kms_client.sign_payload(signing_key_id, signing_input)
        signature_bytes = base64.b64decode(signature_b64_str)

        # Serialize as JWT
        vp_jwt = jwt_builder.serialize_vp_jwt(header_b64, payload_b64, signature_bytes)

        logger.info(f"Presentation built for {agent_did} to {verifier_did}")
        return vp_jwt

    finally:
        await session.close()
