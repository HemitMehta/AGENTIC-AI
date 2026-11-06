"""
wallet_service/crypto/jwt_builder.py

VP JWT construction and serialization.

--------------------------------------------------------------------------
FIX (combined Layer 1 + Layer 2 integration): build_vp_json() never set an
"iss" claim, but verification_service's vp_sig_verifier.py reads
`payload.get("iss")` to know which DID's public key to verify against --
every VP verification failed with "VP missing 'iss' (issuer) claim" before
even reaching the signature check. Added "iss": issuer_did (kept "holder"
too, since that's the correct VC-spec field name and other code/future
readers may expect it).

Also added header_and_payload_b64() as a new helper: see the matching fix
in presentation_builder.py for why the *previous* signing step (signing
raw JSON bytes) could never actually verify, and why the fix is to sign
over the header/payload's base64url encoding instead -- the standard
compact-JWT signing input.
--------------------------------------------------------------------------
"""

import json
import base64
import logging

logger = logging.getLogger(__name__)


def build_vp_json(
    verifiable_credentials: list,
    nonce: str,
    verifier_did: str,
    issuer_did: str
) -> dict:
    """
    Build a Verifiable Presentation JSON structure.

    Args:
        verifiable_credentials: List of decrypted VC objects
        nonce: Verifier's nonce (for replay protection)
        verifier_did: DID of the verifier
        issuer_did: DID of the presenter (agent)

    Returns:
        VP JSON dict (without proof yet)
    """

    return {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiablePresentation"],
        "verifiableCredential": verifiable_credentials,
        "holder": issuer_did,
        "iss": issuer_did,
        "proof": {
            "type": "Ed25519Signature2020",
            "challenge": nonce,
            "domain": verifier_did,
            "created": json.dumps({"placeholder": "timestamp_will_be_added_at_signing"})
        }
    }


def header_and_payload_b64(header: dict, payload: dict) -> tuple[str, str]:
    """
    Base64url-encode (no padding) the JWT header and payload individually.

    This is the standard compact-JWT signing input: the actual bytes a
    verifier signs/checks are `f"{header_b64}.{payload_b64}"`, NOT the
    raw JSON payload bytes. Exposed as its own function so the caller
    (presentation_builder.py) can sign exactly this string, rather than
    signing something else and hoping it lines up with what a verifier
    reconstructs.
    """
    header_json = json.dumps(header, separators=(',', ':'), sort_keys=True)
    payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=True)

    header_b64 = base64.urlsafe_b64encode(header_json.encode()).decode().rstrip('=')
    payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip('=')
    return header_b64, payload_b64


def serialize_vp_jwt(header_b64: str, payload_b64: str, signature_bytes: bytes) -> str:
    """
    Assemble the final compact JWT string from already-encoded header and
    payload segments (see header_and_payload_b64()) plus the raw signature
    bytes computed over exactly `f"{header_b64}.{payload_b64}"`.

    Returns:
        JWT string in format: header.payload.signature (all base64url)
    """
    signature_b64 = base64.urlsafe_b64encode(signature_bytes).decode().rstrip('=')
    return f"{header_b64}.{payload_b64}.{signature_b64}"