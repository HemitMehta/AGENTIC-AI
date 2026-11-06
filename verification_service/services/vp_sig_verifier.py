"""
services/vp_sig_verifier.py

Step 1 of verification pipeline: VP signature verification.

Verifies that the VP JWT is signed by the claimed presenting agent.
"""

import logging
import json
import base64
from typing import Dict, Any, Tuple

from clients.did_registry_client import get_did_registry_client, VerificationError

logger = logging.getLogger(__name__)


async def verify_vp_signature(vp_jwt: str) -> Tuple[str, Dict[str, Any]]:
    """
    Verify the VP JWT signature.

    Args:
        vp_jwt: Signed VP JWT string

    Returns:
        (issuer_did, decoded_payload)

    Raises:
        VerificationError if signature verification fails
    """
    try:
        # Decode JWT (without verification first) to extract issuer
        parts = vp_jwt.split(".")
        if len(parts) != 3:
            raise VerificationError("Invalid JWT format (expected 3 parts)")

        # Decode payload (second part)
        payload_b64 = parts[1]
        # Add padding if needed
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        payload_json = base64.urlsafe_b64decode(payload_b64).decode()
        payload = json.loads(payload_json)

        issuer_did = payload.get("iss")
        if not issuer_did:
            raise VerificationError("VP missing 'iss' (issuer) claim")

        # Resolve issuer's DID Document
        did_client = get_did_registry_client()
        did_result = await did_client.resolve_did(issuer_did)
        did_document = did_result["didDocument"]

        # Extract public key from DID Document
        verification_methods = did_document.get("verificationMethod", [])
        if not verification_methods:
            raise VerificationError(f"DID Document for {issuer_did} has no verificationMethod")

        first_vm = verification_methods[0]
        public_key_multibase = first_vm.get("publicKeyMultibase")
        if not public_key_multibase:
            raise VerificationError(f"No publicKeyMultibase in verificationMethod")

        # Decode multibase to raw public key bytes
        # multibase format: 'z' + base58(multicodec prefix + raw key)
        if not public_key_multibase.startswith("z"):
            raise VerificationError("Unsupported multibase encoding")

        import base58
        decoded = base58.b58decode(public_key_multibase[1:])

        # Check Ed25519 multicodec prefix (0xed 0x01)
        if len(decoded) < 2 or decoded[:2] != bytes([0xed, 0x01]):
            raise VerificationError("Unsupported key type in DID Document")

        public_key_bytes = decoded[2:]

        # Verify JWT signature using Ed25519
        import nacl.signing
        import nacl.exceptions

        try:
            verify_key = nacl.signing.VerifyKey(public_key_bytes)
            # JWT signature is the third part, base64url-encoded
            signature_b64 = parts[2]
            padding = 4 - len(signature_b64) % 4
            if padding != 4:
                signature_b64 += "=" * padding
            signature_bytes = base64.urlsafe_b64decode(signature_b64)

            # Verify: signed data is {header}.{payload}
            signed_data = f"{parts[0]}.{parts[1]}".encode()
            verify_key.verify(signed_data, signature_bytes)

            logger.info(f"VP signature verified for issuer: {issuer_did}")
            return issuer_did, payload

        except nacl.exceptions.BadSignatureError:
            raise VerificationError("VP signature verification failed")

    except VerificationError:
        raise
    except Exception as e:
        logger.error(f"VP signature verification error: {e}")
        raise VerificationError(f"VP signature verification failed: {e}")
