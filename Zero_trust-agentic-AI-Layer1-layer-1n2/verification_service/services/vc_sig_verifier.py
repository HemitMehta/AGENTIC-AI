"""
services/vc_sig_verifier.py

Step 3 of verification pipeline: Per-VC signature verification.

Handles both Ed25519Signature2020 and BbsBlsSignatureProof2020.
"""

import logging
import json
import base64
from typing import Dict, Any, List

from clients.did_registry_client import get_did_registry_client, VerificationError
from services import zkp_verifier

logger = logging.getLogger(__name__)


async def verify_vc_signatures(vcs: List[Dict[str, Any]]) -> None:
    """
    Verify signatures on all VCs in the presentation.

    Args:
        vcs: List of VC dictionaries (already decoded)

    Raises:
        VerificationError if any VC signature verification fails
    """
    for vc in vcs:
        await _verify_single_vc_signature(vc)


async def _verify_single_vc_signature(vc: Dict[str, Any]) -> None:
    """
    Verify signature on a single VC.

    Args:
        vc: VC dictionary

    Raises:
        VerificationError if signature verification fails
    """
    vc_id = vc.get("id", "unknown")
    issuer_did = vc.get("issuer", {}).get("id")
    if not issuer_did:
        raise VerificationError(f"VC {vc_id} has no issuer DID")

    proof = vc.get("proof")
    if not proof:
        raise VerificationError(f"VC {vc_id} has no proof block")

    proof_type = proof.get("type")
    if not proof_type:
        raise VerificationError(f"VC {vc_id} proof has no type")

    if proof_type == "Ed25519Signature2020":
        await _verify_ed25519_signature(vc, issuer_did, vc_id)
    elif proof_type == "BbsBlsSignatureProof2020":
        await _verify_bbs_signature(vc, issuer_did, vc_id)
    else:
        raise VerificationError(f"Unsupported proof type: {proof_type}")


async def _verify_ed25519_signature(
    vc: Dict[str, Any],
    issuer_did: str,
    vc_id: str
) -> None:
    """
    Verify Ed25519 signature on VC.

    Args:
        vc:          VC dictionary
        issuer_did:  Issuer DID
        vc_id:       VC ID for logging

    Raises:
        VerificationError if verification fails
    """
    try:
        # Resolve issuer's DID Document
        did_client = get_did_registry_client()
        did_result = await did_client.resolve_did(issuer_did)
        did_document = did_result["didDocument"]

        # Extract public key
        verification_methods = did_document.get("verificationMethod", [])
        if not verification_methods:
            raise VerificationError(f"DID Document for {issuer_did} has no verificationMethod")

        first_vm = verification_methods[0]
        public_key_multibase = first_vm.get("publicKeyMultibase")
        if not public_key_multibase:
            raise VerificationError(f"No publicKeyMultibase in verificationMethod")

        # Decode multibase
        import base58
        if not public_key_multibase.startswith("z"):
            raise VerificationError("Unsupported multibase encoding")

        decoded = base58.b58decode(public_key_multibase[1:])
        if len(decoded) < 2 or decoded[:2] != bytes([0xed, 0x01]):
            raise VerificationError("Unsupported key type")

        public_key_bytes = decoded[2:]

        # Extract proof
        proof = vc.get("proof")
        signature_b64 = proof.get("proofValue")
        if not signature_b64:
            raise VerificationError(f"VC {vc_id} proof has no proofValue")

        # Decode signature
        padding = 4 - len(signature_b64) % 4
        if padding != 4:
            signature_b64 += "=" * padding
        signature_bytes = base64.urlsafe_b64decode(signature_b64)

        # Verify signature on VC content (without proof block)
        vc_without_proof = {k: v for k, v in vc.items() if k != "proof"}
        signed_data = json.dumps(vc_without_proof, sort_keys=True).encode()

        import nacl.signing
        import nacl.exceptions

        try:
            verify_key = nacl.signing.VerifyKey(public_key_bytes)
            verify_key.verify(signed_data, signature_bytes)
            logger.info(f"VC {vc_id} signature verified (Ed25519)")
        except nacl.exceptions.BadSignatureError:
            raise VerificationError(f"VC {vc_id} signature verification failed")

    except VerificationError:
        raise
    except Exception as e:
        logger.error(f"Ed25519 verification error for VC {vc_id}: {e}")
        raise VerificationError(f"VC {vc_id} signature verification failed: {e}")


async def _verify_bbs_signature(
    vc: Dict[str, Any],
    issuer_did: str,
    vc_id: str
) -> None:
    """
    Verify BBS+ derived proof on VC.

    Args:
        vc:          VC dictionary
        issuer_did:  Issuer DID
        vc_id:       VC ID for logging

    Raises:
        VerificationError if verification fails
    """
    try:
        # Resolve issuer's DID Document to get BBS+ public key
        did_client = get_did_registry_client()
        did_result = await did_client.resolve_did(issuer_did)
        did_document = did_result["didDocument"]

        # Extract BBS+ public key (format TBD based on actual DID Document structure)
        # For now, placeholder — will be refined when integrating with real BBS+ keys
        bbs_public_key = did_document.get("publicKeyBbs", b"")

        # Verify BBS+ proof
        result = await zkp_verifier.verify_bbs_derived_proof(vc, bbs_public_key)
        if not result:
            raise VerificationError(f"VC {vc_id} BBS+ proof verification failed")

        logger.info(f"VC {vc_id} signature verified (BBS+)")

    except VerificationError:
        raise
    except Exception as e:
        logger.error(f"BBS+ verification error for VC {vc_id}: {e}")
        raise VerificationError(f"VC {vc_id} BBS+ proof verification failed: {e}")
