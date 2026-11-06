"""
wallet_service/services/store_service.py

Encrypt and persist credentials.

--------------------------------------------------------------------------
FIX (combined Layer 1 + Layer 2 integration): this function previously
assumed `signed_vc` arrived as a compact JWT string ("header.payload.
signature") and tried to base64-decode its middle segment to recover the
VC JSON. The real VCs produced by vc_issuance are JSON-LD documents with
an embedded Data Integrity `proof` block, not JWTs -- there's no dot-
separated string to split at all, so this always raised
"Invalid JWT format" (or, after models.py's `signed_vc: str` type was
fixed to `dict`, would have failed even earlier at request validation).

Also fixed while here, all confirmed against vc_issuance.py's `_build_vc()`
output shape:
  - `issuer_did = vc.get("issuer")` stored the whole {"id": ...} dict where
    the DB column (and every caller of it) expects a plain string --
    changed to `vc.get("issuer", {}).get("id")`.
  - `expires_at` was read from `credentialSubject.expirationDate`, which
    never exists -- `expirationDate` is a top-level VC field, same as
    `issuanceDate`.
  - `kms_client` was used (via key_handle.get_derived_key) without ever
    being imported -- added `from clients import kms_client`, matching
    the identical import already used in wallet_service.py and
    presentation_builder.py.
--------------------------------------------------------------------------
"""

import json
import logging
import os
from datetime import datetime, timezone
from db.connection import get_session
from db.queries.wallet_queries import get_wallet
from db.queries.credential_queries import store_credential
from crypto import key_handle, aes_gcm
from clients import kms_client

logger = logging.getLogger(__name__)


async def store_vc(agent_did: str, signed_vc: dict) -> str:
    """
    Encrypt the given signed VC (a JSON-LD document) and persist it to
    the agent's wallet.

    Returns: vc_id
    """
    session = await get_session()

    try:
        # Get wallet and KMS key
        wallet = await get_wallet(session, agent_did)
        if not wallet:
            raise ValueError(f"Wallet not found for {agent_did}")

        kms_key_id = wallet[1]

        vc = signed_vc
        vc_json_bytes = json.dumps(vc).encode("utf-8")

        # Extract metadata
        vc_id = vc.get("id")
        credential_type = vc.get("type", [])
        issuer_did = vc.get("issuer", {}).get("id") if isinstance(vc.get("issuer"), dict) else vc.get("issuer")
        # FIX: asyncpg requires real datetime objects for timestamp columns
        # -- passing the raw ISO strings vc_issuance returns straight
        # through to store_credential() failed with "expected a
        # datetime.date or datetime.datetime instance, got 'str'" on
        # every single store. Parse them here.
        issued_at_raw = vc.get("issuanceDate")
        expires_at_raw = vc.get("expirationDate")
        issued_at = datetime.fromisoformat(issued_at_raw) if issued_at_raw else None
        expires_at = datetime.fromisoformat(expires_at_raw) if expires_at_raw else None
        proof_type = vc.get("proof", {}).get("type", "Ed25519Signature2020")

        # Extract BBS+ binding if present
        bbs_binding = None
        if proof_type == "BbsBlsSignature2020":
            bbs_binding = {
                "bbsPublicKey": vc.get("proof", {}).get("bbsPublicKey"),
                "messageCount": len(vc.get("credentialSubject", {}).get("messages", [])),
                "header": vc.get("proof", {}).get("header")
            }

        # Derive encryption key
        context_salt = agent_did.encode()
        derived_key = await key_handle.get_derived_key(kms_client, kms_key_id, context_salt)

        try:
            # Generate random 12-byte IV
            iv = os.urandom(12)

            # Encrypt the VC bytes
            ciphertext = aes_gcm.encrypt(vc_json_bytes, derived_key, iv)

            # Store to database
            await store_credential(
                session,
                agent_did=agent_did,
                vc_id=vc_id,
                credential_type=credential_type,
                issuer_did=issuer_did,
                issued_at=issued_at,
                expires_at=expires_at,
                encrypted_vc=ciphertext,
                iv=iv,
                proof_type=proof_type,
                bbs_binding=bbs_binding
            )

            logger.info(f"VC stored for {agent_did}: {vc_id}")
            return vc_id

        finally:
            # Zero the derived key immediately
            key_handle.zero_key(bytearray(derived_key))

    finally:
        await session.close()