"""
wallet_service/clients/vc_issuance_client.py

HTTP client for VC Issuance Service (SS4).

--------------------------------------------------------------------------
FIX (audit finding #8): this previously called
POST /credentials/issue/reputation with only {"signedVC": signed_vc}.

That route didn't exist -- vc_issuance_service.py exposes POST
/issue/reputation, but that route always issues AND signs a brand-new VC
using a centrally-authorized issuer_key_id, which is the wrong operation
for this caller: reputation_issuer.py already signs the VC itself with the
peer agent's own key and only wants this service to record it for audit.

A new, correctly-scoped endpoint was added on the server side:
POST /credentials/log/peer-issued -- see vc_issuance.py's
log_peer_issued_vc() and vc_issuance_service.py's matching route.

log_reputation_vc() below is updated to call that route and to pass
subject_did/issuer_did, which the new endpoint requires and the old
{"signedVC": ...}-only payload never provided.
--------------------------------------------------------------------------
"""

import httpx
import logging
from config import VC_ISSUANCE_URL, HTTP_CLIENT_TIMEOUT

logger = logging.getLogger(__name__)

_vc_client = None


async def init_vc_client():
    """Initialize VC Issuance HTTP client."""
    global _vc_client
    _vc_client = httpx.AsyncClient(base_url=VC_ISSUANCE_URL, timeout=HTTP_CLIENT_TIMEOUT)
    logger.info(f"VC Issuance client initialized: {VC_ISSUANCE_URL}")


async def close_vc_client():
    """Close VC Issuance HTTP client."""
    global _vc_client
    if _vc_client:
        await _vc_client.aclose()
        logger.info("VC Issuance client closed")


async def get_vc_client():
    """Get VC Issuance HTTP client."""
    if not _vc_client:
        await init_vc_client()
    return _vc_client


async def log_reputation_vc(signed_vc: str, subject_did: str, issuer_did: str):
    """
    Log a peer-issued reputation VC to SS4.

    Called after reputation VC is signed by the agent itself.
    SS4 persists it for audit but does not act as signing authority
    for this credential -- see log_peer_issued_vc() on the server side.

    Args:
        signed_vc:   The already-signed VC JWT string.
        subject_did: DID the credential is about (the agent being praised).
        issuer_did:  DID that signed the credential (the peer agent issuing it).
    """
    client = await get_vc_client()
    response = await client.post("/credentials/log/peer-issued", json={
        "signedVC": signed_vc,
        "subject_did": subject_did,
        "issuer_did": issuer_did,
    })
    response.raise_for_status()
    logger.info("Reputation VC logged to SS4")
    return response.json()
