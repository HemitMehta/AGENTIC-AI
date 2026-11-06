"""
services/trust_anchor_checker.py

Step 4 of verification pipeline: Trust anchor validation.

Validates that each issuer is authorized to issue each credential type
in the specified trust domain.
"""

import logging
from typing import Dict, Any, List

from clients.trust_anchor_client import get_trust_anchor_client, VerificationError
from cache import redis_client

logger = logging.getLogger(__name__)


async def validate_issuers(vcs: List[Dict[str, Any]], trust_domain: str = "enterprise") -> None:
    """
    Validate that all VC issuers are authorized in the trust anchor.

    Args:
        vcs:          List of VC dictionaries
        trust_domain: Trust domain (default "enterprise")

    Raises:
        VerificationError if any issuer is not authorized
    """
    for vc in vcs:
        await _validate_issuer(vc, trust_domain)


async def _validate_issuer(vc: Dict[str, Any], trust_domain: str) -> None:
    """
    Validate a single issuer.

    Args:
        vc:          VC dictionary
        trust_domain: Trust domain

    Raises:
        VerificationError if issuer not authorized
    """
    vc_id = vc.get("id", "unknown")
    issuer_did = vc.get("issuer", {}).get("id")
    if not issuer_did:
        raise VerificationError(f"VC {vc_id} has no issuer DID")

    # Extract credential type(s)
    vc_type = vc.get("type", [])
    if isinstance(vc_type, str):
        vc_type = [vc_type]

    # Filter out "VerifiableCredential" base type
    credential_types = [t for t in vc_type if t != "VerifiableCredential"]
    if not credential_types:
        raise VerificationError(f"VC {vc_id} has no specific credential type")

    # Validate for each specific type
    for cred_type in credential_types:
        try:
            ta_client = get_trust_anchor_client()
            result = await ta_client.validate_issuer(issuer_did, cred_type, trust_domain)

            if not result.get("authorised"):
                reason = result.get("reason", "Issuer not authorized")
                raise VerificationError(
                    f"Issuer {issuer_did} not authorized for {cred_type}: {reason}"
                )

            logger.info(f"VC {vc_id}: issuer {issuer_did} authorized for {cred_type}")

        except VerificationError:
            raise
        except Exception as e:
            logger.error(f"Trust anchor validation error: {e}")
            raise VerificationError(f"Trust anchor validation failed: {e}")
