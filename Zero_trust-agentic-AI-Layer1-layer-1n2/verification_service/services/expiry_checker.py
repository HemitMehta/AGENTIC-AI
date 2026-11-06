"""
services/expiry_checker.py

Step 6 of verification pipeline: Expiration date check.
Verifies that credentials have not expired as of the current UTC time.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


async def check_expiry(vcs: List[Dict[str, Any]]) -> None:
    """
    Check expiration dates for all VCs.

    Args:
        vcs: List of VC dictionaries

    Raises:
        ValueError if any VC is expired
    """
    now = datetime.now(timezone.utc)

    for vc in vcs:
        await _check_single_expiry(vc, now)


async def _check_single_expiry(vc: Dict[str, Any], now: datetime) -> None:
    """
    Check expiration date for a single VC.

    Args:
        vc:  VC dictionary
        now: Current UTC time

    Raises:
        ValueError if VC is expired
    """
    vc_id = vc.get("id", "unknown")
    expiration_date_str = vc.get("expirationDate")

    if not expiration_date_str:
        logger.warning(f"VC {vc_id} has no expirationDate")
        return

    try:
        # Parse ISO 8601 expiration date
        expiration_date = datetime.fromisoformat(
            expiration_date_str.replace("Z", "+00:00")
        )

        if now > expiration_date:
            raise ValueError(
                f"Credential {vc_id} expired at {expiration_date_str}"
            )

        logger.info(f"VC {vc_id} expiry OK (expires {expiration_date_str})")

    except ValueError as e:
        if "expired at" in str(e):
            raise
        logger.error(f"Failed to parse expirationDate for VC {vc_id}: {e}")
        raise ValueError(f"Invalid expirationDate format: {e}")
