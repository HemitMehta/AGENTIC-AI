"""
status_list.py

Real client for Sub-System 6 (Status List Service), used in-process by
vc_issuance.py (imported directly, not over HTTP, since Dockerfile.vc_issuance
copies the whole repo root into that image).

--------------------------------------------------------------------------
FIX (combined Layer 1 + Layer 2 integration): this file was, verbatim, a
copy of status_list_stub.py -- the developer's own placeholder, whose
docstring literally says "Rename to status_list.py ONLY when using this
stub locally without SS6... When Sub-System 6 is delivered, replace with
the real status_list.py." Sub-System 6 (status_list_service, port 8006)
was fully built as its own microservice, but this swap was never done.

The practical effect: every single VC ever issued got a hardcoded,
non-existent credentialStatus URL ("https://status.example.com/lists/
stub-list-1"). That was harmless as long as nothing ever tried to check
it -- but verification_service's real revocation_checker.py (Step 5 of
the 6-step pipeline) genuinely fetches that URL on every VP/VC
verification. Since status.example.com doesn't exist, every verification
that reached Step 5 failed with a fetch error, which is why
requiredAttestations-based discovery always came back "no_matches" with
no useful error surfaced through the Gateway.

This replacement calls the real status_list_service over HTTP, exactly as
Sub-System 6's own router docstrings say it should be called
("Called by SS4 (VC Issuance) on every credential issuance").
--------------------------------------------------------------------------
"""

import os
import logging

import httpx

logger = logging.getLogger(__name__)

STATUS_LIST_SERVICE_URL = os.getenv("STATUS_LIST_SERVICE_URL", "http://status_list_service:8006")
_TIMEOUT_SECONDS = float(os.getenv("STATUS_LIST_HTTP_TIMEOUT_SECONDS", "10"))


def allocate_status_entry(vc_id: str, issuer_did: str) -> dict:
    """
    Allocate a real StatusList2021 entry for a newly-issued VC.

    Calls status_list_service's POST /status-lists/allocate, which
    returns { status_list_url, bit_index }.

    Returns:
        { "statusListUrl": str, "bitIndex": int }

    Raises:
        RuntimeError if status_list_service is unreachable or rejects
        the request -- this is a hard failure, not best-effort, since
        vc_issuance.py's Step 5 already wraps this call in its own
        try/except and turns any exception into a RuntimeError with
        "StatusList allocation failed: ...", exactly matching prior
        behaviour for a genuinely broken status list backend.
    """
    url = f"{STATUS_LIST_SERVICE_URL}/status-lists/allocate"
    resp = httpx.post(url, json={"issuer_did": issuer_did, "vc_id": vc_id}, timeout=_TIMEOUT_SECONDS)
    resp.raise_for_status()
    body = resp.json()
    return {
        "statusListUrl": body["status_list_url"],
        "bitIndex": body["bit_index"],
    }


def revoke_entry(vc_id: str, bit_index: int, status_list_url: str) -> None:
    """
    Revoke a previously-issued VC's status list entry.

    Calls status_list_service's POST /status-lists/revoke. bit_index and
    status_list_url are accepted for signature compatibility with the
    original stub, but aren't needed in the request -- the real service
    looks the entry up by vc_id alone (see status_list_service/routers/
    revoke.py and services/revocation_service.py).
    """
    url = f"{STATUS_LIST_SERVICE_URL}/status-lists/revoke"
    resp = httpx.post(
        url,
        json={"vc_id": vc_id, "reason": "revoked via vc_issuance", "authority_did": "system"},
        timeout=_TIMEOUT_SECONDS,
    )
    resp.raise_for_status()
    logger.info(f"Revoked status list entry for VC {vc_id}")