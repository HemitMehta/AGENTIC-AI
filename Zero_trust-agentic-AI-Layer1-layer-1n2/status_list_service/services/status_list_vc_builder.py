"""
status_list_service/services/status_list_vc_builder.py

Build and sign W3C Status List 2021 credentials.
"""

import json
import logging
from datetime import datetime, timezone

from cache import redis_client
from clients import kms_client
from db.connection import get_session
from db.queries.status_list_queries import get_status_list
from services.bitstring_manager import compress_and_encode_bitstring
from config import STATUS_LIST_BASE_URL, KMS_STATUS_LIST_KEY_ID

logger = logging.getLogger(__name__)


async def build_status_list_vc(status_list_id: str, issuer_did: str, fresh: bool = False) -> dict:
    """
    Build a signed Status List 2021 Credential VC.

    Algorithm:
    1. Check Redis cache — if hit, return cached VC
    2. On miss: fetch bitstring from DB
    3. GZIP compress + Base64url encode
    4. Build VC JSON
    5. Sign via KMS
    6. Attach proof
    7. Cache in Redis with TTL
    8. Return VC
    """

    # Step 1: Check cache
    cached_vc = None if fresh else await redis_client.get_cached_status_list(status_list_id)
    if cached_vc:
        logger.debug(f"Cache hit for status list {status_list_id}")
        return json.loads(cached_vc)

    # Step 2: Fetch from DB
    # FIX (combined Layer 1 + Layer 2 integration): get_session() is a
    # plain (non-async) function -- it returns the AsyncSession object
    # directly, not a coroutine. Other callers in this service correctly
    # use `async with get_session() as session:`; this file previously
    # wrote `await get_session()` instead, which crashes with
    # "object AsyncSession can't be used in 'await' expression".
    session = get_session()
    try:
        status_list = await get_status_list(session, status_list_id)
    finally:
        await session.close()

    if not status_list:
        raise ValueError(f"Status list {status_list_id} not found")

    bitstring = status_list["bitstring"]
    issuer_did = status_list["issuer_did"]

    # Step 3: Compress and encode
    encoded_list = compress_and_encode_bitstring(bitstring)

    # Step 4: Build VC JSON
    status_list_url = f"{STATUS_LIST_BASE_URL}/status-lists/{status_list_id}"

    vc_json = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/vc/status-list/2021/v1"
        ],
        "id": status_list_url,
        "type": ["VerifiableCredential", "StatusList2021Credential"],
        "issuer": issuer_did,
        "issuedAt": datetime.now(timezone.utc).isoformat(),
        "credentialSubject": {
            "id": f"{status_list_url}#list",
            "type": "StatusList2021",
            "statusPurpose": "revocation",
            "encodedList": encoded_list
        }
    }

    # Step 5: Sign via KMS
    vc_json_bytes = json.dumps(vc_json, separators=(',', ':'), sort_keys=True).encode()
    signature = await kms_client.sign_payload(KMS_STATUS_LIST_KEY_ID, vc_json_bytes)

    # Step 6: Attach proof
    vc_json["proof"] = {
        "type": "Ed25519Signature2020",
        "created": datetime.now(timezone.utc).isoformat(),
        "verificationMethod": f"urn:kms:{KMS_STATUS_LIST_KEY_ID}",
        "proofPurpose": "assertionMethod",
        "proofValue": signature
    }

    # Step 7: Cache
    vc_json_str = json.dumps(vc_json)
    if not fresh:
        await redis_client.cache_status_list(status_list_id, vc_json_str)

    logger.info(f"Built and cached status list VC for {status_list_id}")

    # Step 8: Return
    return vc_json
