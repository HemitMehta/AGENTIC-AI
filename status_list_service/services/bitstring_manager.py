"""
status_list_service/services/bitstring_manager.py

Core bitstring operations: allocation, bit flipping, compression, encoding.
"""

import logging
import gzip
import base64
import uuid
from typing import Tuple
from sqlalchemy import text

from db.connection import get_session
from db.queries.status_list_queries import (
    get_active_status_list_for_issuer,
    create_status_list,
    claim_status_list_index
)
from config import BITSTRING_SIZE_BITS, BITSTRING_SIZE_BYTES, STATUS_LIST_BASE_URL

logger = logging.getLogger(__name__)


def flip_bit(bitstring: bytes, index: int) -> bytes:
    """
    Flip a bit to 1 (revoked) at the given index.

    Big-endian per StatusList2021 spec:
    - Bit 0 is the MSB of byte 0
    - Bit indexing: byte_pos = index // 8, bit_pos = 7 - (index % 8)
    """
    ba = bytearray(bitstring)
    byte_pos = index // 8
    bit_pos = 7 - (index % 8)
    ba[byte_pos] |= (1 << bit_pos)
    return bytes(ba)


async def allocate_status_entry(issuer_did: str, vc_id: str) -> Tuple[str, int]:
    """Reserve the bit and credential mapping in one transaction, with idempotent retries."""
    session = get_session()
    try:
        await session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                              {"key": "vc:" + vc_id})
        existing = (await session.execute(text(
            "SELECT issuer_did,status_list_url,bit_index FROM status_list_entries WHERE vc_id=:vc"),
            {"vc": vc_id})).mappings().first()
        if existing:
            if existing["issuer_did"] != issuer_did:
                raise ValueError("Credential ID already allocated to another issuer")
            return existing["status_list_url"], existing["bit_index"]
        await session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
                              {"key": "issuer:" + issuer_did})
        row = (await session.execute(text(
            "SELECT id,next_free_index FROM status_lists WHERE issuer_did=:issuer AND next_free_index<total_bits "
            "ORDER BY created_at DESC LIMIT 1 FOR UPDATE"), {"issuer": issuer_did})).mappings().first()
        if not row:
            row = (await session.execute(text(
                "INSERT INTO status_lists (issuer_did,bitstring,total_bits,next_free_index) "
                "VALUES (:issuer,:bits,:total,0) RETURNING id,next_free_index"),
                {"issuer": issuer_did, "bits": b"\x00" * BITSTRING_SIZE_BYTES,
                 "total": BITSTRING_SIZE_BITS})).mappings().one()
        list_id, index = str(row["id"]), row["next_free_index"]
        url = f"{STATUS_LIST_BASE_URL}/status-lists/{list_id}"
        await session.execute(text(
            "UPDATE status_lists SET next_free_index=next_free_index+1,updated_at=NOW() WHERE id=CAST(:id AS UUID)"),
            {"id": list_id})
        await session.execute(text(
            "INSERT INTO status_list_entries (vc_id,issuer_did,status_list_id,bit_index,status_list_url) "
            "VALUES (:vc,:issuer,CAST(:id AS UUID),:index,:url)"),
            {"vc": vc_id, "issuer": issuer_did, "id": list_id, "index": index, "url": url})
        await session.commit()
        return url, index
    finally:
        await session.close()


def compress_and_encode_bitstring(bitstring: bytes) -> str:
    """
    GZIP compress and Base64url encode a bitstring.

    Per StatusList2021 spec: encodedList = base64url(gzip(bitstring))
    """
    compressed = gzip.compress(bitstring)
    encoded = base64.urlsafe_b64encode(compressed).decode().rstrip("=")
    return encoded


def decode_bitstring(encoded: str) -> bytes:
    """
    Reverse of compress_and_encode: decode and decompress.
    """
    # Add back padding
    padding = 4 - (len(encoded) % 4)
    if padding != 4:
        encoded += "=" * padding

    compressed = base64.urlsafe_b64decode(encoded)
    bitstring = gzip.decompress(compressed)
    return bitstring
