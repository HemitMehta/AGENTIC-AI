"""
status_list_service/services/revocation_service.py

Orchestrate revocation: Redis → Postgres → Kafka
"""

import logging
from datetime import datetime, timezone
import uuid
from sqlalchemy import text

from cache import redis_client
from db.connection import get_session
from db.queries.status_list_queries import get_status_list, update_bitstring
from db.queries.revocation_queries import get_entry_by_vc_id, mark_entry_revoked, log_revocation
from services.bitstring_manager import flip_bit
from kafka import producer

logger = logging.getLogger(__name__)


async def revoke_credential(vc_id: str, reason: str, authority_did: str) -> dict:
    """
    Revoke a credential. Strict order:
    1. Redis (immediate verifier visibility)
    2. Postgres (durable)
    3. Kafka (event log)

    Returns: { revokedAt, bitIndex, kafkaEventId }
    """

    # FIX (combined Layer 1 + Layer 2 integration): see the identical fix
    # and full rationale in status_list_vc_builder.py / bitstring_manager.py.
    session = get_session()

    try:
        # Get entry
        entry = await get_entry_by_vc_id(session, vc_id)
        if not entry:
            raise ValueError(f"VC entry not found: {vc_id}")

        if entry["revoked_at"]:
            logger.warning(f"VC already revoked: {vc_id}")
            return {
                "revoked_at": entry["revoked_at"].isoformat() if hasattr(entry["revoked_at"], "isoformat") else entry["revoked_at"],
                "bit_index": entry["bit_index"],
                "kafka_event_id": None
            }

        status_list_id = entry["status_list_id"]
        bit_index = entry["bit_index"]
        status_list_url = entry["status_list_url"]

        # Step 1: Redis
        # Lock the authoritative list so simultaneous revocations cannot clear each other's bits.
        row = (await session.execute(text(
            "SELECT bitstring FROM status_lists WHERE id=CAST(:id AS UUID) FOR UPDATE"),
            {"id": status_list_id})).first()
        bitstring = bytes(row[0])

        # Flip the bit
        new_bitstring = flip_bit(bitstring, bit_index)
        await redis_client.update_cached_bitstring(status_list_id, new_bitstring)
        logger.info(f"Revocation bit flipped in Redis for {vc_id}")

        # Step 2: Postgres
        await session.execute(text(
            "UPDATE status_lists SET bitstring=:bits,updated_at=NOW() WHERE id=CAST(:id AS UUID)"),
            {"bits": new_bitstring, "id": status_list_id})
        await session.execute(text(
            "UPDATE status_list_entries SET revoked_at=NOW(),revocation_reason=:reason WHERE vc_id=:vc"),
            {"reason": reason, "vc": vc_id})
        await session.commit()
        await redis_client.invalidate_status_list(status_list_id)
        logger.info(f"Revocation persisted to Postgres for {vc_id}")

        # Step 3: Kafka
        event_id = str(uuid.uuid4())
        revoked_at = datetime.now(timezone.utc).isoformat()

        try:
            await producer.publish_credential_revoked(
                vc_id=vc_id,
                bit_index=bit_index,
                status_list_id=status_list_id,
                reason=reason,
                authority_did=authority_did,
                event_id=event_id,
                revoked_at=revoked_at
            )
        except Exception as e:
            logger.error(f"Kafka publish failed: {e}")
            # Log to revocation_log but mark as failed
            await log_revocation(
                session, vc_id, None, authority_did, reason, bit_index, status_list_id, None
            )
            raise

        # Log the revocation
        await log_revocation(
            session, vc_id, None, authority_did, reason, bit_index, status_list_id, event_id
        )

        logger.info(f"Credential revocation complete: {vc_id}")
        return {
            "revoked_at": revoked_at,
            "bit_index": bit_index,
            "kafka_event_id": event_id
        }

    finally:
        await session.close()
