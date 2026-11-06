"""
status_list_service/kafka/producer.py
─────────────────────────────────────
Async Kafka producer for revocation events.

Topics:
- credential.revoked — individual VC revocation events
- agent.revoked — full agent revocation cascade events
"""

import logging
from aiokafka import AIOKafkaProducer
import json

from config import KAFKA_BOOTSTRAP_SERVERS

logger = logging.getLogger(__name__)

_producer = None


async def init_kafka_producer():
    """Initialize Kafka producer."""
    global _producer
    _producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode('utf-8')
    )
    await _producer.start()
    logger.info("Kafka producer initialized")


async def close_kafka_producer():
    """Close Kafka producer."""
    global _producer
    if _producer:
        await _producer.stop()
        logger.info("Kafka producer closed")


def get_producer():
    """Get Kafka producer."""
    if _producer is None:
        raise RuntimeError("Kafka producer not initialized. Call init_kafka_producer() first.")
    return _producer


async def publish_credential_revoked(vc_id: str, bit_index: int, status_list_id: str,
                                      reason: str, authority_did: str, event_id: str,
                                      revoked_at: str) -> str:
    """Publish credential revocation event."""
    producer = get_producer()

    event = {
        "eventId": event_id,
        "vcId": vc_id,
        "bitIndex": bit_index,
        "statusListId": status_list_id,
        "reason": reason,
        "authorityDID": authority_did,
        "revokedAt": revoked_at
    }

    try:
        await producer.send_and_wait("credential.revoked", value=event)
        logger.info(f"Published credential.revoked event for {vc_id}")
        return event_id
    except Exception as e:
        logger.error(f"Failed to publish credential.revoked: {e}")
        raise


async def publish_agent_revoked(agent_did: str, reason: str, authority_did: str,
                                revoked_vc_count: int, cascade_steps: list,
                                event_id: str, revoked_at: str) -> str:
    """Publish agent revocation cascade event."""
    producer = get_producer()

    event = {
        "eventId": event_id,
        "agentDID": agent_did,
        "reason": reason,
        "authorityDID": authority_did,
        "revokedVcCount": revoked_vc_count,
        "cascadeSteps": cascade_steps,
        "revokedAt": revoked_at
    }

    try:
        await producer.send_and_wait("agent.revoked", value=event)
        logger.info(f"Published agent.revoked event for {agent_did}")
        return event_id
    except Exception as e:
        logger.error(f"Failed to publish agent.revoked: {e}")
        raise
