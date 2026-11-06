"""
status_list_service/services/cascade_coordinator.py

Full agent revocation cascade with retry logic.

Steps in order:
1. Fetch all VCs for agent
2. Revoke all VCs
3. Update DID Document to revoked
4. Add to blocklist if did:key
5. Publish agent revocation event
6. Notify ANS

"""

import logging
import asyncio
import functools
import uuid
from datetime import datetime, timezone

from db.connection import get_session
from db.queries.revocation_queries import get_entries_for_agent, log_revocation
from services.revocation_service import revoke_credential
from services.blocklist_service import add_to_blocklist
from clients import kms_client, did_registry_client, ans_client
from kafka import producer
from config import CASCADE_MAX_RETRIES, CASCADE_RETRY_BASE_SECONDS

logger = logging.getLogger(__name__)


async def revoke_agent_cascade(agent_did: str, reason: str, authority_did: str) -> dict:
    """
    Revoke all credentials for an agent in order with retry logic.

    Returns: { cascade_complete, steps, kafka_event_id }

    If a step fails, retry up to CASCADE_MAX_RETRIES times with exponential backoff.
    If still failing after retries, mark as failed and continue to next step.
    """

    cascade_id = str(uuid.uuid4())
    steps = []
    event_id = None

    try:
        
        # Step 1: Fetch all unrevoked VCs for this agent
        
        async with get_session() as session:
            entries = await get_entries_for_agent(session, agent_did)

        logger.info(f"Found {len(entries)} VCs to revoke for agent {agent_did}")

        
        # Step 2: Revoke all VCs
        
        vc_revoke_step = {
            "step": "REVOKE_VCS",
            "status": "success",
            "count": 0,
        }
        steps.append(vc_revoke_step)

        for entry in entries:
            try:
                
                await _retry_with_backoff(
                    functools.partial(revoke_credential, entry["vc_id"], reason, authority_did),
                    max_retries=CASCADE_MAX_RETRIES,
                    base_seconds=CASCADE_RETRY_BASE_SECONDS,
                )
                vc_revoke_step["count"] += 1
            except Exception as e:
                logger.error(f"Failed to revoke {entry['vc_id']}: {e}")
                vc_revoke_step["status"] = "partial"
                vc_revoke_step["reason"] = (
                    f"Failed to revoke all VCs "
                    f"({vc_revoke_step['count']}/{len(entries)} succeeded)"
                )

        
        # Step 3: Update DID Document
        

        did_update_step = {
            "step": "UPDATE_DID_DOCUMENT",
            "status": "success",
        }
        steps.append(did_update_step)

        try:
            await _retry_with_backoff(
                functools.partial(
                    did_registry_client.update_did,
                    agent_did,
                    {"lifecycleStatus": "revoked"},
                    authority_did,
                ),
                max_retries=CASCADE_MAX_RETRIES,
                base_seconds=CASCADE_RETRY_BASE_SECONDS,
            )
        except Exception as e:
            logger.error(f"Failed to update DID {agent_did}: {e}")
            did_update_step["status"] = "failed"
            did_update_step["reason"] = str(e)

        
        # Step 4: Add to ephemeral blocklist (if did:key)
        

        blocklist_step = {
            "step": "EPHEMERAL_BLOCKLIST",
            "status": "skipped",
            "reason": "did:web agent",
        }
        steps.append(blocklist_step)

        if agent_did.startswith("did:key:"):
            try:
                await _retry_with_backoff(
                    functools.partial(add_to_blocklist, agent_did, reason),
                    max_retries=CASCADE_MAX_RETRIES,
                    base_seconds=CASCADE_RETRY_BASE_SECONDS,
                )
                blocklist_step["status"] = "success"
                blocklist_step.pop("reason")
            except Exception as e:
                logger.error(f"Failed to add {agent_did} to blocklist: {e}")
                blocklist_step["status"] = "failed"
                blocklist_step["reason"] = str(e)

         
        # Step 5: Publish Kafka event
        

        kafka_step = {
            "step": "KAFKA_EVENT",
            "status": "success",
        }
        steps.append(kafka_step)

        revoked_at = datetime.now(timezone.utc).isoformat()
        event_id = str(uuid.uuid4())

        try:
            await _retry_with_backoff(
                functools.partial(
                    producer.publish_agent_revoked,
                    agent_did=agent_did,
                    reason=reason,
                    authority_did=authority_did,
                    revoked_vc_count=vc_revoke_step.get("count", 0),
                    cascade_steps=steps,
                    event_id=event_id,
                    revoked_at=revoked_at,
                ),
                max_retries=CASCADE_MAX_RETRIES,
                base_seconds=CASCADE_RETRY_BASE_SECONDS,
            )
            kafka_step["kafka_event_id"] = event_id
        except Exception as e:
            logger.error(f"Failed to publish Kafka event: {e}")
            kafka_step["status"] = "failed"
            kafka_step["reason"] = str(e)

         
        # Step 6: Notify ANS
        

        ans_step = {
            "step": "ANS_DEACTIVATE",
            "status": "success",
        }
        steps.append(ans_step)

        try:
            await _retry_with_backoff(
                functools.partial(ans_client.deactivate_agent, agent_did),
                max_retries=CASCADE_MAX_RETRIES,
                base_seconds=CASCADE_RETRY_BASE_SECONDS,
            )
        except Exception as e:
            logger.error(f"Failed to notify ANS: {e}")
            ans_step["status"] = "failed"
            ans_step["reason"] = str(e)

        
        async with get_session() as session:
            await log_revocation(
                session,
                vc_id=None,
                agent_did=agent_did,
                authority_did=authority_did,
                reason=reason,
                bit_index=None,
                status_list_id=None,
                kafka_event_id=event_id,
                cascade_steps=steps,
            )

        # Determine overall cascade success
        cascade_complete = all(s["status"] in ("success", "skipped") for s in steps)

        return {
            "cascade_complete": cascade_complete,
            "steps": steps,
            "kafka_event_id": event_id,
        }

    except Exception as e:
        logger.error(f"Cascade coordinator failed: {e}", exc_info=True)
        return {
            "cascade_complete": False,
            "steps": steps,
            "kafka_event_id": event_id,
        }


async def _retry_with_backoff(coro_func, max_retries: int = 3, base_seconds: float = 1):
    """
    Retry an async callable with exponential backoff.

    coro_func must be a *callable* that returns a fresh coroutine each time it is called
    (e.g. functools.partial(some_async_fn, arg1, arg2)).
    Do NOT pass a lambda that calls an async function — lambdas return the same exhausted
    coroutine object on repeated calls and will fail on the second retry.
    """
    for attempt in range(max_retries):
        try:
            return await coro_func()
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            wait_seconds = base_seconds * (2 ** attempt)
            logger.warning(
                f"Retrying after {wait_seconds}s "
                f"(attempt {attempt + 1}/{max_retries}): {e}"
            )
            await asyncio.sleep(wait_seconds)