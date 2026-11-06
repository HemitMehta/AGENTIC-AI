"""
status_list_service/routers/agent_revoke.py

POST /revoke/agent/:did
"""

from fastapi import APIRouter, HTTPException
import logging

from models.requests import AgentRevokeRequest
from models.responses import CascadeResponse
from services.cascade_coordinator import revoke_agent_cascade

router = APIRouter(tags=["revocation"])
logger = logging.getLogger(__name__)


@router.post("/revoke/agent/{agent_did}", response_model=CascadeResponse)
async def revoke_agent(agent_did: str, request: AgentRevokeRequest):
    """
    Revoke all credentials for an agent.

    Full cascade with retry logic:
    1. Revoke all VCs
    2. Update DID Document
    3. Add to blocklist (if did:key)
    4. Publish Kafka event
    5. Notify ANS

    All steps must complete or be retried. If still failing after retries,
    mark as failed but continue to preserve partial revocation.
    """

    try:
        result = await revoke_agent_cascade(agent_did, request.reason, request.authority_did)

        status_code = 200 if result["cascade_complete"] else 207  # 207 Multi-Status for partial success

        logger.info(f"Agent cascade complete: {agent_did}, success={result['cascade_complete']}")

        # Convert steps to response format
        steps = [
            {
                "step": s["step"],
                "status": s["status"],
                "reason": s.get("reason"),
                "count": s.get("count"),
                "kafka_event_id": s.get("kafka_event_id")
            }
            for s in result["steps"]
        ]

        return CascadeResponse(
            cascade_complete=result["cascade_complete"],
            steps=steps,
            kafka_event_id=result.get("kafka_event_id", "")
        )

    except Exception as e:
        logger.error(f"Agent revocation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
