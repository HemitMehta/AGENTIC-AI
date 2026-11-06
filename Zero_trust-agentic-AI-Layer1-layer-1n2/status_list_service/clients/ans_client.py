"""
status_list_service/clients/ans_client.py

HTTP client for ANS (Agent Notification Service) on Layer 2.

This is a STUB implementation. The real ANS will be built in Layer 2.
For now, this logs the call and returns success.
"""

import logging
logger = logging.getLogger(__name__)

async def deactivate_agent(did: str) -> dict:
    """
    Request ANS to deactivate an agent.
    In real implementation:
    POST {ANS_URL}/agents/{did}/deactivate
    Response: { "success": true, "deactivatedAt": "..." }
    For now, this is a stub.
    """
    logger.info(f"ANS stub: would deactivate agent {did}")
    return {
        "success": True,
        "deactivatedAt": None,  # Would be timestamp in real impl
        "note": "ANS stub - real implementation in Layer 2"
    }
