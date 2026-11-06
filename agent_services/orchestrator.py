import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import UUID

import httpx
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import APIKeyHeader

from .common import (TaskStore, digest, json_call, operator_token, register_identity,
                     signed_message, validate_endpoint, verify_did_message)
from .discovery import verify_discovery
from .models import ACTION, TaskSubmission

logger = logging.getLogger(__name__)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


@asynccontextmanager
async def lifespan(app):
    state_dir = Path(os.environ.get("AGENT_STATE_DIR", "/state"))
    app.state.token = operator_token(state_dir / "operator-token.txt")
    app.state.store = TaskStore(state_dir / "tasks.sqlite3")
    async with httpx.AsyncClient(timeout=60, follow_redirects=False, trust_env=False) as client:
        app.state.client = client
        app.state.identity = await register_identity(
            client, os.environ["AGENT_KEY_ID"], "task-orchestrator",
            os.environ.get("AGENT_DID_DOMAIN", "demo.local"))
        yield


app = FastAPI(title="TaskOrchestratorAgent", version="1.0.0", lifespan=lifespan)


def require_operator(key: str | None = Depends(api_key_header)):
    if not key or not secrets.compare_digest(key, app.state.token):
        raise HTTPException(401, "Valid operator API key required")


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "task_orchestrator"}


@app.get("/identity")
async def identity():
    return app.state.identity


@app.get("/tasks/{task_id}", dependencies=[Depends(require_operator)])
async def get_task(task_id: UUID):
    return app.state.store.get(str(task_id))


@app.post("/tasks", dependencies=[Depends(require_operator)])
async def submit_task(request: TaskSubmission):
    task_id = str(request.taskId)
    app.state.store.reserve(task_id, request.model_dump(mode="json"))
    client = app.state.client
    try:
        query = {**request.discovery.model_dump(mode="json"), "requestId": task_id}
        gateway = os.environ.get("DISCOVERY_GATEWAY_URL", "http://discovery_gateway:8012")
        response = await json_call(client, "POST", f"{gateway}/discover", json=query)
        record = await verify_discovery(
            client, response, query,
            os.environ.get("TRUSTED_GATEWAY_KEY_ID", "discovery-gateway-signing-key"),
            os.environ.get("TRUSTED_RESOLVER_KEY_ID", "ans-resolver-signing-key"))
        allowed = {s.strip() for s in os.environ.get("ALLOWED_AGENT_ENDPOINTS", "").split(",") if s.strip()}
        endpoint = validate_endpoint(record["serviceEndpoint"], allowed,
                                     os.environ.get("ALLOW_HTTP_AGENT_ENDPOINTS", "false").lower() == "true")
        now = int(time.time())
        payload = {
            "type": "agent.task.request.v1", "taskId": task_id,
            "issuerDid": app.state.identity["did"], "audienceDid": record["agentDid"],
            "action": ACTION, "issuedAt": now, "expiresAt": now + 60,
            "input": request.input.model_dump(mode="json"),
        }
        message = await signed_message(client, app.state.identity, payload)
        result = await json_call(client, "POST", endpoint, json=message, propagate_denial=True)
        await verify_did_message(client, result, record["agentDid"])
        if (result.get("type") != "agent.task.result.v1" or result.get("taskId") != task_id
                or result.get("agentDid") != record["agentDid"] or result.get("requestHash") != digest(payload)
                or result.get("status") != "completed"):
            raise HTTPException(403, "Agent response is not bound to this task")
        outcome = {
            "taskId": task_id, "status": "completed", "orchestratorDid": app.state.identity["did"],
            "discovery": {"selectedAgent": record["agentDid"], "endpoint": endpoint,
                          "ansName": record["ansName"], "gatewaySignatureVerified": True,
                          "ansRecordSignatureVerified": True, "ansRecord": record},
            "agentResponseSignatureVerified": True, "agentResponse": result,
        }
        app.state.store.finish(task_id, result=outcome)
        return outcome
    except HTTPException as exc:
        app.state.store.finish(task_id, error=str(exc.detail))
        raise HTTPException(exc.status_code, {"taskId": task_id, "reason": exc.detail}) from exc
    except Exception as exc:
        logger.exception("Task %s failed", task_id)
        app.state.store.finish(task_id, error="Unexpected task failure; execution may have occurred")
        raise HTTPException(500, {"taskId": task_id, "reason": "Task failed; inspect its stored status"}) from exc
