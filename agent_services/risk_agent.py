import os
import time
from contextlib import asynccontextmanager
from decimal import Decimal
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException

from .common import (TaskStore, digest, identity_did, kms_public, register_identity,
                     signed_message, verify_did_message)
from .models import FinancialInput, ProtectedSalesInput, PROTOCOL, TaskMessage
from .protected_sales import read_sales


def analyze(data: FinancialInput):
    periods = []
    revenue = Decimal(0)
    expenses = Decimal(0)
    for period in data.periods:
        net = period.revenue - period.expenses
        periods.append({"period": period.period, "revenue": str(period.revenue),
                        "expenses": str(period.expenses), "netIncome": str(net),
                        "lossMaking": net < 0})
        revenue += period.revenue
        expenses += period.expenses
    return {"currency": data.currency, "periods": periods, "totalRevenue": str(revenue),
            "totalExpenses": str(expenses), "netIncome": str(revenue - expenses),
            "lossMakingPeriods": [p["period"] for p in periods if p["lossMaking"]]}


@asynccontextmanager
async def lifespan(app):
    app.state.store = TaskStore(Path(os.environ.get("AGENT_STATE_DIR", "/state")) / "tasks.sqlite3")
    domain = os.environ.get("AGENT_DID_DOMAIN", "demo.local")
    async with httpx.AsyncClient(timeout=15, follow_redirects=False, trust_env=False) as client:
        app.state.client = client
        app.state.identity = await register_identity(client, os.environ["AGENT_KEY_ID"], "risk-analyzer", domain, wallet=True)
        public = await kms_public(client, os.environ["TRUSTED_ORCHESTRATOR_KEY_ID"])
        app.state.trusted_orchestrator = identity_did(public, "task-orchestrator", domain)
        yield


app = FastAPI(title="RiskAnalyzerBot", version="1.0.0", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "risk_analyzer"}


@app.get("/identity")
async def identity():
    return {**app.state.identity, "protocol": PROTOCOL,
            "capability": os.environ.get("AGENT_CAPABILITY", "FinancialRiskAnalysis.CorporateReporting"),
            "provider": os.environ.get("AGENT_PROVIDER", "DemoProvider"),
            "version": "1.0.0", "serviceEndpoint": os.environ["AGENT_SERVICE_ENDPOINT"]}


@app.post("/tasks")
async def execute(request: TaskMessage):
    message = request.model_dump(mode="json")
    now = int(time.time())
    if request.audienceDid != app.state.identity["did"] or request.issuerDid != app.state.trusted_orchestrator:
        raise HTTPException(403, "Task sender or audience is not authorized")
    if not (now - 60 <= request.issuedAt <= now + 5 and now < request.expiresAt <= request.issuedAt + 60):
        raise HTTPException(403, "Task request expired or has an invalid validity window")
    await verify_did_message(app.state.client, message, app.state.trusted_orchestrator)
    task_id = str(request.taskId)
    app.state.store.reserve(task_id, message)
    try:
        payload = {k: v for k, v in message.items() if k != "proof"}
        source = None
        financials = request.input
        if isinstance(financials, ProtectedSalesInput):
            financials, source = await read_sales(app.state.client, app.state.identity, request)
        analysis = analyze(financials)
        if source is not None:
            analysis["dataAccess"] = source
        result = await signed_message(app.state.client, app.state.identity, {
            "type": "agent.task.result.v1", "taskId": task_id,
            "agentDid": app.state.identity["did"], "requestHash": digest(payload),
            "status": "completed", "completedAt": int(time.time()), "result": analysis,
        })
        app.state.store.finish(task_id, result=result)
        return result
    except Exception:
        app.state.store.finish(task_id, error="Task failed; no automatic retry allowed")
        raise
