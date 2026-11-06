import hashlib
import hmac
import json
import os
import ssl
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

HOSTS = {"policy_administration_service", "policy_information_service", "policy_decision_service",
         "access_control_service", "protected_sales_service"}


def directory():
    return Path(os.environ.get("LAYER3_SECURITY_DIR", "/run/layer3"))


def secret(name):
    value = (directory() / name).read_text(encoding="ascii").strip()
    if len(value) < 32:
        raise RuntimeError(f"Invalid or missing Layer 3 secret: {name}")
    return value


def install(app, service):
    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        if request.url.path in {"/health", "/docs", "/openapi.json", "/docs/oauth2-redirect"}:
            return await call_next(request)
        # Resource queries authenticate the agent's signed proof and bearer grant.
        if service == "sales" and request.url.path.endswith("/query") and request.method == "POST":
            return await call_next(request)
        try:
            config = json.loads((directory() / "inbound.json").read_text())
            caller = request.headers.get("X-Service-ID", "")
            token = request.headers.get("X-Service-Token", "")
            expected = config.get(caller)
            if not expected or not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), expected):
                return JSONResponse({"detail": "Service authentication required"}, status_code=401)
            allowed = {
                "pap": {"operator", "pdp", "pip", "pep"} if request.method == "GET" else {"operator"},
                "pip": {"pdp"} if request.url.path.endswith("/revalidate") else {"operator", "pdp"},
                "pdp": {"pep"} if request.url.path.endswith("/revalidate") else {"operator", "pep"},
                "pep": {"operator", "sales"} if request.url.path == "/access/introspect" else {"operator"},
                "sales": {"operator"},
            }[service]
            if service == "pep" and request.url.path == "/access/check" and request.method == "POST":
                allowed = allowed | {"risk_agent"}
            if caller not in allowed:
                return JSONResponse({"detail": "Service is not authorized for this operation"}, status_code=403)
            request.state.caller = caller
        except (OSError, ValueError):
            return JSONResponse({"detail": "Service authentication configuration unavailable"}, status_code=503)
        return await call_next(request)

    original = app.openapi

    def openapi():
        schema = original()
        schemas = schema.setdefault("components", {}).setdefault("securitySchemes", {})
        schemas.update({"ServiceId": {"type": "apiKey", "in": "header", "name": "X-Service-ID"},
                        "ServiceToken": {"type": "apiKey", "in": "header", "name": "X-Service-Token"}})
        schema["security"] = [{"ServiceId": [], "ServiceToken": []}]
        return schema

    app.openapi = openapi


def tls_context():
    context = ssl.create_default_context()
    context.load_verify_locations(str(directory() / "ca.crt"))
    return context


async def request(method, url, **kwargs):
    headers = dict(kwargs.pop("headers", {}))
    if urlsplit(url).hostname in HOSTS:
        if urlsplit(url).scheme != "https":
            raise HTTPException(503, "Layer 3 service connections require TLS")
        headers.update({"X-Service-ID": os.environ["LAYER3_SERVICE_ID"], "X-Service-Token": secret("client.key")})
    async with httpx.AsyncClient(timeout=float(os.getenv("DOWNSTREAM_TIMEOUT_SECONDS", "15")),
                                 verify=tls_context(), follow_redirects=False, trust_env=False) as client:
        return await client.request(method, url, headers=headers, **kwargs)


def database_kwargs():
    return {"host": os.getenv("LAYER3_DB_HOST", "layer3_postgres"), "port": 5432,
            "dbname": "layer3", "user": os.environ["LAYER3_SERVICE_ID"], "password": secret("database.key"),
            "sslmode": "verify-full", "sslrootcert": str(directory() / "ca.crt")}
