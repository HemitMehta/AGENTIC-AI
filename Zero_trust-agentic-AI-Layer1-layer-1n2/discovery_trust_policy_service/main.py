"""
main.py -- Discovery Trust Policy Service (Module 3, Person A)
Port: 8010

Responsibilities:
  - Maintain allowlists of trusted ANS registries, providers, and capability
    namespaces.
  - Expose a single isTrustedSource-style check used by Module 2 (ANS Resolver)
    before returning discovery results, especially from non-local registries.

No Layer 1 dependency required for the initial version -- this is pure
config/policy data. Starts config-driven (in-memory) and can be swapped
for a DB-backed admin UI later.
"""

import os
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import FastAPI, HTTPException, status

from models import (
    TrustedRegistryEntry,
    TrustedProviderEntry,
    TrustedCapabilityDomain,
    TrustCheckRequest,
    TrustCheckResponse,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("discovery_trust_policy_service")
DATABASE_URL = os.getenv("LAYER2_DATABASE_URL")

app = FastAPI(
    title="Discovery Trust Policy Service",
    description="Layer 2 / Module 3 -- discovery-time trust allowlists",
    version="0.1.0",
)

# ---------------------------------------------------------------------------
# In-memory allowlists (temporary -- DB comes later)
# The local/default ANS registry (Module 1) is implicitly trusted and never
# needs a registryId entry here -- only remote/federated registries do.
# ---------------------------------------------------------------------------
_trusted_registries: dict[str, TrustedRegistryEntry] = {}
_trusted_providers: dict[str, TrustedProviderEntry] = {}
_trusted_capability_domains: dict[str, TrustedCapabilityDomain] = {}


def _db_enabled() -> bool:
    return bool(DATABASE_URL)


def _get_db():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def _init_db():
    if not _db_enabled():
        logger.info("LAYER2_DATABASE_URL not set; Trust Policy using in-memory storage")
        return

    with _get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS trusted_registries (
                    registry_id TEXT PRIMARY KEY,
                    registry_url TEXT NOT NULL,
                    trusted_since TIMESTAMPTZ NOT NULL,
                    notes TEXT
                );
                CREATE TABLE IF NOT EXISTS trusted_providers (
                    provider TEXT PRIMARY KEY,
                    trusted_since TIMESTAMPTZ NOT NULL,
                    notes TEXT
                );
                CREATE TABLE IF NOT EXISTS trusted_capability_domains (
                    domain TEXT PRIMARY KEY,
                    trusted_since TIMESTAMPTZ NOT NULL,
                    notes TEXT
                );
                """
            )
        conn.commit()
    logger.info("Discovery Trust Policy database initialized")


@app.on_event("startup")
async def startup_event():
    _init_db()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) AS count FROM trusted_registries")
                registries = cur.fetchone()["count"]
                cur.execute("SELECT COUNT(*) AS count FROM trusted_providers")
                providers = cur.fetchone()["count"]
                cur.execute("SELECT COUNT(*) AS count FROM trusted_capability_domains")
                domains = cur.fetchone()["count"]
        return {
            "status": "healthy",
            "service": "discovery_trust_policy_service",
            "trusted_registries": registries,
            "trusted_providers": providers,
            "trusted_capability_domains": domains,
            "storage": "postgres",
        }

    return {
        "status": "healthy",
        "service": "discovery_trust_policy_service",
        "trusted_registries": len(_trusted_registries),
        "trusted_providers": len(_trusted_providers),
        "trusted_capability_domains": len(_trusted_capability_domains),
    }


# ---------------------------------------------------------------------------
# Admin endpoints -- manage the allowlists
# ---------------------------------------------------------------------------
@app.post("/registries", response_model=TrustedRegistryEntry, status_code=status.HTTP_201_CREATED)
async def add_trusted_registry(entry: TrustedRegistryEntry):
    if _db_enabled():
        try:
            with _get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO trusted_registries (registry_id, registry_url, trusted_since, notes) VALUES (%s, %s, %s, %s)",
                        (entry.registryId, entry.registryUrl, entry.trustedSince, entry.notes),
                    )
                conn.commit()
            logger.info("Added trusted registry: %s", entry.registryId)
            return entry
        except psycopg2.errors.UniqueViolation:
            raise HTTPException(409, f"Registry '{entry.registryId}' is already trusted")

    if entry.registryId in _trusted_registries:
        raise HTTPException(409, f"Registry '{entry.registryId}' is already trusted")
    _trusted_registries[entry.registryId] = entry
    logger.info("Added trusted registry: %s", entry.registryId)
    return entry


@app.delete("/registries/{registry_id}")
async def remove_trusted_registry(registry_id: str):
    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM trusted_registries WHERE registry_id = %s", (registry_id,))
                removed = cur.rowcount
            conn.commit()
        if removed == 0:
            raise HTTPException(404, f"Registry '{registry_id}' not found")
        return {"registryId": registry_id, "removed": True}

    if registry_id not in _trusted_registries:
        raise HTTPException(404, f"Registry '{registry_id}' not found")
    del _trusted_registries[registry_id]
    return {"registryId": registry_id, "removed": True}


@app.post("/providers", response_model=TrustedProviderEntry, status_code=status.HTTP_201_CREATED)
async def add_trusted_provider(entry: TrustedProviderEntry):
    if _db_enabled():
        try:
            with _get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO trusted_providers (provider, trusted_since, notes) VALUES (%s, %s, %s)",
                        (entry.provider, entry.trustedSince, entry.notes),
                    )
                conn.commit()
            logger.info("Added trusted provider: %s", entry.provider)
            return entry
        except psycopg2.errors.UniqueViolation:
            raise HTTPException(409, f"Provider '{entry.provider}' is already trusted")

    if entry.provider in _trusted_providers:
        raise HTTPException(409, f"Provider '{entry.provider}' is already trusted")
    _trusted_providers[entry.provider] = entry
    logger.info("Added trusted provider: %s", entry.provider)
    return entry


@app.delete("/providers/{provider}")
async def remove_trusted_provider(provider: str):
    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM trusted_providers WHERE provider = %s", (provider,))
                removed = cur.rowcount
            conn.commit()
        if removed == 0:
            raise HTTPException(404, f"Provider '{provider}' not found")
        return {"provider": provider, "removed": True}

    if provider not in _trusted_providers:
        raise HTTPException(404, f"Provider '{provider}' not found")
    del _trusted_providers[provider]
    return {"provider": provider, "removed": True}


@app.post("/capability-domains", response_model=TrustedCapabilityDomain, status_code=status.HTTP_201_CREATED)
async def add_trusted_capability_domain(entry: TrustedCapabilityDomain):
    if _db_enabled():
        try:
            with _get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO trusted_capability_domains (domain, trusted_since, notes) VALUES (%s, %s, %s)",
                        (entry.domain, entry.trustedSince, entry.notes),
                    )
                conn.commit()
            logger.info("Added trusted capability domain: %s", entry.domain)
            return entry
        except psycopg2.errors.UniqueViolation:
            raise HTTPException(409, f"Capability domain '{entry.domain}' is already trusted")

    if entry.domain in _trusted_capability_domains:
        raise HTTPException(409, f"Capability domain '{entry.domain}' is already trusted")
    _trusted_capability_domains[entry.domain] = entry
    logger.info("Added trusted capability domain: %s", entry.domain)
    return entry


@app.get("/registries", response_model=list[TrustedRegistryEntry])
async def list_trusted_registries():
    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM trusted_registries ORDER BY registry_id")
                rows = cur.fetchall()
        return [
            TrustedRegistryEntry(
                registryId=row["registry_id"],
                registryUrl=row["registry_url"],
                trustedSince=row["trusted_since"],
                notes=row["notes"],
            )
            for row in rows
        ]

    return list(_trusted_registries.values())


@app.get("/providers", response_model=list[TrustedProviderEntry])
async def list_trusted_providers():
    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM trusted_providers ORDER BY provider")
                rows = cur.fetchall()
        return [
            TrustedProviderEntry(provider=row["provider"], trustedSince=row["trusted_since"], notes=row["notes"])
            for row in rows
        ]

    return list(_trusted_providers.values())


@app.get("/capability-domains", response_model=list[TrustedCapabilityDomain])
async def list_trusted_capability_domains():
    if _db_enabled():
        with _get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM trusted_capability_domains ORDER BY domain")
                rows = cur.fetchall()
        return [
            TrustedCapabilityDomain(domain=row["domain"], trustedSince=row["trusted_since"], notes=row["notes"])
            for row in rows
        ]

    return list(_trusted_capability_domains.values())


# ---------------------------------------------------------------------------
# The core check -- called by Module 2 (ANS Resolver) before returning results
# ---------------------------------------------------------------------------
@app.post("/check", response_model=TrustCheckResponse)
async def check_trust(req: TrustCheckRequest):
    """
    A source is trusted if:
      - registryId is None (local/default registry, implicitly trusted), AND
      - provider (if given) is either unset or in the trusted provider list, AND
      - capability domain (if given) is either unset or in the trusted domain list.

    If registryId IS given and not in the trusted list, it fails immediately --
    federated/remote registries must be explicitly trusted.
    """
    reasons: list[str] = []
    trusted = True

    if req.registryId is not None and req.registryId not in _trusted_registries:
        if _db_enabled():
            with _get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM trusted_registries WHERE registry_id = %s", (req.registryId,))
                    registry_exists = cur.fetchone() is not None
            if not registry_exists:
                trusted = False
                reasons.append(f"registry '{req.registryId}' is not in the trusted registry list")
        else:
            trusted = False
            reasons.append(f"registry '{req.registryId}' is not in the trusted registry list")

    if req.provider is not None:
        if _db_enabled():
            with _get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) AS count FROM trusted_providers")
                    provider_count = cur.fetchone()["count"]
                    cur.execute("SELECT 1 FROM trusted_providers WHERE provider = %s", (req.provider,))
                    provider_exists = cur.fetchone() is not None
            if provider_count and not provider_exists:
                trusted = False
                reasons.append(f"provider '{req.provider}' is not in the trusted provider list")
        elif _trusted_providers and req.provider not in _trusted_providers:
            trusted = False
            reasons.append(f"provider '{req.provider}' is not in the trusted provider list")

    if req.capability is not None:
        top_level_domain = req.capability.split(".")[0]
        if _db_enabled():
            with _get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(*) AS count FROM trusted_capability_domains")
                    domain_count = cur.fetchone()["count"]
                    cur.execute("SELECT 1 FROM trusted_capability_domains WHERE domain = %s", (top_level_domain,))
                    domain_exists = cur.fetchone() is not None
            if domain_count and not domain_exists:
                trusted = False
                reasons.append(f"capability domain '{top_level_domain}' is not in the trusted domain list")
        elif _trusted_capability_domains and top_level_domain not in _trusted_capability_domains:
            trusted = False
            reasons.append(f"capability domain '{top_level_domain}' is not in the trusted domain list")

    if trusted:
        reasons.append("passed all configured trust checks")

    return TrustCheckResponse(trusted=trusted, reasons=reasons)
