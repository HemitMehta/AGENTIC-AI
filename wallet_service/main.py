"""
wallet_service/main.py
FastAPI application entry point.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from config import WALLET_SERVICE_PORT, ENVIRONMENT
from db.connection import init_db, close_db, run_migration
from clients import kms_client, did_registry_client, vc_issuance_client
from routers import wallet_lifecycle, credential_store, credential_query, present, present_zkp, reputation

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan events."""
    # Startup
    logger.info("Wallet Service starting up...")
    await init_db()
    await run_migration()
    await kms_client.init_kms_client()
    await did_registry_client.init_did_client()
    await vc_issuance_client.init_vc_client()
    logger.info("Wallet Service ready")

    yield

    # Shutdown
    logger.info("Wallet Service shutting down...")
    await kms_client.close_kms_client()
    await did_registry_client.close_did_client()
    await vc_issuance_client.close_vc_client()
    await close_db()
    logger.info("Wallet Service stopped")


app = FastAPI(
    title="Wallet Service (SS7)",
    description="Agent-facing secure credential container for Zero-Trust Agentic AI Layer 1",
    version="0.1.0",
    lifespan=lifespan
)

# Health check
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "wallet_service"}

# Root
@app.get("/")
async def root():
    return {
        "service": "Wallet Service (SS7)",
        "description": "Secure agent credential container and presenter",
        "docs": "/docs"
    }

# Register routers
app.include_router(wallet_lifecycle.router)
app.include_router(credential_store.router)
app.include_router(credential_query.router)
app.include_router(present.router)
app.include_router(present_zkp.router)
app.include_router(reputation.router)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=WALLET_SERVICE_PORT,
        reload=(ENVIRONMENT == "development")
    )
