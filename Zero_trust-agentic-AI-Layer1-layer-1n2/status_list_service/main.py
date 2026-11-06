"""
status_list_service/main.py

FastAPI application for Status List Service.
"""

from fastapi import FastAPI, Request
from contextlib import asynccontextmanager
import logging

from config import STATUS_LIST_SERVICE_PORT
from db.connection import init_db, close_db, run_migration
from cache import redis_client
from kafka import producer
from routers import allocate, status_list, revoke, blocklist, agent_revoke

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
    logger.info("Status List Service starting up...")
    await init_db()
    await run_migration()
    await redis_client.init_redis()
    await producer.init_kafka_producer()
    logger.info("Status List Service ready")

    yield

    # Shutdown
    logger.info("Status List Service shutting down...")
    await redis_client.close_redis()
    await producer.close_kafka_producer()
    await close_db()
    logger.info("Status List Service stopped")


app = FastAPI(
    title="Status List Service (SS6)",
    description="Revocation infrastructure for Zero-Trust Agentic AI Layer 1",
    version="0.1.0",
    lifespan=lifespan
)

# Health check
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "status_list_service"}

# Root
@app.get("/")
async def root():
    return {
        "service": "Status List Service (SS6)",
        "description": "Revocation backbone for Zero-Trust Agentic AI Layer 1",
        "docs": "/docs"
    }

# Register routers
app.include_router(allocate.router)
app.include_router(status_list.router)
app.include_router(revoke.router)
app.include_router(blocklist.router)
app.include_router(agent_revoke.router)

# CORS middleware
from fastapi.middleware.cors import CORSMiddleware
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
        port=STATUS_LIST_SERVICE_PORT,
        reload=False
    )
