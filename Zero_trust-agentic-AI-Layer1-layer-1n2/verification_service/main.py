"""
main.py
Verification Service FastAPI Application

Entry point for the VC Verification Service.
Handles startup/shutdown events, router registration, middleware, etc.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

import config
from cache import redis_client
from routers import nonce, presentation, credential

logger = logging.getLogger(__name__)

# Configure logging
logging.basicConfig(level=config.LOG_LEVEL)


# Lifespan events 

@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan context — startup and shutdown events."""
    # Startup
    logger.info("Starting Verification Service...")
    await redis_client.init_redis()
    logger.info(f"Verification Service running on {config.VERIFICATION_SERVICE_HOST}:{config.VERIFICATION_SERVICE_PORT}")

    yield

    # Shutdown
    logger.info("Shutting down Verification Service...")
    await redis_client.close_redis()
    logger.info("Verification Service stopped")


# FastAPI App 

app = FastAPI(
    title="VC Verification Service",
    description="Verifies Verifiable Credentials and Presentations",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(nonce.router)
app.include_router(presentation.router)
app.include_router(credential.router)


#  Health Check 

@app.get("/health")
async def health_check():
    """Simple health check endpoint."""
    return {"status": "ok", "service": "verification"}


#  Root 

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "VC Verification Service",
        "version": "1.0.0",
        "endpoints": {
            "health": "GET /health",
            "nonce": "POST /verify/nonce",
            "presentation": "POST /verify/presentation",
            "credential": "POST /verify/credential",
            "docs": "GET /docs",
            "redoc": "GET /redoc"
        }
    }


# CLI Entry Point 

if __name__ == "__main__":
    uvicorn.run(
        app,
        host=config.VERIFICATION_SERVICE_HOST,
        port=config.VERIFICATION_SERVICE_PORT,
        log_level=config.LOG_LEVEL.lower()
    )
