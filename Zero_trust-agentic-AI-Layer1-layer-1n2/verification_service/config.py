"""
config.py
Verification Service Configuration

Loads environment variables with sensible defaults.
Security note: STATUS_CACHE_TTL is a security parameter, not just performance.
A too-long TTL can allow revoked credentials to pass verification for minutes after revocation.
Default 30 seconds balances security (revocation latency) with performance (network load on status list service).
"""

import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

# Service Configuration 

VERIFICATION_SERVICE_PORT = int(os.getenv("VERIFICATION_SERVICE_PORT", "8004"))
VERIFICATION_SERVICE_HOST = os.getenv("VERIFICATION_SERVICE_HOST", "0.0.0.0")

# Upstream Service URLs 

KMS_URL = os.getenv("KMS_URL", "http://localhost:8001")
DID_REGISTRY_URL = os.getenv("DID_REGISTRY_URL", "http://localhost:8002")
TRUST_ANCHOR_URL = os.getenv("TRUST_ANCHOR_URL", "http://localhost:8003")
STATUS_LIST_BASE_URL = os.getenv("STATUS_LIST_BASE_URL", "http://localhost:8006")
KMS_STATUS_LIST_KEY_ID = os.getenv("KMS_STATUS_LIST_KEY_ID", "status-list-signing-key")

# HTTP Client Configuration 

HTTP_CLIENT_TIMEOUT = int(os.getenv("HTTP_CLIENT_TIMEOUT", "5"))

# Redis Configuration 

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# Cache TTLs (Security Parameters) 

# Nonce TTL: How long a nonce is valid before it expires.
# Default 300s = 5 minutes. Longer = more time for presentation, but higher replay risk if nonce stolen.
NONCE_TTL_SECONDS = int(os.getenv("NONCE_TTL_SECONDS", "300"))

# Status List Cache TTL: How long we cache a fetched status list bitstring.
# SECURITY CRITICAL: A too-long TTL delays revocation propagation.
#   - TTL=30s (default): revoked credential may pass for up to 30s after revocation
#   - TTL=1s: higher accuracy, but 30x more load on status list service
#   - TTL=60s: lower load, but 2 minutes revocation latency — use only if your SLA allows
# Default 30 seconds balances security with practical performance.
STATUS_CACHE_TTL = int(os.getenv("STATUS_CACHE_TTL", "30"))

# Trust Anchor Cache TTL: How long we cache the root trust document.
# Default 60s. Trust anchor changes infrequently, but must be refreshed regularly for security.
TRUST_ANCHOR_CACHE_TTL = int(os.getenv("TRUST_ANCHOR_CACHE_TTL", "60"))

# ── ZKP Configuration (Future) ─────────────────────────────────────────────────

CIRCUIT_VKEY_PATH = os.getenv("CIRCUIT_VKEY_PATH", "./circuits/verification_key.json")

# ── Logging ────────────────────────────────────────────────────────────────────

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
