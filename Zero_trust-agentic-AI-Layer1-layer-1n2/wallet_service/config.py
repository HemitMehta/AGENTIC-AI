"""
wallet_service/config.py
Environment configuration for Wallet Service.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# Service Port
WALLET_SERVICE_PORT = int(os.getenv("WALLET_SERVICE_PORT", 8006))

# Upstream Services
KMS_URL = os.getenv("KMS_URL", "http://localhost:8001")
DID_REGISTRY_URL = os.getenv("DID_REGISTRY_URL", "http://localhost:8002")
VC_ISSUANCE_URL = os.getenv("VC_ISSUANCE_URL", "http://localhost:8004")

# Database
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://user:pass@localhost:26257/layer1")

# Cryptography
HKDF_ITERATIONS = int(os.getenv("HKDF_ITERATIONS", 1))
CIRCUITS_BASE_PATH = os.getenv("CIRCUITS_BASE_PATH", "./circuits")

# Subprocess Execution
NODE_BINARY = os.getenv("NODE_BINARY", "node")
BBS_SCRIPT_PATH = os.getenv("BBS_SCRIPT_PATH", "./bbs_derive_proof.js")
SNARK_TIMEOUT_SECONDS = int(os.getenv("SNARK_TIMEOUT_SECONDS", 30))
BBS_TIMEOUT_SECONDS = int(os.getenv("BBS_TIMEOUT_SECONDS", 10))

# HTTP Client
HTTP_CLIENT_TIMEOUT = int(os.getenv("HTTP_CLIENT_TIMEOUT", 5))

# Environment
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
