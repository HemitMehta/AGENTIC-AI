"""
status_list_service/config.py

Environment configuration for the Status List Service.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# Server
STATUS_LIST_SERVICE_PORT = int(os.getenv("STATUS_LIST_SERVICE_PORT", "8006"))
STATUS_LIST_BASE_URL = os.getenv("STATUS_LIST_BASE_URL", "http://localhost:8006")

# Caching
STATUS_CACHE_TTL = int(os.getenv("STATUS_CACHE_TTL", "30"))  # seconds

# Status list parameters
BITSTRING_SIZE_BITS = int(os.getenv("BITSTRING_SIZE_BITS", "131072"))  # 2^17
BITSTRING_SIZE_BYTES = BITSTRING_SIZE_BITS // 8  # 16384 bytes

# Upstream services
KMS_URL = os.getenv("KMS_URL", "http://localhost:8001")
KMS_STATUS_LIST_KEY_ID = os.getenv("KMS_STATUS_LIST_KEY_ID", "status-list-signing-key")
DID_REGISTRY_URL = os.getenv("DID_REGISTRY_URL", "http://localhost:8002")
ANS_URL = os.getenv("ANS_URL", "http://localhost:9001")

# Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# Kafka
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092").split(",")

# Database
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:password@localhost:5432/status_list"
)

# Cascade parameters
CASCADE_MAX_RETRIES = int(os.getenv("CASCADE_MAX_RETRIES", "3"))
CASCADE_RETRY_BASE_SECONDS = int(os.getenv("CASCADE_RETRY_BASE_SECONDS", "1"))

# HTTP timeout
HTTP_CLIENT_TIMEOUT = int(os.getenv("HTTP_CLIENT_TIMEOUT", "5"))  # seconds
