# Docker Compose Architecture Diagram

## Network Topology (All Services Connected via `zero-trust` Bridge Network)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Docker Compose Network: zero-trust                    │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                     INFRASTRUCTURE LAYER                             │  │
│  │                                                                      │  │
│  │  ┌───────────────┐   ┌──────────────┐   ┌────────────────────────┐│  │
│  │  │    Redis      │   │  PostgreSQL  │   │   Kafka + Zookeeper    ││  │
│  │  │   (6379)      │   │   (5432)     │   │  (9092, 2181)          ││  │
│  │  │               │   │              │   │                        ││  │
│  │  │ • Cache       │   │ • SS6 DB     │   │ • Event Stream         ││  │
│  │  │ • Nonces      │   │ • SS7 DB     │   │ • Revocation Log       ││  │
│  │  │ • Blocklist   │   │              │   │ • Audit Trail          ││  │
│  │  └───────────────┘   └──────────────┘   └────────────────────────┘│  │
│  └────────────────┬───────────────────────┬──────────────────────────┘  │
│                   ↓                       ↓                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │              PERSON A: TRUST INFRASTRUCTURE                          │  │
│  │                                                                      │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │  │
│  │  │     KMS      │  │ DID Registry │  │ Trust Anchor │              │  │
│  │  │   (8001)     │  │   (8002)     │  │   (8003)     │              │  │
│  │  │              │  │              │  │              │              │  │
│  │  │ • Keys       │  │ • DIDs       │  │ • Authorize  │              │  │
│  │  │ • Sign VPs   │  │ • Controllers│  │   Issuers    │              │  │
│  │  │ • Sign VCs   │  │              │  │              │              │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘              │  │
│  │         ↑                  ↑                 ↑                       │  │
│  └─────────┼──────────────────┼─────────────────┼─────────────────────┘  │
│            │                  │                 │                        │
│  ┌─────────┼──────────────────┼─────────────────┼─────────────────────┐  │
│  │         ↓                  ↓                 ↓                     │  │
│  │      PERSON B: CREDENTIAL SERVICES                                │  │
│  │                                                                  │  │
│  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐   │  │
│  │  │   SS4: Issue   │  │  SS5: Verify   │  │  SS6: Revoke   │   │  │
│  │  │   (8004)       │  │  (8005)        │  │  (8006)        │   │  │
│  │  │                │  │                │  │                │   │  │
│  │  │ • Issue 6 VCs  │  │ • Verify VP    │  │ • Allocate SL  │   │  │
│  │  │ • Store in S7  │  │ • Check revoke │  │ • Revoke cred  │   │  │
│  │  │ • Peer rep.    │  │ • Check exp.   │  │ • Cascade      │   │  │
│  │  └────────────────┘  └────────────────┘  └────────────────┘   │  │
│  │                             ↑                                  │  │
│  │                             │                                  │  │
│  │                    ┌────────────────┐                          │  │
│  │                    │   SS7: Wallet  │                          │  │
│  │                    │   Agent (8007) │                          │  │
│  │                    │                │                          │  │
│  │                    │ • Init wallet  │                          │  │
│  │                    │ • Store VCs    │                          │  │
│  │                    │ • Query creds  │                          │  │
│  │                    │ • Present VP   │                          │  │
│  │                    │ • ZKP proofs   │                          │  │
│  │                    └────────────────┘                          │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│                         Internal DNS Resolution:                  │
│                   redis:6379   → localhost:6379                   │
│                   postgres:5432 → localhost:5432                  │
│                   kafka:9092   → localhost:9092                   │
│                   kms:8001     → localhost:8001                   │
│                   did_registry:8002 → localhost:8002              │
│                   trust_anchor:8003 → localhost:8003              │
│                   vc_issuance:8004 → localhost:8004               │
│                   vc_verification:8004 → localhost:8005           │
│                   status_list:8005 → localhost:8006               │
│                   wallet_service:8006 → localhost:8007            │
│                                                                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow: Issue → Store → Verify

```
1. ISSUANCE FLOW (SS4)
   ┌─────────────┐
   │   Agent     │  Request VC
   └──────┬──────┘
          │
          ↓
   ┌──────────────────────────────────┐
   │    SS4: VC Issuance (8004)       │
   │                                  │
   │ 1. Validate subject (DID Reg)   │
   │ 2. Check authority (Trust Anchor)│
   │ 3. Build VC JSON                │
   │ 4. Allocate Status List (SS6)   │
   │ 5. Sign via KMS                 │
   │ 6. Store in DB                  │
   │ 7. Return JWT                   │
   │                                  │
   │    ↓ Calls SS7                  │
   └──────────────┬───────────────────┘
                  │ POST /wallets/:did/store
                  ↓
   
   ┌──────────────────────────────────┐
   │    SS7: Wallet Agent (8007)      │
   │                                  │
   │ 1. Decode JWT                   │
   │ 2. Derive AES key (in-memory)   │
   │ 3. Encrypt VC                   │
   │ 4. Store encrypted blob + IV    │
   │ 5. Zero key from memory         │
   │ 6. Return vc_id                 │
   │                                  │
   │ ➜ Uses PostgreSQL (5432)        │
   │ ➜ Uses KMS for key derivation   │
   └──────────────────────────────────┘


2. PRESENTATION FLOW (SS7 → SS5)
   ┌──────────────────────────────────┐
   │    Agent (via SS7 Wallet)        │
   └──────┬───────────────────────────┘
          │
          │ POST /wallets/:did/present
          ↓
   ┌──────────────────────────────────┐
   │    SS7: Wallet Agent (8007)      │
   │                                  │
   │ 1. Query credentials by type     │
   │ 2. Enforce selective disclosure  │
   │ 3. For each VC:                 │
   │    - Derive AES key (in-memory) │
   │    - Decrypt VC                 │
   │    - Zero key                   │
   │ 4. Build VP JSON                │
   │ 5. Sign via KMS                 │
   │ 6. Return VP JWT                │
   │                                  │
   │ ➜ Uses PostgreSQL (5432)        │
   │ ➜ Uses KMS for signing          │
   └──────────────┬────────────────────┘
                  │ VP JWT
                  ↓
   ┌──────────────────────────────────┐
   │  Verifier sends to SS5           │
   │  POST /verify/presentation       │
   │                                  │
   │  SS5: VC Verification (8005)    │
   │                                  │
   │ 1. Verify VP signature (KMS)    │
   │ 2. Check nonce (Redis)          │
   │ 3. Delete nonce (replay prev.)  │
   │ 4. For each VC:                 │
   │    - Verify signature           │
   │    - Check trust anchor         │
   │    - Check revocation (SS6)     │
   │    - Check expiry               │
   │ 5. Return verification result   │
   │                                  │
   │ ➜ Uses Redis (6379) for nonces  │
   │ ➜ Uses KMS for verification     │
   │ ➜ Uses SS6 for revocation       │
   └──────────────────────────────────┘


3. REVOCATION FLOW (SS6)
   ┌─────────────────────────────────┐
   │ Security Team / Admin           │
   │ POST /revoke/credential/:id     │
   └──────┬──────────────────────────┘
          │
          ↓
   ┌───────────────────────────────────┐
   │  SS6: Status List Service (8006)  │
   │                                   │
   │ 1. Update Redis (immediate)       │
   │    - Flip bit in bitstring        │
   │ 2. Update PostgreSQL (durable)    │
   │    - Update entry status          │
   │ 3. Publish to Kafka (audit)       │
   │    - credential.revoked event     │
   │                                   │
   │ ➜ Uses Redis (6379) fast path    │
   │ ➜ Uses PostgreSQL (5432) for DB  │
   │ ➜ Uses Kafka (9092) for audit    │
   └───────────────┬────────────────────┘
                   │
        Visible in SS5 verification
        within 30s (Redis TTL)
```

## Startup Dependency Order

```
Step 1: Infrastructure (Parallel Start)
   ┌────────┐  ┌──────────┐  ┌────────────┐
   │ Redis  │  │PostgreSQL│  │ Zookeeper  │
   └────────┘  └──────────┘  └────────────┘
        │           │             │
        └───────────┼─────────────┘
                    ↓

Step 2: Trust Services (Depend on Infrastructure)
   ┌────────┐  ┌──────────┐  ┌────────────┐
   │  KMS   │  │DID Reg   │  │Trust Anchor│
   └────────┘  └──────────┘  └────────────┘
        │           │             │
        └───────────┼─────────────┘
                    ↓

Step 3: Kafka (After Zookeeper Ready)
   ┌────────────┐
   │   Kafka    │
   └────────────┘
        │
        └─────┬──────────────────────────┐
              ↓                          ↓

Step 4: Credential Services (Depend on Trust + Infra)
   ┌──────────┐  ┌──────────┐  ┌──────────┐
   │   SS4    │  │   SS5    │  │   SS6    │
   └──────────┘  └──────────┘  └──────────┘
        │           │             │
        └───────────┼─────────────┘
                    ↓

Step 5: Agent Services (Depend on SS4)
   ┌──────────┐
   │   SS7    │
   └──────────┘

Total Startup: ~3-5 minutes
```

## Service Communication Matrix

| From | To | Protocol | Port | Purpose |
|------|----|----|------|---------|
| SS4,SS5,SS6,SS7 | KMS | HTTP | 8001 | Key gen, signing |
| SS4,SS5,SS6,SS7 | DID Registry | HTTP | 8002 | DID resolution |
| SS4 | Trust Anchor | HTTP | 8003 | Authorization |
| SS7 | SS4 | HTTP | 8004 | Log reputation VCs |
| SS5 | SS6 | HTTP | 8006 | Revocation check |
| SS4,SS5,SS6,SS7 | Redis | TCP | 6379 | Cache, nonces |
| SS6,SS7 | PostgreSQL | TCP | 5432 | Persistent storage |
| SS6 | Kafka | TCP | 9092 | Audit events |

## Environment Variables (via .env)

```bash
# Infrastructure
REDIS_URL=redis://redis:6379
DATABASE_URL=postgresql://user:password@postgres:5432/...
KAFKA_BOOTSTRAP_SERVERS=kafka:9092

# Trust Services (Person A)
KMS_URL=http://kms:8001
DID_REGISTRY_URL=http://did_registry:8002
TRUST_ANCHOR_URL=http://trust_anchor:8003

# Credential Services (Person B)
VC_ISSUANCE_URL=http://vc_issuance:8004
STATUS_LIST_SERVICE_URL=http://status_list_service:8005

# Agent (SS7)
WALLET_SERVICE_PORT=8006
```

## Port Mapping (Host ← Container)

```
Host Port  Container Port  Service
6379   ←   6379           Redis
5432   ←   5432           PostgreSQL
9092   ←   9092           Kafka
2181   ←   2181           Zookeeper
8001   ←   8001           KMS
8002   ←   8002           DID Registry
8003   ←   8003           Trust Anchor
8004   ←   8004           VC Issuance
8005   ←   8004           VC Verification
8006   ←   8005           Status List Service
8007   ←   8006           Wallet Service
```

## Health Check Flow

```
docker-compose up
    ↓
    For each service:
    1. Wait for container to start
    2. Run health check command
    3. If healthy: ✓ move to next
    4. If fail: ✓ retry (max 5 times)
    5. If all retries fail: ✗ service unhealthy
    
All services healthy? → Ready to test ✅
Service unhealthy? → Check logs, debug ❌
```

---

**Ready to orchestrate? Run: `docker-compose up --build`**
