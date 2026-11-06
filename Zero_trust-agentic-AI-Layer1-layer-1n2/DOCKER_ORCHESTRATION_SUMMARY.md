# Docker Compose Setup — Complete (10 Services Configured)

##  Status: READY TO RUN

All 10 services are now fully configured in `docker-compose.yml` and ready for orchestration.

---

##  What You Have

### Infrastructure (3 services)
```
Redis         (6379)      — Cache, nonces, blocklist
PostgreSQL    (5432)      — Persistent storage for SS6, SS7
Kafka         (9092)      — Event streaming for audit trail
└─ Zookeeper  (2181)      — Kafka coordination
```

### Trust Infrastructure (Person A) (3 services)
```
KMS           (8001)      — Key generation, signing
DID Registry  (8002)      — DID resolution, controllers
Trust Anchor  (8003)      — Issuer authorization
```

### Credential Services (Person B) (4 services)
```
SS4: VC Issuance         (8004)  — Issue 6 VC types
SS5: VC Verification     (8005)  — Verify presentations
SS6: Status List (Revocation) (8006)  — Credential revocation
SS7: Wallet (Agent)      (8007)  — Credential storage
```

**Total: 11 containers (10 services + Zookeeper)**

---

## How to Start (Choose One)

### Option 1: Auto Script (Recommended)

**Windows:**
```bash
cd c:\Users\Disha\Zero_trust-agentic-AI-Layer1
start-docker.bat
```

**macOS/Linux:**
```bash
cd c:\Users\Disha\Zero_trust-agentic-AI-Layer1
chmod +x start-docker.sh
./start-docker.sh
```

### Option 2: Manual Command

```bash
cd c:\Users\Disha\Zero_trust-agentic-AI-Layer1
docker-compose up --build
```

### Option 3: Background

```bash
# Start in background
docker-compose up -d --build

# Check status in another terminal
docker-compose ps

# View logs
docker-compose logs -f
```

---

## Expected Timeline

| Phase | Duration | What Happens |
|-------|----------|---|
| Docker build | 1-2 min | Builds 3 custom images, pulls base images |
| Infrastructure startup | 30-40s | Redis, Postgres, Kafka, Zookeeper |
| Trust services startup | 20-30s | KMS, DID Registry, Trust Anchor (depend on Redis) |
| Credential services startup | 20-40s | SS4, SS5, SS6 (depend on trust services) |
| Agent services startup | 10-20s | SS7 Wallet (depends on SS4 + trust services) |
| Health checks stabilize | 10-15s | All health checks pass |
| **Total** | **~3-5 minutes** | **Ready to test** |

---

## Verification

### Check All Services Running

```bash
docker-compose ps
```

**Expected (11 containers with "Up (healthy)" status):**
```
NAME                      STATUS              PORTS
redis                     Up (healthy)        6379→6379/tcp
postgres                  Up (healthy)        5432→5432/tcp
kafka                     Up (healthy)        9092→9092/tcp
zookeeper                 Up (healthy)        2181→2181/tcp
kms                       Up (healthy)        8001→8001/tcp
did_registry              Up (healthy)        8002→8002/tcp
trust_anchor              Up (healthy)        8003→8003/tcp
vc_issuance               Up (healthy)        8004→8004/tcp
vc_verification           Up (healthy)        8005→8004/tcp
status_list_service       Up (healthy)        8006→8005/tcp
wallet_service            Up (healthy)        8007→8006/tcp
```

### Test Each Service

```bash
# Health endpoints (should all return 200 OK)
curl http://localhost:8001/health   # KMS
curl http://localhost:8002/health   # DID Registry
curl http://localhost:8003/health   # Trust Anchor
curl http://localhost:8004/health   # VC Issuance
curl http://localhost:8005/health   # VC Verification
curl http://localhost:8006/health   # Status List
curl http://localhost:8007/health   # Wallet

# Test Redis
docker-compose exec redis redis-cli PING
# Expected: PONG

# Test PostgreSQL
docker-compose exec postgres psql -U user -c "SELECT 1"
# Expected: 1

# Test Kafka
docker-compose exec kafka kafka-broker-api-versions.sh --bootstrap-server localhost:9092
# Expected: version info
```

---

##  What Was Updated

### 1. docker-compose.yml (Modified)
-  Added PostgreSQL service (15-alpine)
-  Added Kafka service (confluentinc/cp-kafka:7.5.0)
-  Added Zookeeper service (confluentinc/cp-zookeeper:7.5.0)
-  Updated status_list_service to depend on postgres + kafka
-  Added volumes section for postgres_data persistence

### 2. .env (Modified)
-  Added SS7 wallet service parameters (12 new variables)

### 3. New Files
-  `start-docker.bat` — Windows startup script
-  `start-docker.sh` — macOS/Linux startup script
-  `DOCKER_COMPOSE_GUIDE.md` — Comprehensive Docker guide
-  `DOCKER_COMPOSE_QUICKSTART.md` — Step-by-step quickstart

---

##  Service Dependencies

```
                    ┌─────────────────────────────────┐
                    │    Credential Services (B)      │
                    │  SS4 → SS5 → SS6 → SS7         │
                    └──────────────┬──────────────────┘
                                   ↓
                    ┌──────────────────────────────┐
                    │   Trust Infrastructure (A)    │
                    │  KMS + DID Reg + Trust Anchor│
                    └──────────────┬────────────────┘
                                   ↓
                    ┌──────────────────────────────┐
                    │    Infrastructure             │
                    │  Redis, Postgres, Kafka      │
                    └──────────────────────────────┘
```

**Startup Order (enforced by compose):**
1. Infrastructure (no dependencies)
2. Trust services (depend on infrastructure)
3. Credential services (depend on trust)
4. Agent services (depend on credential)

---

## How to Stop

### Graceful Stop (keep containers)
```bash
docker-compose stop
```

### Remove Containers (keep data)
```bash
docker-compose down
```

### Clean Everything (remove data)
```bash
docker-compose down -v
```

---

## Resource Requirements

### Minimum
- **CPU:** 2 cores
- **RAM:** 4 GB
- **Disk:** 5 GB free space

### Recommended
- **CPU:** 4+ cores
- **RAM:** 8+ GB
- **Disk:** 10+ GB free space

### Monitor Usage
```bash
docker stats
```

---

##  Next: Run Integration Tests

Once all services are healthy:

```bash
# Terminal 1: Keep compose running
docker-compose up

# Terminal 2: Run tests
docker-compose exec vc_verification pytest tests/test_integration_*.py -v
```

Expected: All tests pass 

---

## Documentation Files

| File | Purpose |
|------|---------|
| [DOCKER_COMPOSE_GUIDE.md](./DOCKER_COMPOSE_GUIDE.md) | Comprehensive Docker Compose guide with all commands |
| [DOCKER_COMPOSE_QUICKSTART.md](./DOCKER_COMPOSE_QUICKSTART.md) | Step-by-step quickstart with examples |
| [INTEGRATION_TESTING_QUICK_REFERENCE.md](./INTEGRATION_TESTING_QUICK_REFERENCE.md) | How to run integration tests |
| [PLATFORM_COMPLETE.md](./PLATFORM_COMPLETE.md) | Full architecture overview |
| [SS7_DELIVERY_SUMMARY.md](./SS7_DELIVERY_SUMMARY.md) | Agent Wallet Service details |

---

##  Common Tasks

```bash
# Start services
docker-compose up --build

# Check status
docker-compose ps

# View logs
docker-compose logs -f vc_verification

# Run tests
docker-compose exec vc_verification pytest tests/ -v

# Enter service shell
docker-compose exec wallet_service bash

# Stop services
docker-compose stop

# Clean everything
docker-compose down -v
```

---

##  Production Checklist

Before deploying to production:

- [ ] Use `.env.local` with strong secrets (not in git)
- [ ] PostgreSQL authentication with strong password
- [ ] Redis persistence enabled
- [ ] Kafka replication factor > 1
- [ ] TLS/mTLS for inter-service communication
- [ ] Use managed services (AWS RDS, ElastiCache, MSK)
- [ ] Deploy with Kubernetes instead of docker-compose
- [ ] Enable audit logging to Kafka
- [ ] Set up monitoring + alerting
- [ ] Use separate networks per environment

---

##  Troubleshooting

**Port in use?**
```bash
docker-compose down
```

**Build failed?**
```bash
docker-compose build --no-cache
```

**Service won't start?**
```bash
docker-compose logs <service_name>
```

**Out of space?**
```bash
docker system prune -a
```

---

## Ready?

### Run Now:

**Windows:**
```
start-docker.bat
```

**macOS/Linux:**
```
./start-docker.sh
```

**Manual:**
```
docker-compose up --build
```

---

##  Quick Reference

| Command | Purpose |
|---------|---------|
| `docker-compose up --build` | Start all services |
| `docker-compose ps` | See all running services |
| `docker-compose logs -f` | View live logs |
| `docker-compose stop` | Stop services |
| `docker-compose down -v` | Remove everything |
| `docker stats` | Monitor resource usage |

---

**Everything is configured. Ready to orchestrate 10 services! **

Run: `docker-compose up --build`
