# How to Run Docker Compose (Step-by-Step)

##  Complete 10-Service Orchestration

Your setup now includes **10 services**:

**Infrastructure (3):**
1. Redis (cache, nonces, blocklist)
2. PostgreSQL (persistent storage)
3. Kafka + Zookeeper (event streaming)

**Trust Infrastructure - Person A (3):**
4. KMS (key management)
5. DID Registry (DID resolution)
6. Trust Anchor (issuer authorization)

**Credential Services - Person B (4):**
7. VC Issuance (SS4) - Issue credentials
8. VC Verification (SS5) - Verify presentations
9. Status List Service (SS6) - Revocation + blocklist
10. Wallet Service (SS7) - Agent credential storage

---

##  Method 1: Auto Start Script (Easiest)

### Windows

```bash
cd c:\Users\Disha\Zero_trust-agentic-AI-Layer1
start-docker.bat
```

**What it does:**
- Checks Docker is installed
- Checks Docker Compose is installed
- Verifies docker-compose.yml exists
- Starts all 10 services

**Expected output:**
```
[1/4] Checking Docker installation...
   ✓ Docker found
[2/4] Checking Docker Compose...
   ✓ Docker Compose found
[3/4] Checking docker-compose.yml...
   ✓ docker-compose.yml found
[4/4] Starting all services...
```

### macOS / Linux

```bash
cd c:\Users\Disha\Zero_trust-agentic-AI-Layer1
chmod +x start-docker.sh
./start-docker.sh
```

---

##  Method 2: Manual Commands

### Step 1: Navigate to Project

```bash
cd c:\Users\Disha\Zero_trust-agentic-AI-Layer1
```

### Step 2: Start All Services (Foreground)

```bash
docker-compose up --build
```

**What happens:**
1. Pulls base images (python:3.11, redis:7-alpine, postgres:15, kafka, zookeeper)
2. Builds custom images (vc_verification, status_list_service, wallet_service)
3. Creates `zero-trust` internal network
4. Starts infrastructure first (redis, postgres, kafka, zookeeper)
5. Starts trust services (kms, did_registry, trust_anchor)
6. Starts credential services (vc_issuance, vc_verification, status_list_service)
7. Starts agent services (wallet_service)
8. Runs health checks for each service

**Typical startup time: 2-3 minutes**

### Step 3: Verify All Services Running

**In a new terminal:**

```bash
docker-compose ps
```

**Expected output:**
```
NAME                      STATUS              PORTS
redis                     Up (healthy)        6379/tcp
postgres                  Up (healthy)        5432/tcp
kafka                     Up (healthy)        9092/tcp
zookeeper                 Up (healthy)        2181/tcp
kms                       Up (healthy)        8001/tcp
did_registry              Up (healthy)        8002/tcp
trust_anchor              Up (healthy)        8003/tcp
vc_issuance               Up (healthy)        8004/tcp
vc_verification           Up (healthy)        8005→8004/tcp
status_list_service       Up (healthy)        8006→8005/tcp
wallet_service            Up (healthy)        8007→8006/tcp
```

### Step 4: Test Health Endpoints

```bash
# Test each service
curl http://localhost:8001/health   # KMS
curl http://localhost:8002/health   # DID Registry
curl http://localhost:8003/health   # Trust Anchor
curl http://localhost:8004/health   # VC Issuance
curl http://localhost:8005/health   # VC Verification
curl http://localhost:8006/health   # Status List
curl http://localhost:8007/health   # Wallet
```

**Expected response:**
```json
{"status": "healthy"}
```

---

## Method 3: Start in Background

If you want to keep using your terminal:

```bash
# Start services in background
docker-compose up -d --build

# Check status
docker-compose ps

# View logs
docker-compose logs -f

# Stop when done
docker-compose down
```

---

## Service Ports Reference

| Service | Port | Access | Purpose |
|---------|------|--------|---------|
| Redis | 6379 | localhost:6379 | Cache, nonces, blocklist |
| PostgreSQL | 5432 | localhost:5432 | Database |
| Kafka | 9092 | localhost:9092 | Event streaming |
| Zookeeper | 2181 | localhost:2181 | Kafka coordination |
| **KMS** | 8001 | localhost:8001 | Key management (Person A) |
| **DID Registry** | 8002 | localhost:8002 | DID resolution (Person A) |
| **Trust Anchor** | 8003 | localhost:8003 | Issuer authorization (Person A) |
| **VC Issuance** | 8004 | localhost:8004 | Issue credentials (SS4) |
| **VC Verification** | 8005 | localhost:8005 | Verify presentations (SS5) |
| **Status List** | 8006 | localhost:8006 | Revocation (SS6) |
| **Wallet** | 8007 | localhost:8007 | Credential storage (SS7) |

---

##  How to Stop Services

### Stop and Keep Containers (can restart)

```bash
docker-compose stop
```

Then restart:
```bash
docker-compose start
```

### Stop and Remove Containers

```bash
docker-compose down
```

### Remove Everything (Clean Slate)

```bash
docker-compose down -v
```

This removes:
- All containers
- All volumes (database data)
- All networks

**Use with caution** — you'll lose all stored data!

---

##  Viewing Logs

### All Logs

```bash
docker-compose logs
```

### Live Logs (Follow Mode)

```bash
docker-compose logs -f
```

### Logs for One Service

```bash
docker-compose logs -f vc_verification
docker-compose logs -f wallet_service
docker-compose logs -f kms
```

### Last 50 Lines

```bash
docker-compose logs --tail 50 vc_issuance
```

### Logs with Timestamps

```bash
docker-compose logs -f --timestamps
```

---

##  Run Integration Tests

Once all services are healthy:

### In a New Terminal

```bash
# Run all integration tests
docker-compose exec vc_verification pytest tests/test_integration_*.py -v

# Run specific test file
docker-compose exec vc_verification pytest tests/test_integration_ss4_ss5.py -v

# Run with output
docker-compose exec vc_verification pytest tests/ -v -s
```

---

##  Troubleshooting

### Problem: Port Already in Use

```
ERROR: bind: address already in use [::]:8004
```

**Solution 1:** Stop other services using that port
```bash
docker-compose down
```

**Solution 2:** Find and kill process using port (Windows)
```bash
netstat -ano | findstr 8004
taskkill /PID <PID> /F
```

**Solution 3:** Find and kill process using port (macOS/Linux)
```bash
lsof -i :8004
kill -9 <PID>
```

---

### Problem: Image Build Failed

```
ERROR: Service vc_verification failed to build
```

**Solution:**
```bash
# Rebuild without cache
docker-compose build --no-cache

# Try again
docker-compose up
```

---

### Problem: Service Won't Start / Health Check Failing

```
ERROR: Service vc_issuance exited with code 1
```

**Check logs:**
```bash
docker-compose logs vc_issuance
```

**Common causes:**
- Missing environment variables
- Upstream dependency not healthy yet
- Port conflict
- Missing Python package

**Fix:**
```bash
docker-compose down -v
docker-compose up --build
```

---

### Problem: Services Can't Talk to Each Other

```
Error: Cannot connect to http://kms:8001
```

**Solution:** Verify network
```bash
docker network ls
docker network inspect zero-trust_zero-trust
```

---

### Problem: Out of Disk Space

```
ERROR: no space left on device
```

**Clean up Docker:**
```bash
docker system prune -a
docker volume prune
```

---
## Performance Tips

### Speed Up Build Time

```bash
# Rebuild only changed service
docker-compose build --no-cache wallet_service

# Then start just that service
docker-compose up wallet_service
```

### Reduce Startup Time

- Infrastructure (redis, postgres, kafka) starts first (in parallel)
- Trust services start (depend on infrastructure)
- Credential services start (depend on trust services)
- Agent services start last

Total: ~2-3 minutes depending on your machine

### Monitor Resource Usage

```bash
docker stats
```

Watch CPU, memory, network usage in real-time

---

##  Security Notes

### Development Mode (Current)

- Simple passwords used (OK for dev)
- All services in one compose file (OK for dev)
- No encryption for inter-service communication (OK for dev)

### Before Production

- Use `.env.local` with strong secrets
- Use Docker secrets or Vault for sensitive values
- Use separate services on different machines
- Use TLS/mTLS for inter-service communication
- Don't expose ports directly to internet

---
##  Verification Checklist

Before running integration tests:

- [ ] `docker-compose ps` shows 11 services with "Up (healthy)" status
- [ ] `curl http://localhost:8001/health` returns `{"status": "healthy"}`
- [ ] All 11 services have (healthy) status
- [ ] Docker using < 4GB RAM
- [ ] No error messages in logs after startup stabilizes

---

##  Quick Commands Reference

```bash
# Start services
docker-compose up --build

# Start in background
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f

# Stop services
docker-compose stop

# Remove everything
docker-compose down -v

# Run command in container
docker-compose exec vc_verification bash

# Run tests
docker-compose exec vc_verification pytest tests/ -v

# View specific service logs
docker-compose logs -f wallet_service
```

---

##  Next Steps

1. **Run:** `docker-compose up --build`
2. **Verify:** `docker-compose ps` (should show 11 healthy services)
3. **Test:** `curl http://localhost:8001/health`
4. **Integrate:** Run integration tests
5. **Monitor:** `docker-compose logs -f`
6. **Explore:** Visit http://localhost:8004 (VC Issuance), etc.

---

##  Related Documentation

- [DOCKER_COMPOSE_GUIDE.md](./DOCKER_COMPOSE_GUIDE.md) — Comprehensive guide with all commands
- [INTEGRATION_TESTING_QUICK_REFERENCE.md](./INTEGRATION_TESTING_QUICK_REFERENCE.md) — How to run tests
- [PLATFORM_COMPLETE.md](./PLATFORM_COMPLETE.md) — Full architecture overview

---

**Ready? Run: `docker-compose up --build`**
