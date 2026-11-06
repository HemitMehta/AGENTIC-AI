# Docker Compose — Complete 10-Service Orchestration

## Architecture Overview

Your docker-compose.yml orchestrates **7 microservices** across **3 layers**:

```
┌─────────────────────────────────────────────────────────────┐
│  External Layer: Clients, Verifiers, Agents                 │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  Application Services (Ports 8004-8007)                     │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ SS4: VC Issuance (8004)    │ SS7: Wallet (8007)    │   │
│  │ SS5: Verification (8005)   │ SS6: Status List (8006)   │
│  └─────────────────────────────────────────────────────┘   │
│  ↑ ↑ ↑                                                       │
└─────────────────────────────────────────────────────────────┘
    ↓ ↓ ↓
┌─────────────────────────────────────────────────────────────┐
│  Trust Infrastructure (Person A) - Ports 8001-8003          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  KMS (8001)  │  │  DID Reg     │  │  Trust       │      │
│  │  Key Mgmt    │  │  (8002)      │  │  Anchor      │      │
│  │              │  │  DIDs        │  │  (8003)      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
    ↓ ↓ ↓
┌─────────────────────────────────────────────────────────────┐
│  Infrastructure (Redis, Postgres, Kafka)                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Redis      │  │   PostgreSQL │  │    Kafka     │      │
│  │  (6379)      │  │   (5432)     │  │   (9092)     │      │
│  │  Cache,      │  │   Database   │  │   Events     │      │
│  │  Nonces      │  │              │  │              │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

```bash
# Check Docker installation
docker --version
# Expected: Docker version 20.10+

# Check Docker Compose
docker-compose --version
# Expected: Docker Compose version 2.0+

# For Windows: Use Docker Desktop
# For macOS: Use Docker Desktop
# For Linux: Install Docker + docker-compose
```

---

##  Quick Start (3 steps)

### Step 1: Start All Services

```bash
cd c:\Users\Disha\Zero_trust-agentic-AI-Layer1
docker-compose up --build
```

**What happens:**
- Docker builds the 2 custom images (vc_verification, status_list, wallet_service)
- Pulls base images (python:3.11-slim, redis:7-alpine)
- Starts all 7 services in dependency order
- Waits for health checks (5 retries × 5s = ~25s total startup)

**Expected output (last lines):**
```
redis is healthy
kms is healthy
did_registry is healthy
trust_anchor is healthy
vc_issuance is healthy
vc_verification is healthy
status_list_service is healthy
wallet_service is healthy
```

### Step 2: Verify All Services Running

```bash
# In a new terminal
docker-compose ps
```

**Expected output:**
```
NAME                      STATUS              PORTS
redis                     Up (healthy)        6379/tcp
kms                       Up (healthy)        8001/tcp
did_registry              Up (healthy)        8002/tcp
trust_anchor              Up (healthy)        8003/tcp
vc_issuance               Up (healthy)        8004/tcp
vc_verification           Up (healthy)        8005→8004/tcp
status_list_service       Up (healthy)        8006→8005/tcp
wallet_service            Up (healthy)        8007→8006/tcp
```

### Step 3: Test Endpoints

```bash
# Health check all services
curl http://localhost:8001/health   # KMS
curl http://localhost:8002/health   # DID Registry
curl http://localhost:8003/health   # Trust Anchor
curl http://localhost:8004/health   # VC Issuance
curl http://localhost:8005/health   # VC Verification
curl http://localhost:8006/health   # Status List
curl http://localhost:8007/health   # Wallet
```

---

## Service Status & Ports

| Service | Container Port | Host Port | Status | Role |
|---------|---|---|---|---|
| **Redis** | 6379 | 6379 | Infrastructure | Cache, nonces, blocklist |
| **KMS** | 8001 | 8001 | Trust (A) | Key generation, signing |
| **DID Registry** | 8002 | 8002 | Trust (A) | DID resolution, controllers |
| **Trust Anchor** | 8003 | 8003 | Trust (A) | Issuer authorization |
| **VC Issuance** | 8004 | 8004 | Services (B) | Issue credentials |
| **VC Verification** | 8004 | 8005 | Services (B) | Verify presentations |
| **Status List** | 8005 | 8006 | Services (B) | Revocation + blocklist |
| **Wallet** | 8006 | 8007 | Agent | Store & present credentials |

---

##  Common Docker Compose Commands

### Lifecycle Management

```bash
# Start services (foreground - see logs)
docker-compose up

# Start services (background)
docker-compose up -d

# Stop services (keep containers)
docker-compose stop

# Restart services
docker-compose restart

# Stop and remove containers
docker-compose down

# Remove containers + volumes (clean slate)
docker-compose down -v

# Rebuild images
docker-compose build --no-cache
```

### Viewing Information

```bash
# Show running services
docker-compose ps

# Show logs (all services)
docker-compose logs

# Tail logs (follow mode)
docker-compose logs -f

# Logs for specific service
docker-compose logs -f vc_verification

# Last 50 lines
docker-compose logs --tail 50 vc_issuance
```

### Execute Commands

```bash
# Run command in running container
docker-compose exec vc_verification bash
docker-compose exec redis redis-cli

# Run tests in container
docker-compose exec vc_verification pytest tests/ -v

# View service environment
docker-compose exec kms env
```

### Inspect Network

```bash
# Enter container shell
docker-compose exec vc_verification bash

# Inside container, test internal DNS
curl http://kms:8001/health
curl http://redis:6379  # Redis port

# Test from host
docker network ls
docker network inspect zero-trust_zero-trust
```

---

## Troubleshooting

### Problem 1: Port Already in Use

```
Error: bind: address already in use
```

**Solution A:** Use different ports in compose
```yaml
ports:
  - "9001:8001"  # Map 9001→8001 instead
```

**Solution B:** Kill existing process
```bash
# Windows
netstat -ano | findstr 8001
taskkill /PID <PID> /F

# macOS/Linux
lsof -i :8001
kill -9 <PID>
```

**Solution C:** Stop other containers
```bash
docker-compose down
```

---

### Problem 2: Services Not Starting (Health Check Failing)

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
- Image build failed

**Fix:**
```bash
# Rebuild without cache
docker-compose build --no-cache

# Try again
docker-compose up
```

---

### Problem 3: Services Connected but Can't Communicate

```
Error: Cannot connect to http://kms:8001
```

**This means:**
- Services are on different networks
- DNS not resolving

**Fix:**
```bash
# Verify network
docker network ls

# Check which containers are on zero-trust network
docker network inspect zero-trust_zero-trust

# If missing, recreate
docker-compose down
docker-compose up
```

---

### Problem 4: Out of Memory / Disk Space

```
ERROR: no space left on device
```

**Check disk:**
```bash
docker system df
```

**Clean up:**
```bash
# Remove unused images
docker image prune -a

# Remove unused volumes
docker volume prune

# Remove everything (careful!)
docker system prune -a --volumes
```

---

### Problem 5: Slow Build / Network Issues

```
# Install with pip failed
# Read timed out
```

**Solutions:**
```bash
# Rebuild with no-cache + increase timeout
docker-compose build --no-cache --build-arg BUILDKIT_INLINE_CACHE=1

# Or manually pull base images first
docker pull python:3.11-slim
docker pull redis:7-alpine
```

---

##  Performance & Optimization

### Reduce Build Time

```bash
# Use .dockerignore to skip unnecessary files
echo "
__pycache__
*.pyc
.git
.pytest_cache
node_modules
" > .dockerignore
```

### Reduce Memory Usage

```yaml
# Add resource limits to docker-compose.yml
services:
  kms:
    mem_limit: 512m
    memswap_limit: 512m
```

### Parallel Startup

```bash
# Services start in dependency order automatically
# To speed up, run independent services in parallel

# Only start infrastructure
docker-compose up redis

# In another terminal, start services
docker-compose up --build vc_issuance vc_verification
```

---

## Verify Complete Setup

### Test 1: All Services Running

```bash
docker-compose ps | grep "Up (healthy)"
# Should show 8 services with "Up (healthy)"
```

### Test 2: Network Communication

```bash
# From vc_verification container, reach KMS
docker-compose exec vc_verification curl http://kms:8001/health

# Expected:
# {"status": "healthy"}
```

### Test 3: Full Integration Flow

```bash
# Issue a credential
curl -X POST http://localhost:8004/credentials/issue \
  -H "Content-Type: application/json" \
  -d '{
    "subject_did": "did:web:alice",
    "credential_type": "RoleCredential",
    "claims": {"role": "engineer", "level": 3}
  }'

# Should succeed and return signed VC JWT
```

---

##  Monitoring & Debugging

### Real-time Logs

```bash
# Watch all services
watch -n 1 'docker-compose ps'

# Live logs with timestamps
docker-compose logs -f --timestamps

# Filter for errors
docker-compose logs | grep -i error
```

### System Resources

```bash
# CPU and memory usage
docker stats

# Container details
docker inspect <container_name>
```

### Database/Cache State

```bash
# Connect to Redis
docker-compose exec redis redis-cli

# Inside redis-cli:
> KEYS *           # See all keys
> GET key_name     # Get value
> FLUSHALL         # Clear everything

# Connect to PostgreSQL
docker-compose exec postgres psql -U user -d <database>
```

---

##  Security Considerations

### In Development

```bash
# Current setup uses simple passwords
DATABASE_URL=postgresql://user:password@postgres:5432

# OK for dev, but note: passwords visible in logs, env
```

### Before Production

```bash
# Use .env.local (don't commit)
cp .env .env.local

# Update with strong secrets
VAULT_TOKEN=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -base64 32)

# Update compose to use external secrets
```

---

## Deployment Strategies

### Development (Current Setup)

```bash
# Local testing with volume mounts
docker-compose up

# Hot reload code changes
```

### Staging

```bash
# Build once, push to registry
docker-compose build --no-cache
docker tag wallet_service myregistry/wallet_service:v1.0
docker push myregistry/wallet_service:v1.0

# Deploy with pinned versions
docker-compose up --no-build
```

### Production

```bash
# Use managed services (RDS for Postgres, ElastiCache for Redis, MSK for Kafka)
# Deploy with Kubernetes or ECS instead of docker-compose
# Use secrets management (Vault, AWS Secrets Manager)
```

---

##  Next Steps

### 1. Verify Setup
```bash
docker-compose ps
```

### 2. Run Integration Tests
```bash
docker-compose exec vc_verification pytest tests/test_integration_*.py -v
```

### 3. Monitor Services
```bash
docker-compose logs -f
```

### 4. Test Workflows
- Issue VC via SS4 → POST /credentials/issue
- Store in wallet → POST /wallets/:did/store
- Present to verifier → POST /wallets/:did/present
- Verify → POST /verify/presentation

---

##  Pro Tips

1. **Separate Logs:** Start compose in background, view logs separately
   ```bash
   docker-compose up -d
   docker-compose logs -f vc_verification
   ```

2. **Rebuild One Service:** Don't rebuild everything
   ```bash
   docker-compose up --build wallet_service
   ```

3. **Use Shell Aliases:** Speed up common commands
   ```bash
   alias dcu='docker-compose up'
   alias dcd='docker-compose down'
   alias dcps='docker-compose ps'
   alias dcl='docker-compose logs -f'
   ```

4. **Debug with Shell:** Access container for inspection
   ```bash
   docker-compose exec vc_verification bash
   pip list  # Check installed packages
   python -c "import fastapi; print(fastapi.__version__)"
   ```

5. **Health Check Interval:** Services wait for dependencies
   ```yaml
   depends_on:
     kms:
       condition: service_healthy  # Waits for health check
   ```

---

##  Checklist Before Running

- [ ] Docker Desktop installed and running
- [ ] docker-compose version 2.0+
- [ ] Ports 6379, 8001-8007 not already in use
- [ ] .env file exists with configuration
- [ ] docker-compose.yml in root directory
- [ ] All Dockerfile files exist (verification_service, status_list_service, wallet_service)
- [ ] All source Python files exist (kms.py, did.py, vc_issuance.py, etc.)
- [ ] At least 4GB RAM available for all services
- [ ] At least 5GB disk space for images + containers

---

##  Quick Help

| Issue | Command |
|-------|---------|
| Stuck on startup? | `docker-compose logs` |
| Service won't start? | `docker-compose build --no-cache` |
| Out of space? | `docker system prune -a` |
| Need to restart? | `docker-compose restart` |
| Clean up everything? | `docker-compose down -v` |
| See all running? | `docker-compose ps -a` |

---

**Ready to start? Run: `docker-compose up --build`**
