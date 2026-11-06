# Docker Compose — Command Cheatsheet

##  QUICK START (Copy & Paste)

### Windows
```bash
cd c:\Users\Disha\Zero_trust-agentic-AI-Layer1 && start-docker.bat
```

### macOS/Linux
```bash
cd c:\Users\Disha\Zero_trust-agentic-AI-Layer1 && ./start-docker.sh
```

### Manual (All Platforms)
```bash
cd c:\Users\Disha\Zero_trust-agentic-AI-Layer1 && docker-compose up --build
```

---

## ESSENTIAL COMMANDS

### Lifecycle
```bash
docker-compose up              # Start (foreground, see logs)
docker-compose up -d           # Start (background)
docker-compose up --build      # Start + rebuild images
docker-compose stop            # Stop (keep containers)
docker-compose restart         # Restart
docker-compose down            # Stop + remove containers
docker-compose down -v         # Stop + remove + delete volumes (CLEAN)
```

### Status
```bash
docker-compose ps             # Show running services + status
docker-compose ps -a          # Show all services (including stopped)
```

### Logs
```bash
docker-compose logs           # Show all logs
docker-compose logs -f        # Follow (live) all logs
docker-compose logs -f kms    # Follow logs for one service
docker-compose logs --tail 50 # Last 50 lines
```

### Rebuild
```bash
docker-compose build          # Build all images
docker-compose build --no-cache # Force rebuild without cache
docker-compose build wallet_service # Rebuild one service
```

### Execute
```bash
docker-compose exec vc_verification bash    # Enter container shell
docker-compose exec redis redis-cli         # Run Redis CLI
docker-compose exec postgres psql -U user   # Enter PostgreSQL
```

### Tests
```bash
docker-compose exec vc_verification pytest tests/ -v
```

---

## VERIFICATION COMMANDS

### Check All Services
```bash
docker-compose ps
# Expected: All 11 services with "Up (healthy)"
```

### Test Individual Endpoints
```bash
curl http://localhost:8001/health    # KMS
curl http://localhost:8002/health    # DID Registry
curl http://localhost:8003/health    # Trust Anchor
curl http://localhost:8004/health    # VC Issuance
curl http://localhost:8005/health    # VC Verification
curl http://localhost:8006/health    # Status List
curl http://localhost:8007/health    # Wallet
```

### Test Redis
```bash
docker-compose exec redis redis-cli PING
# Expected: PONG
```

### Test PostgreSQL
```bash
docker-compose exec postgres psql -U user -c "SELECT 1"
# Expected: 1
```

### Monitor Resources
```bash
docker stats
# Watch CPU, memory, network usage in real-time
```

---

##  TROUBLESHOOTING COMMANDS

### View Service Details
```bash
docker-compose logs <service_name>       # Latest logs
docker-compose logs -f <service_name>    # Follow logs

# Examples:
docker-compose logs -f vc_verification
docker-compose logs -f wallet_service
```

### Check Service Errors
```bash
docker-compose logs | grep -i error
docker-compose logs | grep -i failed
```

### Inspect Network
```bash
docker network ls                            # List networks
docker network inspect zero-trust_zero-trust # Inspect our network
```

### Inspect Volume
```bash
docker volume ls                    # List volumes
docker volume inspect zero-trust_agentic-ai-layer1_postgres_data
```

### Check Port Usage (Windows)
```bash
netstat -ano | findstr 8001
taskkill /PID <PID> /F
```

### Check Port Usage (macOS/Linux)
```bash
lsof -i :8001
kill -9 <PID>
```

---

##  CLEANUP COMMANDS

### Remove Unused Images
```bash
docker image prune -a
```

### Remove Unused Volumes
```bash
docker volume prune
```

### Remove Unused Networks
```bash
docker network prune
```

### Full System Cleanup (CAREFUL!)
```bash
docker system prune -a --volumes
# Removes everything not actively in use
```

### Clean Specific Service
```bash
docker-compose down -v
# Removes containers, networks, and volumes for this project only
```

---

##  MONITORING COMMANDS

### Real-Time Stats
```bash
docker stats
watch -n 1 docker-compose ps
```

### View Container Details
```bash
docker inspect <container_name>
docker-compose exec <service> env  # See environment variables
```

### Check Image Size
```bash
docker images
docker-compose images
```

### Disk Usage
```bash
docker system df
```

---

## DATABASE COMMANDS

### PostgreSQL
```bash
# Connect to PostgreSQL
docker-compose exec postgres psql -U user

# Inside psql:
\l                    # List databases
\dt                   # List tables
\d table_name         # Describe table
SELECT * FROM table;  # Query
```

### Redis
```bash
# Connect to Redis
docker-compose exec redis redis-cli

# Inside redis-cli:
KEYS *               # See all keys
GET key_name         # Get value
SET key value        # Set value
FLUSHALL             # Delete everything
MONITOR              # Watch commands in real-time
```

---

## USEFUL WORKFLOWS

### Development Iteration
```bash
# Terminal 1: Keep compose running
docker-compose up

# Terminal 2: Make code changes
# (edit files, save)

# Terminal 3: Rebuild one service
docker-compose build --no-cache wallet_service

# Terminal 1: Restart service
docker-compose restart wallet_service

# Terminal 3: Run tests
docker-compose exec wallet_service pytest tests/ -v
```

### Debugging a Service
```bash
# 1. Follow logs
docker-compose logs -f wallet_service

# 2. Enter shell
docker-compose exec wallet_service bash

# 3. Check environment
env
pip list

# 4. Manual test
python -c "import fastapi; print(fastapi.__version__)"
```

### Full Restart
```bash
docker-compose down -v    # Clean slate
docker-compose up --build # Full rebuild
```

---

## USEFUL ALIASES (Add to .bashrc or .zshrc)

```bash
alias dcu='docker-compose up'
alias dcd='docker-compose down'
alias dcps='docker-compose ps'
alias dcl='docker-compose logs -f'
alias dcb='docker-compose build --no-cache'
alias dce='docker-compose exec'
alias dcr='docker-compose restart'
```

Then use:
```bash
dcu              # Start
dcps             # Status
dcl kms          # Logs for KMS
dcb wallet_service  # Rebuild wallet
dce kms bash     # Enter KMS shell
```

---

##  PERFORMANCE TIPS

### Speed Up Builds
```bash
# Rebuild only changed service
docker-compose build --no-cache wallet_service

# Then start just that service
docker-compose up wallet_service
```

### Reduce Startup Time
```bash
# Services start in dependency order automatically
# Independent services (redis, postgres) start in parallel
```

### Parallel Testing
```bash
# Run multiple tests in parallel
docker-compose exec vc_verification pytest tests/ -n auto
```

---

##  USEFUL ONE-LINERS

```bash
# Check if all services are healthy
docker-compose ps | grep -c "Up (healthy)"
# Expected: 11

# Get all container IPs
docker-compose exec -T redis env | grep HOSTNAME
for svc in $(docker-compose ps --services); do 
  echo "$svc: $(docker-compose exec -T $svc hostname -I)"
done

# List all exposed ports
docker-compose ps | awk '{print $6}'

# View all environment variables for a service
docker-compose exec wallet_service env | sort

# Count running containers
docker ps -q | wc -l
```

---

##  BOOKMARKS

Quick links to full guides:
- **[DOCKER_COMPOSE_QUICKSTART.md](./DOCKER_COMPOSE_QUICKSTART.md)** — Step-by-step guide
- **[DOCKER_COMPOSE_GUIDE.md](./DOCKER_COMPOSE_GUIDE.md)** — Comprehensive reference
- **[DOCKER_ARCHITECTURE_DIAGRAM.md](./DOCKER_ARCHITECTURE_DIAGRAM.md)** — Visual diagrams

---

##  COMMON WORKFLOWS

### I want to...

**Start all services**
```bash
docker-compose up --build
```

**Check if everything is running**
```bash
docker-compose ps
curl http://localhost:8001/health
```

**View logs for one service**
```bash
docker-compose logs -f wallet_service
```

**Run integration tests**
```bash
docker-compose exec vc_verification pytest tests/test_integration_*.py -v
```

**Debug a service**
```bash
docker-compose logs -f wallet_service
docker-compose exec wallet_service bash
```

**Stop all services**
```bash
docker-compose stop
```

**Clean everything and start fresh**
```bash
docker-compose down -v
docker-compose up --build
```

**Update one service's code and restart**
```bash
# Edit code
# Save
docker-compose build --no-cache wallet_service
docker-compose restart wallet_service
```

**Check resource usage**
```bash
docker stats
```

---

##  Reference Table

| What | Command |
|------|---------|
| Start | `docker-compose up` |
| Stop | `docker-compose stop` |
| Remove | `docker-compose down` |
| Status | `docker-compose ps` |
| Logs | `docker-compose logs -f` |
| Rebuild | `docker-compose build --no-cache` |
| Test Health | `curl http://localhost:8001/health` |
| Shell | `docker-compose exec <svc> bash` |
| Tests | `docker-compose exec vc_verification pytest` |
| Monitor | `docker stats` |
| Clean | `docker-compose down -v` |

---

**Pro Tip:** Copy these commands and bookmark this file for quick reference during development!
