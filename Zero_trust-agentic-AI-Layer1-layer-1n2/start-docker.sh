#!/bin/bash

# Docker Compose Quick Start for macOS/Linux
# Orchestrates all 10 services

clear

echo "===================================================================="
echo "  Zero-Trust Agentic AI Layer 1"
echo "  Docker Compose Orchestration - All 10 Services"
echo "===================================================================="
echo ""

# Check Docker
echo "[1/4] Checking Docker installation..."
if ! command -v docker &> /dev/null; then
    echo "   ERROR: Docker not found. Please install Docker Desktop or Docker Engine."
    exit 1
fi
echo "   ✓ Docker found: $(docker --version)"

# Check Docker Compose
echo "[2/4] Checking Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
    echo "   ERROR: Docker Compose not found."
    exit 1
fi
echo "   ✓ Docker Compose found: $(docker-compose --version)"

# Check docker-compose.yml
echo "[3/4] Checking docker-compose.yml..."
if [ ! -f docker-compose.yml ]; then
    echo "   ERROR: docker-compose.yml not found in current directory"
    echo "   Run from: $(pwd)"
    exit 1
fi
echo "   ✓ docker-compose.yml found"

# Start services
echo "[4/4] Starting all services..."
echo ""
echo "===================================================================="
echo "  Service Startup"
echo "===================================================================="
echo ""

docker-compose up --build
