@echo off
REM Docker Compose Quick Start for Windows
REM Orchestrates all 10 services

setlocal enabledelayedexpansion

cls
echo.
echo ====================================================================
echo  Zero-Trust Agentic AI Layer 1
echo  Docker Compose Orchestration - All 10 Services
echo ====================================================================
echo.

REM Check Docker
echo [1/4] Checking Docker installation...
docker --version >nul 2>&1
if errorlevel 1 (
    echo   ERROR: Docker not found. Please install Docker Desktop.
    pause
    exit /b 1
)
echo   ✓ Docker found

REM Check Docker Compose
echo [2/4] Checking Docker Compose...
docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo   ERROR: Docker Compose not found.
    pause
    exit /b 1
)
echo   ✓ Docker Compose found

REM Check docker-compose.yml
echo [3/4] Checking docker-compose.yml...
if not exist docker-compose.yml (
    echo   ERROR: docker-compose.yml not found in current directory
    echo   Run this script from: c:\Users\Disha\Zero_trust-agentic-AI-Layer1
    pause
    exit /b 1
)
echo   ✓ docker-compose.yml found

REM Start services
echo [4/4] Starting all services...
echo.
echo ====================================================================
echo  Service Startup
echo ====================================================================
echo.

docker-compose up --build

pause
