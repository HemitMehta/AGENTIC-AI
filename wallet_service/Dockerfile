# Dockerfile for SS7: Wallet Service

FROM node:18-alpine AS node_builder

WORKDIR /app

# Install Node dependencies for BBS+ and snarkjs
RUN npm install -g @mattrglobal/bbs-signatures snarkjs

FROM python:3.11-slim

WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Copy built Node modules (if needed; alternatively, install at runtime)
# For now, assume Node is installed separately

# Start service
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8007"]
