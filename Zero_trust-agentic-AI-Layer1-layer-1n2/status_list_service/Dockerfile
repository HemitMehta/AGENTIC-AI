# Dockerfile for SS6: Status List Service

FROM python:3.11-slim

WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Run migrations on startup (optional for Docker)
# RUN python -m alembic upgrade head

# Start service
CMD ["sh", "-c", "python -m uvicorn main:app --host 0.0.0.0 --port ${STATUS_LIST_SERVICE_PORT:-8006}"]
