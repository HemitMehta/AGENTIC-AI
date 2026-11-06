FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . ./agent_services
EXPOSE 8017 8018
CMD ["uvicorn", "agent_services.orchestrator:app", "--host", "0.0.0.0", "--port", "8017"]
