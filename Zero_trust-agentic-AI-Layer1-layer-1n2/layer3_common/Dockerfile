FROM python:3.11-slim
WORKDIR /app
COPY layer3_common/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY layer3_common ./layer3_common
COPY policy_administration_service ./policy_administration_service
COPY policy_information_service ./policy_information_service
COPY policy_decision_service ./policy_decision_service
COPY access_control_service ./access_control_service
COPY protected_sales_service ./protected_sales_service
CMD ["python", "-m", "layer3_common.serve"]
