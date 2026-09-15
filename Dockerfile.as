FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY src /app/src
ENV PYTHONPATH=/app/src
CMD ["python", "-m", "as_engine.cli", "--eve", "/logs/suricata/eve.json", "--rules", "/app/rules/rule_metadata.yaml", "--scoring", "/app/config/scoring-v2.yaml", "--out-jsonl", "/app/runs/improved/scores.jsonl", "--out-csv", "/app/runs/improved/scores.csv", "--out-summary", "/app/runs/improved/summary.json"]
