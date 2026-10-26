FROM mirror.gcr.io/library/python:3.11.17-slim
WORKDIR /app
COPY services/analysis/src /app/services/analysis/src
COPY schemas /app/schemas
COPY scripts/benchmarks /app/scripts/benchmarks
COPY profiles/synthetic-demo.json /app/profiles/synthetic-demo.json
COPY tests/fixtures/synthetic/network.normalized.jsonl /app/tests/fixtures/synthetic/network.normalized.jsonl
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65532:65532
ENTRYPOINT ["python", "/app/scripts/benchmarks/synthetic_scaling.py"]
