FROM mirror.gcr.io/library/python:3.12-alpine
COPY services/analysis/src /app/services/analysis/src
COPY schemas /app/schemas
COPY services/worker/cpag_worker/container_entry.py /app/entry.py
ENV PYTHONPATH=/app/services/analysis/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65532:65532
ENTRYPOINT ["python", "/app/entry.py"]
