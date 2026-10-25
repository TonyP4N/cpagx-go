FROM mirror.gcr.io/library/python:3.12-alpine
WORKDIR /app
COPY services/worker/cpag_worker /app/cpag_worker
COPY scripts/m4/linux-isolation /app/isolation
ENV PYTHONPATH=/app PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65532:65532
ENTRYPOINT ["python", "/app/isolation/init.py"]
CMD ["python", "-m", "cpag_worker.worker", "--enable-m4-worker", "--once"]
