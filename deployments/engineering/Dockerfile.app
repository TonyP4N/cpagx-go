FROM mirror.gcr.io/library/docker@sha256:4fa0ee1f3a7e4354c4ea34558b6d4ee32859baf4973d4c8ccc8e7fe3dd730c04 AS dockercli
FROM mirror.gcr.io/library/python@sha256:848ba4413eb897e225159b8fc1b02094576cbae4aa73fc13142608ae2c8c0e32
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY services /app/services
COPY schemas /app/schemas
COPY migrations /app/migrations
COPY scripts /app/scripts
COPY engineering /app/engineering
COPY samples /app/samples
COPY bin /app/bin
COPY release.json /app/release.json
ENV PYTHONPATH=/app/services/worker:/app/services/analysis/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
