FROM mirror.gcr.io/library/golang:1.26.5-alpine AS go-build
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
COPY internal ./internal
WORKDIR /src/internal/jobs/integration
RUN go mod download && go build -mod=readonly -trimpath -o /out/cpagx-v3 ./cmd/cpagx-v3 && go build -mod=readonly -trimpath -o /out/cpag-migrate ./cmd/cpag-migrate

FROM mirror.gcr.io/library/node:22.14.0-alpine3.21 AS ui-build
WORKDIR /webui
COPY webui/package.json webui/package-lock.json ./
RUN npm ci
COPY webui/ ./
RUN npm run build:static

FROM mirror.gcr.io/library/python@sha256:848ba4413eb897e225159b8fc1b02094576cbae4aa73fc13142608ae2c8c0e32 AS runtime
RUN apk add --no-cache libseccomp=2.6.1-r0
COPY services/worker/requirements-resident.txt /opt/cpag/requirements-resident.txt
RUN pip install --no-cache-dir -r /opt/cpag/requirements-resident.txt
COPY --from=go-build /out/ /opt/cpag/bin/
COPY --from=ui-build /webui/out/ /opt/cpag/webui/out/
COPY services/worker/cpag_worker/ /opt/cpag/services/worker/cpag_worker/
COPY services/analysis/src/ /opt/cpag/services/analysis/src/
COPY schemas/ /opt/cpag/schemas/
COPY internal/jobs/migrations/ /opt/cpag/migrations/
COPY deployments/v3/ /opt/cpag/deploy/
COPY deployments/resident/private_relay.py /opt/cpag/private_relay.py
COPY deployments/r21/k3s/source-verifier.py /opt/cpag/source-verifier.py
COPY deployments/resident/verifier_identity.py /opt/cpag/verifier_identity.py
RUN python3 /opt/cpag/verifier_identity.py --root /opt/cpag > /opt/cpag/verifier-source.identity
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/cpag/services/worker:/opt/cpag/services/analysis/src
WORKDIR /opt/cpag
ENTRYPOINT ["/opt/cpag/bin/cpagx-v3"]
CMD ["--config", "/etc/cpag/app.json"]

FROM mirror.gcr.io/library/nginx@sha256:0e52bd054126cdc040b1276c0af347aeb02a41b9cfe305d6094767ac30e97949 AS relay
COPY deployments/v3/nginx.conf /etc/nginx/nginx.conf
USER 101:101
ENTRYPOINT ["nginx", "-g", "daemon off;"]
