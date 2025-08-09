# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o cpagx-go ./cmd/cpagx

FROM gcr.io/distroless/base-debian11
WORKDIR /
COPY --from=builder /app/cpagx-go /cpagx-go
ENTRYPOINT ["/cpagx-go"]