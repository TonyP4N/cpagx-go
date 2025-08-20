# ================================================================================
# CPAGX-Go Makefile - Cyber-Physical Attack Graph Analysis Platform
# ================================================================================

# Project configuration
APP_NAME=cpagx-go
BINARY_NAME=cpagx
BINARY_PATH=../bin/$(BINARY_NAME)
PROJECT_ROOT=..
GO_MODULE=github.com/TonyP4N/cpagx-go

# Docker image tags
GO_IMAGE=$(APP_NAME):latest
PYTHON_IMAGE=cpagx-python-generator:latest
WEBUI_IMAGE=cpagx-webui:latest

# Build information
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION=$(shell git describe --tags --abbrev=0 2>/dev/null || echo "dev")

# Go build flags
LDFLAGS=-ldflags "-X '$(GO_MODULE)/internal/version.Version=$(VERSION)' \
                  -X '$(GO_MODULE)/internal/version.BuildTime=$(BUILD_TIME)' \
                  -X '$(GO_MODULE)/internal/version.GitCommit=$(GIT_COMMIT)'"

# Docker Compose file paths
COMPOSE_FILE=./docker-compose.yml
ENV_FILE=./env.example

# ================================================================================
# Build Commands
# ================================================================================

# Build Go application
build:
	@echo "Building $(APP_NAME)..."
	cd $(PROJECT_ROOT) && go build $(LDFLAGS) -o $(BINARY_PATH) ./cmd/cpagx
	@echo "Build complete: $(BINARY_PATH)"

# Build production version
build-prod:
	@echo "Building production version..."
	cd $(PROJECT_ROOT) && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo $(LDFLAGS) -o $(BINARY_PATH) ./cmd/cpagx
	@echo "Production build complete"

# Cross-compile for multiple platforms
build-cross:
	@echo "Cross-compiling for multiple platforms..."
	cd $(PROJECT_ROOT) && \
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_PATH)-linux-amd64 ./cmd/cpagx && \
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_PATH)-windows-amd64.exe ./cmd/cpagx && \
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_PATH)-darwin-amd64 ./cmd/cpagx
	@echo "Cross-compilation complete"

# ================================================================================
# Development Commands
# ================================================================================

# Run Go application with development config
run:
	@echo "Starting $(APP_NAME) with development config..."
	cd $(PROJECT_ROOT) && go run ./cmd/cpagx server -c configs/config-dev.json

# Run with production config
run-prod:
	@echo "Starting $(APP_NAME) with production config..."
	cd $(PROJECT_ROOT) && go run ./cmd/cpagx server -c configs/config-prod.json

# Run unit tests
test:
	@echo "Running tests..."
	cd $(PROJECT_ROOT) && go test -v ./...

# Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	cd $(PROJECT_ROOT) && go test -v -coverprofile=coverage.out ./...
	cd $(PROJECT_ROOT) && go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: $(PROJECT_ROOT)/coverage.html"

# Run benchmark tests
benchmark:
	@echo "Running benchmarks..."
	cd $(PROJECT_ROOT) && go test -bench=. -benchmem ./...

# Run code linter
lint:
	@echo "Running linter..."
	cd $(PROJECT_ROOT) && golangci-lint run

# Format source code
fmt:
	@echo "Formatting code..."
	cd $(PROJECT_ROOT) && go fmt ./...

# Update Go dependencies
deps-update:
	@echo "Updating dependencies..."
	cd $(PROJECT_ROOT) && go mod tidy && go mod download

# ================================================================================
# Docker Commands
# ================================================================================

# Build all Docker images
docker-build-all:
	@echo "Building all Docker images..."
	docker build -f Dockerfile -t $(GO_IMAGE) $(PROJECT_ROOT)
	docker build -f $(PROJECT_ROOT)/services/python-cpag-generator/Dockerfile -t $(PYTHON_IMAGE) $(PROJECT_ROOT)/services/python-cpag-generator
	docker build -f $(PROJECT_ROOT)/webui/Dockerfile -t $(WEBUI_IMAGE) $(PROJECT_ROOT)/webui
	@echo "All Docker images built successfully"

# Build individual service images
docker-build-go:
	@echo "Building Go service image..."
	docker build -f Dockerfile -t $(GO_IMAGE) $(PROJECT_ROOT)

docker-build-python:
	@echo "Building Python service image..."
	docker build -f $(PROJECT_ROOT)/services/python-cpag-generator/Dockerfile -t $(PYTHON_IMAGE) $(PROJECT_ROOT)/services/python-cpag-generator

docker-build-webui:
	@echo "Building WebUI image..."
	docker build -f $(PROJECT_ROOT)/webui/Dockerfile -t $(WEBUI_IMAGE) $(PROJECT_ROOT)/webui

# ================================================================================
# Docker Compose Commands
# ================================================================================

# Start all services (detached)
up:
	@echo "Starting all services..."
	docker-compose -f $(COMPOSE_FILE) up -d
	@echo "All services started"

# Start services in foreground
up-fg:
	@echo "Starting all services in foreground..."
	docker-compose -f $(COMPOSE_FILE) up

# Stop all services
down:
	@echo "Stopping all services..."
	docker-compose -f $(COMPOSE_FILE) down
	@echo "All services stopped"

# Stop services and clean volumes
down-clean:
	@echo "Stopping services and cleaning up..."
	docker-compose -f $(COMPOSE_FILE) down -v --remove-orphans
	@echo "Services stopped and cleaned"

# Build services with Docker Compose
docker-compose-build:
	@echo "Building services with Docker Compose..."
	docker-compose -f $(COMPOSE_FILE) build --parallel

# Restart all services
restart:
	@echo "Restarting all services..."
	docker-compose -f $(COMPOSE_FILE) restart

# View all service logs
logs:
	docker-compose -f $(COMPOSE_FILE) logs -f

# View specific service logs
logs-go:
	docker-compose -f $(COMPOSE_FILE) logs -f go-app

logs-python:
	docker-compose -f $(COMPOSE_FILE) logs -f python-cpag-generator

logs-webui:
	docker-compose -f $(COMPOSE_FILE) logs -f webui

logs-celery:
	docker-compose -f $(COMPOSE_FILE) logs -f celery-worker

logs-neo4j:
	docker-compose -f $(COMPOSE_FILE) logs -f neo4j

logs-redis:
	docker-compose -f $(COMPOSE_FILE) logs -f redis

# Check service status
status:
	@echo "Service status:"
	docker-compose -f $(COMPOSE_FILE) ps

# Health check for all services
health:
	@echo "Checking service health..."
	@curl -f http://localhost:8080/api/health 2>/dev/null && echo "Go API: OK" || echo "Go API: FAILED"
	@curl -f http://localhost:8000/health 2>/dev/null && echo "Python v1: OK" || echo "Python v1: FAILED"
	@curl -f http://localhost:8002/health 2>/dev/null && echo "Python v2: OK" || echo "Python v2: FAILED"
	@curl -f http://localhost:3000 2>/dev/null && echo "WebUI: OK" || echo "WebUI: FAILED"

# ================================================================================
# Environment Management
# ================================================================================

# Setup development environment
dev-setup:
	@echo "Setting up development environment..."
	@echo "Installing Go dependencies..."
	cd $(PROJECT_ROOT) && go mod tidy
	@echo "Installing Python dependencies..."
	cd $(PROJECT_ROOT)/services/python-cpag-generator && pip install -r requirements.txt
	@echo "Installing Node.js dependencies..."
	cd $(PROJECT_ROOT)/webui && npm install
	@echo "Development environment ready"

# Check development prerequisites
dev-check:
	@echo "Checking development environment..."
	@go version || echo "ERROR: Go not installed"
	@python --version || echo "ERROR: Python not installed"
	@node --version || echo "ERROR: Node.js not installed"
	@docker --version || echo "ERROR: Docker not installed"
	@docker-compose --version || echo "ERROR: Docker Compose not installed"

# Start development services locally
dev-start:
	@echo "Starting development services..."
	cd $(PROJECT_ROOT)/services/python-cpag-generator && python server.py &
	cd $(PROJECT_ROOT)/webui && npm run dev &
	sleep 2
	cd $(PROJECT_ROOT) && go run ./cmd/cpagx server -c configs/config-dev.json

# Create environment file from template
init-env:
	@if [ ! -f .env ]; then \
		cp $(ENV_FILE) .env; \
		echo "Created .env from template. Please edit with your settings."; \
	else \
		echo ".env file already exists"; \
	fi

# ================================================================================
# Data Management
# ================================================================================

# Backup application data
backup:
	@echo "Creating backup..."
	mkdir -p $(PROJECT_ROOT)/backups/$(shell date +%Y%m%d_%H%M%S)
	docker-compose -f $(COMPOSE_FILE) exec neo4j neo4j-admin dump --to=/backups/neo4j-backup.dump 2>/dev/null || echo "Neo4j backup failed"
	docker cp $$(docker-compose -f $(COMPOSE_FILE) ps -q redis):/data $(PROJECT_ROOT)/backups/$(shell date +%Y%m%d_%H%M%S)/redis-data 2>/dev/null || echo "Redis backup failed"

# Clean data volumes
clean-data:
	@echo "Cleaning data volumes..."
	docker-compose -f $(COMPOSE_FILE) down -v
	docker volume prune -f

# ================================================================================
# Monitoring and Debug
# ================================================================================

# Show resource usage statistics
stats:
	@echo "Resource usage statistics:"
	docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

# Enter container shells
shell-go:
	docker-compose -f $(COMPOSE_FILE) exec go-app sh

shell-python:
	docker-compose -f $(COMPOSE_FILE) exec python-cpag-generator bash

shell-neo4j:
	docker-compose -f $(COMPOSE_FILE) exec neo4j cypher-shell -u neo4j

shell-redis:
	docker-compose -f $(COMPOSE_FILE) exec redis redis-cli

# ================================================================================
# Cleanup Commands
# ================================================================================

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(PROJECT_ROOT)/bin/$(BINARY_NAME)*
	rm -f $(PROJECT_ROOT)/coverage.out $(PROJECT_ROOT)/coverage.html
	cd $(PROJECT_ROOT) && go clean -cache -modcache -testcache

# Clean Docker images
clean-images:
	@echo "Cleaning Docker images..."
	docker rmi $(GO_IMAGE) $(PYTHON_IMAGE) $(WEBUI_IMAGE) 2>/dev/null || true
	docker image prune -f

# Full cleanup
clean-all: clean clean-images clean-data
	@echo "Full cleanup complete"

# ================================================================================
# Deployment Commands
# ================================================================================

# Deploy to production
deploy-prod:
	@echo "Deploying to production..."
	docker-compose -f $(COMPOSE_FILE) -f docker-compose.prod.yml up -d
	@echo "Production deployment complete"

# Check application configuration
config-check:
	@echo "Checking configuration..."
	cd $(PROJECT_ROOT) && ./bin/$(BINARY_NAME) config show

# Validate configuration files
config-validate:
	@echo "Validating configuration files..."
	cd $(PROJECT_ROOT) && ./bin/$(BINARY_NAME) config validate

# ================================================================================
# Utility Commands
# ================================================================================

# Show version information
version:
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Git Commit: $(GIT_COMMIT)"

# Install development tools
install-tools:
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/air-verse/air@latest

# Generate API documentation
docs:
	@echo "Generating API documentation..."
	cd $(PROJECT_ROOT) && swag init -g cmd/cpagx/main.go

# Run security scan
security-scan:
	@echo "Running security scan..."
	cd $(PROJECT_ROOT) && gosec ./...

# ================================================================================
# Help
# ================================================================================

help:
	@echo "CPAGX-Go Makefile Commands"
	@echo "=========================="
	@echo ""
	@echo "Build Commands:"
	@echo "  build               - Build Go application"
	@echo "  build-prod          - Build production version" 
	@echo "  build-cross         - Cross-compile for multiple platforms"
	@echo ""
	@echo "Development Commands:"
	@echo "  run                 - Run Go application with dev config"
	@echo "  run-prod            - Run Go application with prod config"
	@echo "  test                - Run unit tests"
	@echo "  test-coverage       - Run tests with coverage report"
	@echo "  benchmark           - Run benchmark tests"
	@echo "  lint                - Run code linter"
	@echo "  fmt                 - Format source code"
	@echo "  deps-update         - Update Go dependencies"
	@echo ""
	@echo "Docker Commands:"
	@echo "  docker-build-all    - Build all Docker images"
	@echo "  docker-build-go     - Build Go service image"
	@echo "  docker-build-python - Build Python service image"
	@echo "  docker-build-webui  - Build WebUI image"
	@echo ""
	@echo "Docker Compose Commands:"
	@echo "  up                  - Start all services (detached)"
	@echo "  up-fg               - Start all services (foreground)"
	@echo "  down                - Stop all services"
	@echo "  down-clean          - Stop services and clean volumes"
	@echo "  restart             - Restart all services"
	@echo "  docker-compose-build- Build services with compose"
	@echo "  logs                - View all service logs"
	@echo "  logs-{service}      - View specific service logs"
	@echo "  status              - Show service status"
	@echo "  health              - Check service health"
	@echo ""
	@echo "Environment Management:"
	@echo "  dev-setup           - Setup development environment"
	@echo "  dev-check           - Check development prerequisites"
	@echo "  dev-start           - Start development services"
	@echo "  init-env            - Create environment file from template"
	@echo ""
	@echo "Data Management:"
	@echo "  backup              - Backup application data"
	@echo "  clean-data          - Clean data volumes"
	@echo ""
	@echo "Monitoring & Debug:"
	@echo "  stats               - Show resource usage"
	@echo "  shell-{service}     - Enter service container shell"
	@echo ""
	@echo "Cleanup Commands:"
	@echo "  clean               - Clean build artifacts"
	@echo "  clean-images        - Clean Docker images"
	@echo "  clean-all           - Full cleanup"
	@echo ""
	@echo "Deployment:"
	@echo "  deploy-prod         - Deploy to production"
	@echo "  config-check        - Check application configuration"
	@echo "  config-validate     - Validate configuration files"
	@echo ""
	@echo "Utility:"
	@echo "  version             - Show version information"
	@echo "  install-tools       - Install development tools"
	@echo "  docs                - Generate API documentation"
	@echo "  security-scan       - Run security scan"
	@echo ""

# ================================================================================
# Phony Targets
# ================================================================================

.PHONY: build build-prod build-cross run run-prod test test-coverage benchmark \
        lint fmt deps-update docker-build-all docker-build-go docker-build-python \
        docker-build-webui up up-fg down down-clean restart docker-compose-build \
        logs logs-go logs-python logs-webui logs-celery logs-neo4j logs-redis \
        status health dev-setup dev-check dev-start init-env backup clean-data \
        stats shell-go shell-python shell-neo4j shell-redis clean clean-images \
        clean-all deploy-prod config-check config-validate version install-tools \
        docs security-scan help