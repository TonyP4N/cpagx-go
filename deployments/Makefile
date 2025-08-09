APP=cpagx-go
BINARY=./cmd/cpagx/$(APP)

# Docker镜像标签
GO_IMAGE=cpagx-go:latest
PYTHON_IMAGE=cpagx-python-generator:latest
WEBUI_IMAGE=cpagx-webui:latest

# 构建Go应用
build:
	go build -o $(BINARY) ./cmd/cpagx

# 运行Go应用
run:
	go run ./cmd/cpagx/main.go

# 测试
test:
	go test ./...

# 构建所有Docker镜像
docker-build-all:
	docker build -f deployments/Dockerfile -t $(GO_IMAGE) .
	docker build -f services/python-cpag-generator/Dockerfile -t $(PYTHON_IMAGE) services/python-cpag-generator
	docker build -f webui/Dockerfile -t $(WEBUI_IMAGE) webui

# 构建单个服务镜像
docker-build-go:
	docker build -f deployments/Dockerfile -t $(GO_IMAGE) .

docker-build-python:
	docker build -f services/python-cpag-generator/Dockerfile -t $(PYTHON_IMAGE) services/python-cpag-generator

docker-build-webui:
	docker build -f webui/Dockerfile -t $(WEBUI_IMAGE) webui

# 使用Docker Compose
docker-compose-up:
	docker-compose -f deployments/docker-compose.yml up -d

docker-compose-down:
	docker-compose -f deployments/docker-compose.yml down

docker-compose-build:
	docker-compose -f deployments/docker-compose.yml build

docker-compose-logs:
	docker-compose -f deployments/docker-compose.yml logs -f

# 状态检查
status:
	docker-compose -f deployments/docker-compose.yml ps

# 开发环境设置
dev-setup:
	# 安装Go依赖
	go mod tidy
	# 安装Python依赖
	cd services/python-cpag-generator && pip install -r requirements.txt
	# 安装Node.js依赖
	cd webui && npm install

# 清理
clean:
	rm -f $(BINARY)
	docker rmi $(GO_IMAGE) $(PYTHON_IMAGE) $(WEBUI_IMAGE) 2>/dev/null || true

# 帮助信息
help:
	@echo "Available commands:"
	@echo "  build              - Build Go application"
	@echo "  run                - Run Go application"
	@echo "  test               - Run tests"
	@echo "  docker-build-all   - Build all Docker images"
	@echo "  docker-build-go    - Build Go service image"
	@echo "  docker-build-python- Build Python service image"
	@echo "  docker-build-webui - Build WebUI image"
	@echo "  docker-compose-up  - Start all services with Docker Compose"
	@echo "  docker-compose-down- Stop all services"
	@echo "  docker-compose-build- Build all services"
	@echo "  docker-compose-logs- Show service logs"
	@echo "  status             - Show service status"
	@echo "  dev-setup          - Setup development environment"
	@echo "  clean              - Clean build artifacts"
	@echo "  help               - Show this help message"

.PHONY: build run test docker-build-all docker-build-go docker-build-python docker-build-webui \
        docker-compose-up docker-compose-down docker-compose-build docker-compose-logs \
        status dev-setup clean help 