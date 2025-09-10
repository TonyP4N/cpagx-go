# CPAGx-Go

[![Go Report Card](https://goreportcard.com/badge/github.com/TonyP4N/cpagx-go)](https://goreportcard.com/report/github.com/TonyP4N/cpagx-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

CPAGx-Go is a microservices platform for analyzing cyber-physical attack graphs from network traffic. Built for security researchers and SOC analysts to visualize attack paths in industrial control systems.

## Features

- **Real-time PCAP processing** with ENIP/CIP protocol support
- **Interactive graph visualization** powered by Neo4j
- **Scalable microservices architecture** with async processing
- **Multi-version API support** for different analysis capabilities
- **Production-ready infrastructure** with monitoring and observability

## Architecture

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│   Web UI    │    │  Go API      │    │   Python    │
│  (Next.js)  │◄──►│  Gateway     │◄──►│   Services  │
│   :3000     │    │   :8080      │    │ v1:8000     │
└─────────────┘    └──────────────┘    │ v2:8002     │
                          │            │   +Celery   │
                          │            └─────────────┘
        ┌─────────────────┼─────────────────┐
        │                 │                 │
   ┌────▼────┐      ┌─────▼─────┐    ┌─────▼─────┐
   │  Neo4j  │      │ RabbitMQ  │    │   Redis   │
   │  :7687  │      │  :5672    │    │   :6379   │
   └─────────┘      └───────────┘    └───────────┘
```

## Quick Start

### Using Docker Compose (Recommended)

```bash
git clone https://github.com/TonyP4N/cpagx-go.git
cd cpagx-go
cp deployments/env.example deployments/.env
# Edit .env with your configuration
make docker-compose-up
```

Access the application:
- Web UI: http://localhost:3000
- API: http://localhost:8080
- Neo4j Browser: http://localhost:7476

### Local Development

**Prerequisites:**
- Go 1.24+
- Python 3.9+
- Node.js 18+
- Neo4j 5.15+

```bash
# Install dependencies
make dev-setup

# Build and run
make build
make run

## Usage

### Upload and Process CSV, PCAP, PCAPNG Files

1. Open the Web UI at http://localhost:3000
2. Select API version (v1 for basic processing, v2 for enhanced analysis)
3. Upload PCAP/PCAPNG files via drag-and-drop
4. View processing results and generated attack graphs

### API Endpoints

```bash
# Upload file for processing
POST /api/v2/cpag/upload

# Check processing status
GET /api/v2/cpag/status/{task_id}

# Retrieve attack graph
GET /api/graph/data/{task_id}

# Health check
GET /api/health
```

### CLI Usage

```bash
# Process file directly
./bin/cpagx analyze input.pcap

# Start server with custom config
./bin/cpagx server -c configs/config-prod.json

# Show configuration
./bin/cpagx config show
```

## Configuration

Configuration is managed through JSON files in the `configs/` directory:

- `config.json` - Default configuration
- `config-dev.json` - Development settings  
- `config-prod.json` - Production settings

Key configuration sections:
- **server** - API gateway settings
- **neo4j** - Graph database connection
- **python** - Processing service URLs
- **versions** - API version management

## Monitoring

The platform includes comprehensive monitoring:

- **Prometheus** metrics at :9090
- **Grafana** dashboards at :3001
- **Flower** Celery monitoring at :5555
- **RabbitMQ** management at :15672

## Development

### Project Structure

```
├── api/                    # HTTP handlers and routing
├── cmd/cpagx/             # CLI application entry point
├── configs/               # Configuration files
├── internal/              # Core services and utilities
├── services/              # Python processing services
├── webui/                 # Next.js frontend
├── deployments/           # Docker and infrastructure
└── tests/                 # Evaluation and testing
```

### Running Services Individually

```bash
# Go API Gateway
make build && ./bin/cpagx server

# Python Services - Start All Versions
cd services/python-cpag-generator
./start_all.sh

# Or start individual Python service versions:
# V1 Service (port 8000)
cd services/python-cpag-generator
export CPAG_VERSION=v1 && export PORT=8000 && python main.py

# V2 Service (port 8002)
cd services/python-cpag-generator
export CPAG_VERSION=v2 && export PORT=8002 && python main.py

# Celery Worker
cd services/python-cpag-generator
celery -A entrypoints.app:celery worker --loglevel=info

# Celery Beat (task scheduler)
cd services/python-cpag-generator
celery -A entrypoints.app:celery beat --loglevel=info

# Web UI
cd webui
npm run dev
```

## License

MIT License - see [LICENSE](LICENSE) for details.