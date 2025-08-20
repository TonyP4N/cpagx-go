#!/bin/bash

# Service health check script
# Used to check connectivity and liveness of all internal services

set -e

echo "Starting service health checks..."

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check function
check_service() {
    local service_name=$1
    local check_command=$2
    local timeout=${3:-10}
    
    echo -n "Checking $service_name... "
    
    if timeout $timeout bash -c "$check_command" >/dev/null 2>&1; then
        echo -e "${GREEN}[OK] Running${NC}"
        return 0
    else
        echo -e "${RED}[FAIL] Failed${NC}"
        return 1
    fi
}

# Check Redis
check_redis() {
    check_service "Redis" "docker run --rm --network host redis:7-alpine redis-cli -h localhost -p 6379 -a password123 ping"
}

# Check Neo4j
check_neo4j() {
    check_service "Neo4j" "docker run --rm --network host neo4j:5-community cypher-shell -u neo4j -p password123 -a localhost:7689 'RETURN 1'"
}

# Check RabbitMQ
check_rabbitmq() {
    check_service "RabbitMQ" "curl -s -u guest:guest http://localhost:15672/api/overview >/dev/null"
}

# Check InfluxDB
check_influxdb() {
    check_service "InfluxDB" "docker run --rm --network host influxdb:2.7-alpine influx ping --host http://localhost:8086"
}

# Check Go application configuration
check_go_config() {
    echo -n "Checking Go application configuration... "
    
    # Set environment variables
    export REDIS_HOST=localhost
    export REDIS_PORT=6379
    export REDIS_PASSWORD=password123
    export NEO4J_URI=bolt://localhost:7687
    export NEO4J_USER=neo4j
    export NEO4J_PASSWORD=password123
    export RABBITMQ_URL=amqp://guest:guest@localhost:5672/
    export INFLUXDB_URL=http://localhost:8086
    export INFLUXDB_TOKEN=cpagx-admin-token-2025
    
    # Ensure Go module mode is used
    export GO111MODULE=on
    unset GOPATH
    
    # Check Go version first
    if ! go version >/dev/null 2>&1; then
        echo -e "${RED}[FAIL] Failed (Go not installed)${NC}"
        return 1
    fi
    
    # Check if go.mod exists
    if [ ! -f "go.mod" ]; then
        echo -e "${RED}[FAIL] Failed (go.mod not found)${NC}"
        return 1
    fi
    
    # Clean module cache and re-download
    go clean -modcache >/dev/null 2>&1
    go mod download >/dev/null 2>&1
    
    # Check if it can compile - use relative path
    if ! go build -o cpagx-test ./cmd/cpagx 2>/dev/null; then
        echo -e "${RED}[FAIL] Failed (compilation error)${NC}"
        echo "Compilation error details:"
        go build ./cmd/cpagx 2>&1 | head -5
        return 1
    fi
    
    # Check if it can run - use relative path
    if go run ./cmd/cpagx --help >/dev/null 2>&1; then
        echo -e "${GREEN}[OK] Running${NC}"
        rm -f cpagx-test cpagx-test.exe
        return 0
    else
        echo -e "${RED}[FAIL] Failed (runtime error)${NC}"
        echo "Runtime error details:"
        go run ./cmd/cpagx --help 2>&1 | head -5
        rm -f cpagx-test cpagx-test.exe
        return 1
    fi
}

# Main check process
main() {
    local failed_checks=0
    
    echo "Waiting for services to start..."
    sleep 5
    
    # Check each service
    check_redis || ((failed_checks++))
    check_neo4j || ((failed_checks++))
    check_rabbitmq || ((failed_checks++))
    check_influxdb || ((failed_checks++))
    check_go_config || ((failed_checks++))
    
    echo ""
    if [ $failed_checks -eq 0 ]; then
        echo -e "${GREEN}All service checks passed!${NC}"
        exit 0
    else
        echo -e "${RED}$failed_checks service checks failed${NC}"
        exit 1
    fi
}

# If running this script directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
