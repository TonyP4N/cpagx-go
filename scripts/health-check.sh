#!/bin/bash

# 服务健康检查脚本
# 用于检查所有内部服务的连接和存活状态

set -e

echo "🔍 开始服务健康检查..."

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查函数
check_service() {
    local service_name=$1
    local check_command=$2
    local timeout=${3:-10}
    
    echo -n "检查 $service_name... "
    
    if timeout $timeout bash -c "$check_command" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ 正常${NC}"
        return 0
    else
        echo -e "${RED}❌ 失败${NC}"
        return 1
    fi
}

# 检查Redis
check_redis() {
    check_service "Redis" "docker run --rm --network host redis:7-alpine redis-cli -h localhost -p 6379 -a password123 ping"
}

# 检查Neo4j
check_neo4j() {
    check_service "Neo4j" "docker run --rm --network host neo4j:5-community cypher-shell -u neo4j -p password123 -a localhost:7689 'RETURN 1'"
}

# 检查RabbitMQ
check_rabbitmq() {
    check_service "RabbitMQ" "curl -s -u guest:guest http://localhost:15672/api/overview >/dev/null"
}

# 检查InfluxDB
check_influxdb() {
    check_service "InfluxDB" "docker run --rm --network host influxdb:2.7-alpine influx ping --host http://localhost:8086"
}

# 检查Go应用配置
check_go_config() {
    echo -n "检查Go应用配置... "
    
    # 设置环境变量
    export REDIS_HOST=localhost
    export REDIS_PORT=6379
    export REDIS_PASSWORD=password123
    export NEO4J_URI=bolt://localhost:7687
    export NEO4J_USER=neo4j
    export NEO4J_PASSWORD=password123
    export RABBITMQ_URL=amqp://guest:guest@localhost:5672/
    export INFLUXDB_URL=http://localhost:8086
    export INFLUXDB_TOKEN=cpagx-admin-token-2025
    
    if go run cmd/cpagx/main.go --help >/dev/null 2>&1; then
        echo -e "${GREEN}✅ 正常${NC}"
        return 0
    else
        echo -e "${RED}❌ 失败${NC}"
        return 1
    fi
}

# 主检查流程
main() {
    local failed_checks=0
    
    echo "等待服务启动..."
    sleep 5
    
    # 检查各个服务
    check_redis || ((failed_checks++))
    check_neo4j || ((failed_checks++))
    check_rabbitmq || ((failed_checks++))
    check_influxdb || ((failed_checks++))
    check_go_config || ((failed_checks++))
    
    echo ""
    if [ $failed_checks -eq 0 ]; then
        echo -e "${GREEN}🎉 所有服务检查通过！${NC}"
        exit 0
    else
        echo -e "${RED}❌ $failed_checks 个服务检查失败${NC}"
        exit 1
    fi
}

# 如果直接运行此脚本
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
