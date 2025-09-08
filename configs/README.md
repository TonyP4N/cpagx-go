# CPAG Generator Configuration

## Configuration Strategy

This project uses an **environment variable first** configuration strategy:

1. **Environment Variables** - Highest priority, used for runtime configuration
2. **config.json** - Default configuration containing settings that don't change often
3. **Code Defaults** - Lowest priority, serves as final fallback

## Configuration Priority

```
Environment Variables > config.json > Code Defaults
```

## Environment Variable Configuration

### Server Configuration
- `SERVER_PORT` - Server port (default: 8080)
- `SERVER_HOST` - Server host (default: 0.0.0.0)

### Python Service Configuration
- `PYTHON_SERVICE_URL` - Python service URL (default: http://python-cpag-generator:8000)
- `PYTHON_V1_SERVICE_URL` - Python v1 service URL (default: http://python-cpag-generator:8000)
- `PYTHON_V2_SERVICE_URL` - Python v2 service URL (default: http://python-cpag-generator:8002)
- `CPAG_VERSION` - CPAG service version to use (v1 or v2, default: v2)

### Message Queue Configuration
- `RABBITMQ_URL` - RabbitMQ connection URL (default: amqp://guest:guest@rabbitmq:5672/)
- `RABBITMQ_HOST` - RabbitMQ host (default: rabbitmq)
- `RABBITMQ_PORT` - RabbitMQ port (default: 5672)
- `RABBITMQ_USER` - RabbitMQ username (default: guest)
- `RABBITMQ_PASSWORD` - RabbitMQ password (default: guest)

### InfluxDB Configuration (Monitoring)
- `INFLUXDB_URL` - InfluxDB URL (default: http://influxdb:8086)
- `INFLUXDB_TOKEN` - InfluxDB access token
- `INFLUXDB_ORG` - InfluxDB organization name
- `INFLUXDB_BUCKET` - InfluxDB bucket name

### Redis Configuration
- `REDIS_HOST` - Redis host (default: redis)
- `REDIS_PORT` - Redis port (default: 6379)
- `REDIS_DB` - Redis database (default: 0)
- `REDIS_PASSWORD` - Redis password (default: password123)
- `REDIS_USERNAME` - Redis username (default: "") Uses default user, can be empty

### Neo4j Configuration
- `NEO4J_URI` - Neo4j connection URI (default: bolt://neo4j:7687)
- `NEO4J_USER` - Neo4j username (default: neo4j)
- `NEO4J_PASSWORD` - Neo4j password (default: password123)
- `NEO4J_DATABASE` - Neo4j database (default: neo4j)
- `NEO4J_ENABLED` - Enable Neo4j (default: true)

### Other Configuration
- `DATABASE_TYPE` - Database type (default: redis)

## config.json Configuration

`config.json` contains only configuration items that don't change frequently:

- Timeout settings
- Retry counts
- Cache TTL
- Other static configurations

## Usage

### 1. Development Environment
Copy `env.example` to `.env` and modify required values:

```bash
cp deployments/env.example deployments/.env
# Edit .env file
```

### 2. Production Environment
Set environment variables:

```bash
# Database Configuration
export NEO4J_PASSWORD=your-secure-password
export REDIS_PASSWORD=your-redis-password

# Python Service Configuration
export PYTHON_V1_SERVICE_URL=http://python-cpag-v1:8000
export PYTHON_V2_SERVICE_URL=http://python-cpag-v2:8002
export CPAG_VERSION=v2

# Message Queue Configuration
export RABBITMQ_URL=amqp://admin:your-rabbitmq-password@rabbitmq:5672/
export RABBITMQ_PASSWORD=your-rabbitmq-password

# Monitoring Configuration
export INFLUXDB_URL=http://influxdb:8086
export INFLUXDB_TOKEN=your-influxdb-token
export INFLUXDB_ORG=your-org
export INFLUXDB_BUCKET=cpagx-metrics
```

### 3. Docker Environment
Use environment variables in `docker-compose.yml`:

```yaml
environment:
  - NEO4J_PASSWORD=${NEO4J_PASSWORD}
  - REDIS_PASSWORD=${REDIS_PASSWORD}
  - RABBITMQ_URL=${RABBITMQ_URL}
  - PYTHON_V1_SERVICE_URL=http://python-cpag-generator:8000
  - PYTHON_V2_SERVICE_URL=http://python-cpag-generator:8002
  - CPAG_VERSION=v2
  - INFLUXDB_URL=${INFLUXDB_URL}
  - INFLUXDB_TOKEN=${INFLUXDB_TOKEN}
```

## Configuration Validation

When starting the application, loaded configuration information will be displayed. You can check the actual configuration values used through logs.

## Version Selection

The system supports multiple versions of the Python CPAG generator service:

- **v1 (port 8000)**: Basic version with fundamental PCAP and CSV processing capabilities
- **v2 (port 8002)**: Enhanced version with ENIP/CIP protocol support and optimized Neo4j integration

Version selection can be controlled through:
- `CPAG_VERSION` environment variable (v1, v2)
- Individual service URLs via `PYTHON_V1_SERVICE_URL` and `PYTHON_V2_SERVICE_URL`

## Important Notes

1. **Sensitive Information**: Passwords, keys, and other sensitive information should be set through environment variables
2. **Environment Isolation**: Use different environment variable values for different environments
3. **Configuration Consistency**: Ensure all services maintain consistent configuration
4. **Default Values**: Consider backward compatibility when modifying default values
5. **Service Dependencies**: Make sure RabbitMQ, Redis, Neo4j, and InfluxDB are properly configured before starting the application 