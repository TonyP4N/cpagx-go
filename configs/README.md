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
export NEO4J_PASSWORD=your-secure-password
export REDIS_PASSWORD=your-redis-password
# ... other environment variables
```

### 3. Docker Environment
Use environment variables in `docker-compose.yml`:

```yaml
environment:
  - NEO4J_PASSWORD=${NEO4J_PASSWORD}
  - REDIS_PASSWORD=${REDIS_PASSWORD}
```

## Configuration Validation

When starting the application, loaded configuration information will be displayed. You can check the actual configuration values used through logs.

## Important Notes

1. **Sensitive Information**: Passwords, keys, and other sensitive information should be set through environment variables
2. **Environment Isolation**: Use different environment variable values for different environments
3. **Configuration Consistency**: Ensure all services maintain consistent configuration
4. **Default Values**: Consider backward compatibility when modifying default values 