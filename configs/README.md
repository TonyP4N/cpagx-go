# CPAG Generator 配置说明

## 配置策略

本项目采用**环境变量优先**的配置策略：

1. **环境变量** - 最高优先级，用于运行时配置
2. **config.json** - 默认配置，包含不常变化的设置
3. **代码默认值** - 最低优先级，作为最后的回退

## 配置优先级

```
环境变量 > config.json > 代码默认值
```

## 环境变量配置

### 服务器配置
- `SERVER_PORT` - 服务器端口 (默认: 8080)
- `SERVER_HOST` - 服务器主机 (默认: 0.0.0.0)

### Python服务配置
- `PYTHON_SERVICE_URL` - Python服务URL (默认: http://python-cpag-generator:8000)

### Redis配置
- `REDIS_HOST` - Redis主机 (默认: redis)
- `REDIS_PORT` - Redis端口 (默认: 6379)
- `REDIS_DB` - Redis数据库 (默认: 0)
- `REDIS_PASSWORD` - Redis密码 (默认: password123)
- `REDIS_USERNAME` - Redis用户名 (默认: "") 默认为default用户，可为空

### Neo4j配置
- `NEO4J_URI` - Neo4j连接URI (默认: bolt://neo4j:7687)
- `NEO4J_USER` - Neo4j用户名 (默认: neo4j)
- `NEO4J_PASSWORD` - Neo4j密码 (默认: password123)
- `NEO4J_DATABASE` - Neo4j数据库 (默认: neo4j)
- `NEO4J_ENABLED` - 是否启用Neo4j (默认: true)

### 其他配置
- `DATABASE_TYPE` - 数据库类型 (默认: redis)

## config.json 配置

`config.json` 只包含不常变化的配置项：

- 超时设置
- 重试次数
- 缓存TTL
- 其他静态配置

## 使用方法

### 1. 开发环境
复制 `env.example` 到 `.env` 并修改需要的值：

```bash
cp deployments/env.example deployments/.env
# 编辑 .env 文件
```

### 2. 生产环境
设置环境变量：

```bash
export NEO4J_PASSWORD=your-secure-password
export REDIS_PASSWORD=your-redis-password
# ... 其他环境变量
```

### 3. Docker环境
在 `docker-compose.yml` 中使用环境变量：

```yaml
environment:
  - NEO4J_PASSWORD=${NEO4J_PASSWORD}
  - REDIS_PASSWORD=${REDIS_PASSWORD}
```

## 配置验证

启动应用时会显示加载的配置信息，可以通过日志查看实际使用的配置值。

## 注意事项

1. **敏感信息**：密码、密钥等敏感信息应通过环境变量设置
2. **环境隔离**：不同环境使用不同的环境变量值
3. **配置一致性**：确保所有服务的配置保持一致
4. **默认值**：修改默认值时要考虑向后兼容性 