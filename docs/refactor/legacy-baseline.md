# R02 legacy 安全基线（2026-10-24）

本记录是静态入口核查和无依赖隔离复现，不是整套服务启动成功记录，也不是实际 PCAP/PCAPNG 协议能力验收。

## 复现与最小修复

对修改前 HEAD 的方法通过 AST 提取执行，避免导入服务依赖：

- `OptimizedPCAPProcessor.process_pcap_optimized(object(), 'unused', 'pcap')` 在读取文件前报 `AttributeError: 'object' object has no attribute '_parse_pcap_enhanced'`。类中确实没有该方法。
- `_parse_classic_pcap` 输入 24 个零字节加 100 个小端记录头和任意单字节 `x`，返回一条并非从报文字段解码的记录：`src=192.168.1.101, dst=192.168.1.151, sport=12345, dport=44818, service=76, path=Tag_0`。这个故意无效的合成输入仅用于暴露旧逻辑，不能当真实协议样本。

本次删除经典 PCAP 的按包序号构造地址、服务和标签逻辑，替换为 `NotImplementedError`，错误前缀为 `UNSUPPORTED_CLASSIC_PCAP`。补齐优化入口的缺失方法，委托到同一个明确拒绝路径。默认优化模式、显式标准模式以及优化模块不可导入时的标准回退，都不能通过经典 PCAP 占位逻辑生成成功产物。没有添加新的真实报文解析能力。

现有 `_process_pcap_file` 会将异常向上传递；`process_file` 将其转成 `status=failed` 和原始错误文字；Celery `generate_cpag` 已在成功结果处理前检查这个状态并抛错。保留这个公共返回约定。PCAPNG 文件打开、头部解析的异常现在抛出 `PCAPNG_PARSE_FAILED`，避免已捕获异常变成空表成功。既有 CSV、PCAPNG 解码算法及 V1 路径未重写。

## 本次验证

在仓库根目录执行：

```sh
python3 -m unittest discover -s tests/legacy -v
```

5 项测试通过：经典 PCAP 不返回假事件；优化分派同样明确拒绝；公共处理方法保留失败且无图/事件/文件；PCAPNG 缺失文件和空头部错误可见；Celery 失败结果守卫仍存在。测试从实际源码提取方法，注解延迟求值，使用最小替身代替 pandas；公共处理测试注入失败解析器，Celery 守卫为 AST 结构断言。它们不覆盖真实模块导入、FastAPI HTTP、Celery broker、Neo4j 或真实 DataFrame 运算。

当前默认 `python3` 中 `pandas`、`fastapi`、`celery`、`redis`、`neo4j` 均不可发现。没有安装依赖或启动外部服务。

## 实际入口和路由（静态核查）

| 层 | 入口及依赖 | 实际路由/行为 |
| --- | --- | --- |
| Go | 仓库根目录 `go run ./cmd/cpagx server --config configs/config.json`；配置由 `internal/config/config.go` 加载；默认 8080 | `api/routes.go` 注册 `/api/version/list`、`/api/version/switch`、`/api/version/health/:version`；任务 `/api/tasks/list`、`download/:task_id/:filename`、`status/batch`、`queue/status`；`/api/v1/*path` 和 `/api/v2/*path` 代理；兼容 `/api/cpag/generate`、`status/:id`、`result/:id`；图 `/api/graph/tasks`、`data/:task_id`、`health`、`browser`；`/api/health`、`/api/ping` |
| Python | `services/python-cpag-generator` 下 `CPAG_VERSION=v1 python main.py`（8000）或 `CPAG_VERSION=v2 python main.py`（8002）；`PORT` 可覆盖；`start_all.sh` 启动两个 HTTP 进程 | V1 `/health` 和 `/cpag/generate`、`status/batch`、`status/{task_id}`、`result/{task_id}`、`tasks`、`download/{task_id}/{filename}`、`queue/status`；V2 同组路径，另有 `/cpag/result/{task_id}/json` |
| Worker | 同目录 `celery -A infrastructure.celery_app:celery_app worker -Q cpag_generation,celery`；HTTP 启动脚本不启动 worker | `infrastructure/celery_app.py` 使用 `RABBITMQ_URL`（默认 localhost:5672）、`REDIS_URL`（默认 localhost:6379/0），加载 V1/V2 任务；Neo4j、InfluxDB 等按旧服务配置使用，需另行核查运行状态 |
| 前端 | `webui/package.json`：`npm run dev`、`npm run build`、`npm run start`（Next.js） | `webui/next.config.js` 把 `/api/v1`、`/api/v2`、`/api/version`、`/api/tasks`、`/api/cpag`、`/api/graph` 和 `/api/health` 转向 localhost:8080 |

`PYTHON_SERVICE_URL` 的默认值为 `http://python-cpag-generator:8000`，CLI 会导出配置值；但 `api/proxy.go` 的版本代理和健康/任务请求仍直接使用 `http://python-cpag-generator:<版本端口>`。因此不能仅设置该环境变量就宣称本机所有代理已连通。Compose 文件位于 `deployments/docker-compose.yml` 和 `deployments/docker-compose.local.yml`。上表启动命令由源码推导，未作为完整启动流程执行通过。

## 保留问题与后续验收

- V2 Redis 并发限制：检查、`sadd` 非原子，且超限异常被内层 `except Exception` 捕获后继续执行；本次未修改。仅重抛超限也不能解决并发争用和 Redis 故障策略，需要专门的有依赖并发测试和任务状态设计。
- PCAPNG 仍可能在截断块处 `break`，包内解析也会返回 None；未实现完整损坏文件分类、链路类型验证、分段重组或覆盖统计。此次错误传播修复只针对原先已抛出而被吞掉的异常。
- 图中的启发式关系和 `_create_fallback_tree_structure` 仍在，不能将其当作有证据的因果结论；本次范围为阻止经典 PCAP 伪造基础事件，非全面图语义重构。
- V2 静态路由 `/cpag/status/batch` 定义在动态 `/cpag/status/{task_id}` 之后，可能被匹配成 task_id；需 HTTP 路由验收，不在本次处理。
- 尚未运行 Go/Python/前端全栈，未取得真实授权双源样本，未验证任务从提交到结果下载，不报告准确率或工业现场适用性。
