# Round 9：真实 Celery 合成队列有限验收

日期：2026-10-26。执行入口为 `scripts/validation/round9_celery.py`，隔离基础设施为
`deployments/compose.round9-celery-validation.yml`。从仓库根目录使用已安装依赖的
Python 运行：

```sh
.venv/bin/python scripts/validation/round9_celery.py
```

CI 可用其环境中的 `python` 执行同一脚本，并通过 `--evidence` 指定输出 JSON。
脚本启动真实 uvicorn v2 API、RabbitMQ、Redis 和单并发 Celery prefork worker；
API 使用 `celery_app.send_task`，worker 消费 `cpag_generation` 队列。没有
`task_always_eager`、`.run()` 或模拟队列，也没有启动 beat。Compose 项目名称与宿主端口
随机分配，独立于默认部署；完成后停止 API/worker，删除容器和卷。

本机最终执行退出码为 0，结果 `validation-round9/celery-live.json` 的 `status=passed`、
`cleanup.status=passed`，API 与 worker 均正常退出，Docker 中无该次 `cpag-r9-` 容器残留。
原始访问与 worker 日志为 `validation-round9/celery-api.log`、
`validation-round9/celery-worker.log`。Python 3.11.9、Celery 5.3.4，
RabbitMQ 3.13.7-management 与 Redis 7.4.2-alpine 的镜像标识均记录于 JSON。

| 检查 | 实际观察 |
|---|---|
| C1 无 worker 排队 | HTTP 返回 `queued`，无发布产物；RabbitMQ 管理接口显示 `cpag_generation` 有 1 条 ready 消息。启动 prefork worker 后消费成功，Redis Celery 结果后端记录 `SUCCESS`。 |
| C2/C3 有效输入与核心一致 | 五件产物经 HTTP 下载，逐件检查 SHA256/大小、manifest、schema、结果指纹；8 个事件与图节点的证据引用均回查到保留原始记录。用相同保留输入、source 与授权参数运行独立核心，四件数据产物逐字节一致，`run_manifest.json` 仅 `run_id` 不同。 |
| C4 错误输入 | malformed network 与只有表头的 process 均由真实 worker 执行，Redis 后端记录 `FAILURE`，HTTP 状态为 `failed`；结果 409、发布产物列表为空（保留任务记录与输入）、下载 409。 |
| C4/C5 重复与 worker 重启 | 已完成任务的重复消息在 worker 日志中第二次 `received`/`succeeded`，全目录文件哈希不变。worker 正常退出码 0 后重启，另一任务完成且后端为 `SUCCESS`。 |
| C5 broker 停止与恢复 | 停止前 ready/unacknowledged 均为 0；broker 停止后新提交返回 HTTP 503，并留下 `failed`、零产物记录。恢复 broker 后，因 Docker 随机宿主端口重分配，重启本次隔离 API 以更新 AMQP 地址；随后新任务由新 worker 成功执行并核对五件产物。此项不证明原 API 进程透明重连。 |
| C6 损坏或缺失发布件 | 对已完成任务的 `graph.json` 分别做有效 JSON 字节篡改和移除，`artifacts`、普通 `result`、JSON `result`、下载四入口均返回 409；恢复原文件后下载返回 200。 |

本机初次 prefork 使用 Celery 5.3.4 的 macOS `spawn` 子进程时，出现
`fast_trace_task` 本地化初始化错误。脚本仅在 macOS 的**测试 worker 进程**中指定
billiard `fork`，仍使用真实 prefork；Linux 使用 Celery 默认启动方式。早期客户端超时、
RabbitMQ 指标采样与 Docker 随机端口恢复探针问题的诊断记录留在
`validation-round9/pre-attempt-*`；它们不算通过结果，也未改生产 Celery 配置。

范围仅为仓库提供的合成 fixture 与独立服务环境。没有中途强杀计算中的 worker，
不推断其重投递恢复语义；没有真实工业数据、历史任务实例或生产环境验收。
