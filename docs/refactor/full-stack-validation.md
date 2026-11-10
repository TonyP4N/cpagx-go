# 本地全栈与任务链路验证（2026-10-24）

本轮在 `refactor/m1-evidence-core` 继续修改，未新建其他分支，未提交或推送远端。本报告更新上一轮“全栈未启动”的状态；验证对象仍为明确标记的合成输入。

## 已实测的运行范围

本机 macOS arm64 源码运行 Go API、Python V1/V2、Celery Worker 和静态前端同源代理；Docker 隔离项目 `cpag-validation` 运行 Redis、RabbitMQ、Neo4j、InfluxDB。四个容器均通过健康检查。监控面板、Beat 定时维护不属于此次交互任务必要链路，未启动。源代码服务不是容器化 Linux 发布验收。

入口：<http://127.0.0.1:13000>。Go 为 18080，Python V1/V2 为 18000/18002，Redis 为 16379，RabbitMQ 为 15673，Neo4j Bolt 为 17687，InfluxDB 为 18086；全部只绑定本机。固定测试凭据仅用于该隔离环境，不用于生产。服务保持运行，可继续在页面操作。

完整实际链路：浏览器/HTTP → 同源代理 → Go `/api/v2/cpag/synthetic` → FastAPI → RabbitMQ → Celery Worker → 同一 M1 核心 → 校验产物 → 状态/结果 → 下载。

- 正常合成任务完成并下载 5 个文件，其中 4 个分析产物 SHA-256 与运行清单一致；运行清单本身不自哈希。
- 错误任务、未知文件、路径越界、未确认 synthetic、损坏网络输入均走明确失败路径。
- Worker 停止时新任务保持 queued；重新启动后完成。
- 已完成逻辑任务再次投递，校验产物后返回原结果，原任务清单字节不变。
- 上传源文件按只读副本留存在任务 `sources/`，校验值与事件来源引用可核对；它们不出现在公开下载白名单中。
- 已通过真实网页选择三份合成文件、提交、看到 completed，并点击 graph.json 下载；下载文件与服务端产物哈希一致。截图见 `validation-stack/browser-result.png`。

证据：`validation-stack/e2e.log`、`queue.log`、`health.json`、`checks.json`。Python 39 项回归通过（核心 6、契约 5、解析 12、旧路径 5、CLI 2、服务 9），Go test/build/vet 与前端 production build 通过。服务单测使用队列替身；上述 E2E/queue 记录使用真实 RabbitMQ、Redis 和 Worker，不将两者混淆。远端 CI 未触发。

## 修复内容

1. Go 按配置选择 V1/V2 地址，修正代理路径、版本头、批量状态参数转义、下载状态/附件头和服务不可用报告。
2. V2 增加显式 opt-in 合成任务入口，不替换旧版默认分析；修复静态批量路由排序、输出目录一致性、失败传播和 manifest 原子写入。
3. Redis 并发准入改为原子操作，容量不足或 Redis 故障时明确拒绝；不再捕获异常后继续执行。
4. 核心逐源判断解析失败，防止另一有效源掩盖完全损坏或不支持的输入。第一次 E2E 暴露的问题及原始失败记录保留在 `e2e-first.log`。
5. 重复投递不覆盖已完成结果，活动重复任务不删除原任务上传目录或释放其槽位；已完成结果须通过校验后复用。
6. 保存源输入，避免任务完成后证据引用失去原始依据。
7. 前端增加合成任务操作区；独立本机静态预览代理解决 Next 静态导出不执行 rewrites 的问题。

## 复现与停止

从仓库根目录执行（首次安装需要网络，镜像摘要与本机依赖快照已记录）：

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r services/python-cpag-generator/requirements-test.txt -r services/analysis/requirements-test.txt
npm --prefix webui ci
npm --prefix webui run build
mkdir -p .local-stack
go build -o .local-stack/cpagx ./cmd/cpagx
docker compose -p cpag-validation -f deployments/docker-compose.validation.yml up -d --wait
python3 scripts/local_validation_stack.py start
.venv/bin/python tests/e2e/synthetic_http_smoke.py --base-url http://127.0.0.1:13000
.venv/bin/python tests/e2e/local_queue_smoke.py
```

源码服务初次启动后先检查 `python3 scripts/local_validation_stack.py status` 和 `.local-stack/*.log`，确认 Worker ready 与 API 监听后再运行测试。`start` 不会覆盖仍在运行的服务。状态、上传源与产物位于 `.local-stack/`，不进 Git。Docker Hub 直连在本次环境失败，测试 Compose 使用 Google 公共镜像缓存，不改变全局 Docker 配置。

```sh
python3 scripts/local_validation_stack.py stop
docker compose -p cpag-validation -f deployments/docker-compose.validation.yml stop
```

只重启 Worker 可分别使用 `stop --only worker` 与 `start --only worker`。停止不会删除测试产物、数据卷或其他项目容器。

## 仍未验收

- 本次是合成任务贯通，不是旧版所有算法、所有文件格式或 Neo4j 图导入的完整回归。V1 已启动且健康可访问，未执行真实协议任务。
- 未在处理中强杀 Worker 或验证恢复部分产物。当前全局 Redis 槽位集合 TTL 仍不是逐 attempt 租约；其他任务续期可能延迟残留槽位回收。容量不足目前明确失败，不自动排队重试。不能据此称为已完成 M4 持久任务系统。
- 未实现 PostgreSQL/fencing token、取消、崩溃后的自动重试、备份恢复、身份权限与离线发布包。本机端口隔离不能替代生产鉴权。
- 原始数据、真实 PCAP/PCAPNG 协议覆盖、时间对齐、双源关联、独立标注与准确性/性能评估仍待办。公开规则不作独立标准答案，合成工程测试不构成工业验证。
