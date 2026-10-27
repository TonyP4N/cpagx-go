# 第十六轮正式入口与复现

本轮是显式可选、本机访问的工程入口，不修改原 `cmd/cpagx`、Celery 路径、用户当前部署或冻结 RC1。浏览器直接访问 Go 服务，Python 不提供对外 HTTP 代理。此文和 [服务配置](round16-v3-service.md)、[API 契约](../../api/openapi/v3.yaml) 一起使用。

## 正常应用启动

1. 准备独立 PostgreSQL 数据库，按文件顺序应用 `internal/jobs/migrations/001_jobs.sql` 至 `006_v3_catalog.sql`。本轮迁移仅增表，不迁移或覆盖旧 V1/V2 数据；生产迁移及任意历史格式不在本轮承诺中。
2. 在仓库执行 `npm --prefix webui ci`、`npm --prefix webui run build:static`，静态目录为 `webui/out`。准备 Python 环境，安装 `services/analysis/requirements-test.txt` 中的验证依赖，并使现有 `cpag_core` 和 `cpag_worker` 可导入。
3. `docker build -t cpag-isolated:round5 -f deployments/isolated-executor/Dockerfile .`。使用独立 shared/control 绝对目录，control 必须在 shared 外，均应只由服务操作者访问。
4. 根据服务配置文档创建权限 `0600` 的 `v3.json`。`static_root` 必须指向导出的 `webui/out`；两个监听地址不同，均绑定 `127.0.0.1`。
5. 启动 Go：`go -C internal/jobs/integration run ./cmd/cpagx-v3 --config /absolute/private/v3.json`。`/` 跳转 `/workspace/`，公共 API 为 `/api/v3`；内部 Worker 协议仅在另一监听地址提供。
6. 创建另一个 `0600` 的 `worker.json`：只包含 `api_url`（内部监听地址）、`shared_root`、`control_root`、`worker_token`、`coordinator_token`，可选 `worker_id`、`image`、`poll_seconds`、`recovery_seconds`。不包含数据库口令、管理员口令或浏览器会话。默认领取间隔 1 秒，独立恢复扫描间隔 5 秒；扫描仍需 Docker/API 可用，未取得退出证明不得推断 cancelled。
7. 在仓库启动：`PYTHONPATH=services/worker:services/analysis/src .venv/bin/python -m cpag_worker.service --config /absolute/private/worker.json`。
8. 浏览器打开公共地址，使用初始管理员登录；创建用户/数据集及授权，再上传、创建配置版本、预检、提交运行。源材料声明和核验状态分别显示；真实来源只能接收及元数据/完整性预检，当前计算核心仍不支持真实双源分析。

两个独立数据库环境若同在 `127.0.0.1` 不同端口，验收使用不同浏览器配置文件/会话，避免浏览器不按端口隔离 cookie。恢复会撤销备份中的会话，必须重新登录。局域网访问、TLS、正式发布包和系统级服务安装留在后续明确批次，本轮不将开发启动算作离线交付。

停止时向 Go 服务与 Worker 发送 SIGTERM，等待进程退出；不要仅凭停止命令成功推断计算已退出。任务状态及 attempt 退出依据沿用现有持久机制。取消中且证据不足的任务继续保留待处理，不修改数据库强行完成。

## 同一 API 的 CLI

`go build -o /absolute/private/cpagctl ./cmd/cpagctl`。登录凭据经标准输入提供 JSON，避免放在命令参数；工具将会话保存到 `0600` 文件，且校验会话所属 origin。

```sh
/absolute/private/cpagctl --url http://127.0.0.1:8095 --session /absolute/private/session.json login
/absolute/private/cpagctl --url http://127.0.0.1:8095 --session /absolute/private/session.json request GET /api/v3/datasets
/absolute/private/cpagctl --url http://127.0.0.1:8095 --session /absolute/private/session.json --body /absolute/private/run.json request POST /api/v3/runs
```

`run.json` 包含 `dataset_id`、`config_version_id`、`mode:"dual_source"`。CLI 不直接连数据库，不创建第二套任务状态；读写及错误与 UI/API 一致。原件上传使用 `--upload` 和 `--idempotency-key`，客户端计算 SHA-256，服务端重新验证。CLI 当前上传上限 16 MiB；接收 API 的更大接收限额不意味着核心可执行该尺寸。

## 可重复完整验收

前提：Go、Node、Python 验证依赖、Docker 可用，前端已构建，Playwright 1.61.0 与 Chromium 已安装。使用全新的绝对输出目录：

```sh
CPAG_PYTHON="$PWD/.venv/bin/python" \
PLAYWRIGHT_MODULE=/absolute/path/node_modules/playwright \
bash scripts/validation/round16_acceptance.sh /absolute/private/new-round16-validation
```

脚本构建正式 Go 二进制，启动独立 PostgreSQL、正式服务及隔离 Worker，实际运行合成任务；验证 CLI、权限、版本、终态备份、空库/新目录恢复，再通过正常浏览器操作和边界注入验收。结束清理自建进程和容器。不会修改用户部署。

`environment/state.json`、配置、数据库 dump 和内部日志是私有验收材料，禁止作为公开 CI 附件；仅 `public/`、`environment/public/` 输出可公开。浏览器下载的示例仍为合成数据。真实来源分支测试使用生成字节测试来源声明，不代表收到、适配或验证真实工业材料。

现有 `scripts/backup/bundle.py` 仍是限定 `m4_validation` / `m4_restore_validation` 的终态停写验收工具。本轮扩展数据集、配置、ACL、审计、运行绑定和会话撤销，不能据此宣称已有任意生产库备份命令、热快照或整机迁移工具；运维产品化在 R21，独立发行包恢复验收在 R22。
