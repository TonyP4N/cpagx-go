# CPAGx-Go

[![Go Report Card](https://goreportcard.com/badge/github.com/TonyP4N/cpagx-go)](https://goreportcard.com/report/github.com/TonyP4N/cpagx-go)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

CPAGx-Go is a microservices platform for analyzing cyber-physical attack graphs from network traffic. Built for security researchers and SOC analysts to visualize attack paths in industrial control systems.

## 安装 v3 工作台

Docker Compose 和 k3s 使用同一套工作台、Go API 和分析核心。网页提交的数据集和任务保存在 PostgreSQL，常驻 Worker 领取任务后在自己的容器内启动 Python，API 核验退出记录与产物后发布结果。

**已有旧版 Compose 部署的用户**请先按[升级与回滚说明](docs/deployment/compose-upgrade.md)保存旧任务、卷和结果，并在独立端口验证 v3。首次安装请从仓库根目录运行：

```sh
docker compose -f deployments/docker-compose.yml up -d --build
docker compose -f deployments/docker-compose.yml ps -a
curl -fsS http://127.0.0.1:3000/health/ready
```

通过 [本地工作台](http://127.0.0.1:3000/workbench/) 登录，首次管理员凭据的读取命令见[安装说明](docs/deployment/compose-upgrade.md)。原 `deployments/docker-compose.local.yml` 文件名也可使用。EU 的 k3s 镜像和工作负载由[独立 GitOps 清单](https://github.com/pplulee/infra/tree/main/gitops/environments/eu/apps/cpag)管理。

## 历史开发记录（2026-10-24）

最新进展见 [第三轮协议适配与 Worker 接入](docs/refactor/round3-completion-20261024.md)。

前轮记录见 [第二轮 M1 收尾、M2/M4 技术交付](docs/refactor/round2-completion-20261024.md) 与 [后续实施计划](docs/refactor/m1-closeout-and-next-plan.md)。

首轮已完成内容、修复清单、验证结果及待办边界见 [阶段性重构完成说明](docs/refactor/completion-summary-20261024.md)。

后续已启动本地全栈并验证合成任务提交、队列执行、结果下载与重复投递，见 [全栈验证与启动说明](docs/refactor/full-stack-validation.md)。

当前分支新增可独立运行的纯 Python 核心、九类版本化数据契约和合成样例。使用方式见 [核心说明](services/analysis/README.md)，实施及验证结果见 [本轮交付记录](docs/refactor/acceptance.md)。本轮只验证软件行为；尚未取得 SWaT 原始双源数据，未验证真实时间对齐、关联或准确性。公开规则不是独立标准答案。

## License

MIT License - see [LICENSE](LICENSE) for details.
