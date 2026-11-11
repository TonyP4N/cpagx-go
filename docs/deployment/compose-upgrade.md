# 从旧版 Docker Compose 升级到 v3

v3 在 Docker 上运行工作台、Go API、PostgreSQL 和常驻 Worker。使用新目录和独立的 Compose 项目名，可在同一主机试运行，并用原容器回滚。下面的命令适用于 Linux 容器和 Docker Compose v2.20 及以上版本。示例中的旧项目名、清单文件名、路径及端口请以现有部署为准。

## 保留旧任务和原始文件

在旧版目录执行 `docker compose ls`，记录正在运行的项目名和清单路径。记录当前 Git 提交、镜像 ID、私有配置、所有命名卷和 bind mount 的实际位置。在运维私有目录保存记录，旧配置可能含数据库密码。

```sh
old_project=deployments             # 替换为实际旧项目名
old_file=/path/to/old/deployments/docker-compose.local.yml
docker compose -p "$old_project" -f "$old_file" ps -a
docker compose -p "$old_project" -f "$old_file" ps -aq |
  xargs -n 1 docker inspect --format '{{.Name}} {{.Image}} {{json .Mounts}}'
```

旧系统的上传文件和结果通常在宿主机的 `uploads/`、`data/`、`services/python-cpag-generator/outputs/`，定制安装请按上一步的实际挂载处理。先从旧系统下载需要保留的结果，备份这些目录、旧配置、数据库卷和容器可写层中的自定义数据。数据库卷应在停写或停机后做一致性快照。保留原部署目录、镜像和卷，直到升级验收及回滚窗口结束。

v3 将任务、权限和数据集登记在 PostgreSQL。旧版任务号、图数据库记录和结果文件可作为历史资料保留。要在 v3 分析既有材料，从工作台创建数据集，上传带来源信息的原始抓包与过程 CSV，完成配置和预检后重新提交。新任务会生成自己的任务号、执行记录及证据。当前没有把旧任务自动转换成已核验 v3 任务的迁移器。

## 在原 Docker 主机上试运行

在单独目录检出包含本次升级的发布版本，进入其仓库根目录。显式使用专用项目名 `cpag-v3`，旧项目继续使用原来的名称。如果已有项目叫 cpag-v3，请在后续命令中为新项目统一选用另一个空闲项目名。先使用空闲端口。

```sh
export CPAG_HTTP_PORT=3300
docker compose -p cpag-v3 -f deployments/docker-compose.local.yml up -d --build
docker compose -p cpag-v3 -f deployments/docker-compose.local.yml ps -a
curl -fsS http://127.0.0.1:3300/health/ready
```

浏览器请使用命令中相同的 127.0.0.1 地址和端口，以通过来源校验。经 HTTPS 反向代理访问时，在启动前设置 CPAG_EXTERNAL_ORIGIN 为浏览器实际使用的完整 HTTPS 来源，例如 https://cpag.example.org。

在本机受信任的终端读取首次登录凭据，然后访问 `http://127.0.0.1:3300/workbench/`。

```sh
docker compose -p cpag-v3 -f deployments/docker-compose.local.yml exec api python3 -c \
  'import json; c=json.load(open("/etc/cpag/app.json")); print(c["bootstrap_admin_username"]); print(c["bootstrap_admin_password"])'
```

提交一个小型合成离线样例，等状态变为成功后打开原始证据并下载结果；用回放样例打开已知末快照。在工作台核实任务归属与预期一致。

## 切换和回滚

停止旧入口接收新任务，等待在途任务完成，按旧项目的清单停止容器并完成最终备份。下面使用 `stop` 保留旧容器及其可写层。当前端口由反向代理提供时，也可以把代理后端切换到已验收的本地新端口。

```sh
docker compose -p "$old_project" -f "$old_file" stop
export CPAG_HTTP_PORT=3000
docker compose -p cpag-v3 -f deployments/docker-compose.local.yml up -d
curl -fsS http://127.0.0.1:3000/health/ready
```

如需回滚，先关闭对外提交并在 v3 核清在途 attempt，保留已经产生的数据集、结果卷和 PostgreSQL。停止新项目，从原目录用原配置启动仍保留的旧容器，或将代理指回旧端口。

```sh
docker compose -p cpag-v3 -f deployments/docker-compose.local.yml stop
docker compose -p "$old_project" -f "$old_file" start
```

切换及回滚过程中保留两套数据卷。带 `-v` 的 `down` 和卷清理命令会删除数据，不适用于以上流程。
