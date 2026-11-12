# R21 单机 Linux 部署操作说明

EU k3s 部署使用独立的 [Kubernetes 终态备份恢复入口](round21-kubernetes-fixes-20261105.md#k3s-运维入口)，含宿主卷与容器路径映射；本文件的 Docker/process/systemd 操作仍按其原环境使用。

本入口独立于冻结 RC1 和旧 compose。统一 Go API、Worker、共享原件/结果、控制回执和 PostgreSQL 必须属于同一明确部署；外部只经 HTTPS 代理访问公共 API。Go 公共及内部监听仍分别为 `127.0.0.1:8095`、`127.0.0.1:8094`，PostgreSQL 本机端口为 `127.0.0.1:15432`。代理不能连接内部监听。

## 交付身份与支持边界

`deployments/r21/build-release.py` 从版本控制清单和明确的 R21 运行文件制作包，排除未跟踪 DAG5 原型 `scripts/backup/shared_storage.py`。`release.json` 记录实际 `go list -deps` 编译输入、模块版本、Go 工具链、逐文件 SHA-256 和二进制 SHA；HEAD 仅为来源参考，不替代运行身份。安装前核对清单，应用目录由管理员持有且服务账号不可写。

本轮实际宿主是独立 Linux/arm64 DinD（Alpine、LinuxKit 内核），使用原生 Linux 数据卷和 UID1001 运行 API/Worker，没有挂载准备机 Docker socket。其私有 Docker daemon 只监听 Unix socket。它证明容器化单机 Linux 部署路径，不能代替裸机/虚拟机开机、Ubuntu 参考环境或真实工业材料验收。systemd 模板交付但本环境 PID1 为 dockerd，实际启动管理使用下面的 process 模式；systemd 主机自启动需在目标系统再验。真实域名、外部可信证书及 Windows 实际终端仍需现场确认。

本轮冻结运行来源参考 `833fbb3854a8dd363790cef93cd8f6c1832eb044`，API 实际编译输入摘要 `b71f6fad26daa56829f590952dbc5a2335a6e6343ae2f25a496b8b40b2c80120`，Linux API 二进制 `159e5fc9e46c4dd54d846eb9516470f02ddf50cd6fdb9f54885620a71f2f0a9f`。完整清单和独立运维工具清单分别保留，见 [本轮验收](round21-acceptance.md)，不把后来运维脚本更新冒充原运行包。

## 目录和账号

| 路径 | 用途 |
|---|---|
| `/opt/cpag/current` | 只读运行包，含 bin、CPAG Python 模块、schemas、migrations、静态工作台 |
| `/etc/cpag/app.json` | 0600，DB URL、独立内部凭证、显式 external_origin、根路径 |
| `/etc/cpag/worker.json` | 0600，仅内部 API/Worker 配置，无 DB 或浏览器凭证 |
| `/etc/cpag/operator.json` | 0600，部署 ID、实际 PG 容器/库名、服务及受控目录 |
| `/var/lib/cpag/shared`、`/var/lib/cpag/control` | 分离的持久原件/结果与控制证据 |
| `/var/log/cpag`、`/run/cpag` | 私有日志与本部署服务 PID/起始时间记录 |
| `/var/backups/cpag` | 受控 bundle、预览和操作审计；不与业务根重叠 |
| `/var/lib/cpag-acme` | 公开 ACME HTTP-01 文件目录，不放业务和配置 |

目标机预置 Docker Engine、Python3（运行时无需 pip）、nginx。`cpag` 为专用账号，访问本机 Docker 组；该账号和运维账号属于可信主机管理边界。目录由管理员创建，业务、控制、日志和 PID 目录允许 cpag 写；配置为该账号可读的 0600 普通文件。外部用户只使用应用角色，不获得操作系统或 Docker 权限。

## 构建和新安装

准备机先完成静态导出，再制作对应架构包；不要在冷启动/烟测期间替换运行文件。

```sh
python3 deployments/r21/build-release.py --arch arm64 \
  --static-root webui/out --output /absolute/path/cpag-r21-release
```

`--include-smoke-fixture` 仅额外带入小型合成夹具。Linux/amd64 可构建，但本轮实跑为 arm64，不能据此标记 amd64 已验。计算镜像使用 `Dockerfile.compute` 构建后固定到目标 daemon 的不可变 image ID；如从离线 tar 加载，记录加载后的实际 ID，不混同准备机 OCI 索引摘要。

将包放入只读应用目录后，用新、空配置目录生成独立凭证。以下域名仅为待替换示例，须与真实证书和 DNS 一致。

```sh
python3 /opt/cpag/current/deployments/r21/init-config.py \
  --deployment-id my-cpag --external-origin https://cpag.example.org \
  --executor-image sha256:REPLACE_WITH_TARGET_IMAGE_ID
```

生成器由root执行并要求backup_root保持root:root 0700；仅打印路径，口令在私有文件中，不写入公开部署包。服务账号权限只分配给业务/控制/日志/PID目录和它必需的配置，不递归chown备份根：

```sh
chown -R cpag:cpag /var/lib/cpag/shared /var/lib/cpag/control /var/log/cpag /run/cpag
chown cpag:cpag /etc/cpag/app.json /etc/cpag/worker.json /etc/cpag/operator.json
chmod 600 /etc/cpag/app.json /etc/cpag/worker.json /etc/cpag/operator.json
chown root:root /var/backups/cpag
chmod 700 /var/backups/cpag
```

配置父目录须允许cpag遍历，但不把备份根交给该账号。首次实验曾误把backup_root改成UID1001，已仅修正备份根而保持shared/control UID1001；部署restore保护没有放宽。`postgres.env` 供创建本部署 PG 使用，`credentials.json` 为首次管理员登录资料。不要覆盖非空配置目录。运行包内 Python 路径应来自目标 Linux 的生成器，不能沿用准备机路径。

创建自有 PG 数据卷和容器，至少设置 `cpag.role=postgres`、`cpag.deployment_id=<相同ID>` 标签；本包实际源库为 `cpag_app`，恢复目标为 `cpag_restore`。容器只发布本机15432，不复用不明容器或重命名测试数据库绕过 gate。原 `bundle.py` 仅测试库名 guard 继续保留，部署工具以私有 operator 配置和实际容器 ID 受控授权。

```sh
docker volume create --label cpag.deployment_id=my-cpag cpag-r21-postgres-data
docker run --name cpag-r21-postgres --pull=never -d --restart unless-stopped \
  --label cpag.role=postgres --label cpag.deployment_id=my-cpag \
  --env-file /etc/cpag/postgres.env -p 127.0.0.1:15432:5432 \
  --mount type=volume,src=cpag-r21-postgres-data,dst=/var/lib/postgresql/data \
  mirror.gcr.io/library/postgres@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94
```

已有同名资源应先核对归属和配置，禁止强制覆盖。等待 `pg_isready` 后，在 Go/Worker 停止状态迁移：

```sh
/opt/cpag/current/deployments/r21/cpag-service migrate --config /etc/cpag/operator.json
/opt/cpag/current/deployments/r21/cpag-service start --config /etc/cpag/operator.json
/opt/cpag/current/deployments/r21/cpag-service status --config /etc/cpag/operator.json
```

迁移内容及其 SHA 回执在同一数据库连接事务提交；已应用文件内容变化会拒绝。包含017 Worker观测迁移。进程模式记录 Linux PID 和起始时间，停服只针对本部署记录且命令身份匹配的进程；过期 PID 不可用来杀其他进程。`stop` 先 Worker 后 API，保留 PG、数据、控制和日志。

## systemd 主机

在具备 systemd 的目标机复制 `cpag-api.service`、`cpag-worker.service` 至 `/etc/systemd/system/`，确认 cpag/docker 组、固定路径和 Python 路径，再 `systemctl daemon-reload`、`systemctl enable --now cpag-api cpag-worker`。本机 Docker 服务及 PG 容器须有明确开机策略。模板仅 systemd 主机使用；本轮容器化验收不声称完成其开机验收。

`cpag-service` 在 PID1 为 systemd 时委托这两份固定 unit，其余 Linux 使用 process 模式。不要混用两种管理方式启动重复实例。日志用 `journalctl -u cpag-api -u cpag-worker`；process 模式用 `cpag-service logs --lines 100`，只作有界 tail。应用审计、原件和控制回执与可轮转诊断日志分开保留。

## HTTPS、Host 和证书

```sh
python3 /opt/cpag/current/deployments/r21/render-proxy.py \
  --origin https://cpag.example.org --nginx-user nginx
nginx -t -c /etc/cpag/nginx.conf
nginx -c /etc/cpag/nginx.conf
```

按目标发行版实际 nginx 账号设置 `--nginx-user`（例如 Debian 常用 www-data）。TLS 文件为 `/etc/cpag/tls/cert.pem` 和 `key.pem`；生产文件必须由实际目标域名的可信签发链提供。只代理公共8095，明确清空 Forwarded 和 X-Forwarded-Host/Proto/For，保留真实 Origin。Go 忽略这些转发声明来决定信任，HTTPS 写入要求 Origin 与 external_origin 精确匹配；无 Origin 的原有 CLI 仍可用。

未知 Host 返回421 JSON。HTTP 只对允许 Host 提供 ACME webroot 或308到固定 HTTPS origin，不反射请求 Host。nginx 全局允许评估请求至128MiB；源文件上传入口64MiB，Go按 role 将工艺文件限制为8MiB；超限返回413 JSON。上传接收限额不等于可分析规模，S100之外的 M/L 不因此获得支持。代理关闭请求/响应磁盘缓冲，并保留65秒发送、610秒读取上限，与有界 Go 服务配合。

现场 ACME 条件是：真实域名控制权、DNS 指向、80端口可达、证书负责人安装并核查 Certbot。HTTP-01 webroot 为 `/var/lib/cpag-acme`。以下由证书负责人在真实主机执行并留存结果，本轮未向外部CA登记或申请：

```sh
CPAG_DOMAIN=cpag.example.org
CPAG_CERT_EMAIL=certificate-owner@example.org
certbot certonly --webroot -w /var/lib/cpag-acme -d "$CPAG_DOMAIN" \
  --email "$CPAG_CERT_EMAIL" --agree-tos --non-interactive
ln -s "/etc/letsencrypt/live/$CPAG_DOMAIN/fullchain.pem" /etc/cpag/tls/cert.pem
ln -s "/etc/letsencrypt/live/$CPAG_DOMAIN/privkey.pem" /etc/cpag/tls/key.pem
/opt/cpag/current/deployments/r21/cert-renew-hook
certbot renew --dry-run --run-deploy-hooks \
  --deploy-hook /opt/cpag/current/deployments/r21/cert-renew-hook
```

若目标TLS文件已存在，证书负责人应先归档、核对，不使用强制覆盖替换测试证书。必须映射 fullchain 与 privkey，不能把单张叶证书当完整链。deploy-hook 先 `nginx -t`，失败不reload；dry-run 默认不执行deploy-hook，显式 `--run-deploy-hooks` 才演练它，语义见 [Certbot官方命令说明](https://eff-certbot.readthedocs.io/en/stable/man/certbot.html)。现场先检查安装版本支持该选项。

选择发行版已有certbot timer或包内 `cpag-cert-renew.service/.timer` 之一；后者每天02/14时加随机延迟检查，只在成功续期后执行deploy-hook。安装两份unit、`systemctl daemon-reload`、`systemctl enable --now cpag-cert-renew.timer` 后，用 `systemctl list-timers` 和 `journalctl -u cpag-cert-renew` 留存调度/续期结果。目标为非systemd主机时使用其原生定时器执行相同renew命令，不声称本轮已验证systemd timer。外部CA签发、公网续期和真实域名信任仍为现场门禁；本轮本地webroot及测试证书演练与它分开记录。

本轮测试地址 `https://127.0.0.1:44943`，使用两天有效的私有测试 CA。严格 curl `--cacert` 和 Python CERT_REQUIRED+check_hostname 已分别验证链、IP主机名与TLS1.3；没有安装到OS永久信任。浏览器 SPKI 例外只证明功能点击，不能视为系统/浏览器CA信任通过。Windows实际终端另列待确认。

## 健康、角色和恢复

- `/health/live` 只代表进程存活；`/health/ready` 检查 DB 和必要持久目录访问/64MiB可用空间。
- 管理员 `/api/v3/health/operations` 提供 Worker最近观测、队列等待、失败/核验/审计计量。默认 Worker陈旧120秒、队列告警60秒；只按接口允许范围调整，不能把进程存在当Worker业务活动。
- 安装/恢复后用真实登录和受控下载检查角色：未登录拒绝、无数据集授权拒绝、只读者不出现写入入口。Secure/HttpOnly/SameSite=Strict Cookie需经实际HTTPS核查。

本次实跑运维工具为历史签名 `914a0c35` 对应独立包 `/opt/cpag-ops/dd37db61292694856bb53f7c290b9c600b302747f546f727c0548a991752097d`，其manifest绑定四脚本、drill和冻结runtime清单。设置 `CPAG_OPS_ROOT` 为此路径执行下列命令。最终提交重新构建的release可包含相同SHA脚本，必须逐文件比对后才等同于本次工具；原冻结runtime内未同步旧副本不作为本次运维入口。

```sh
python3 "$CPAG_OPS_ROOT/scripts/backup/deployment_ops.py" --config /etc/cpag/operator.json status
python3 "$CPAG_OPS_ROOT/scripts/backup/deployment_ops.py" --config /etc/cpag/operator.json \
  backup --destination /var/backups/cpag/checkpoint-001 --stop-services
python3 "$CPAG_OPS_ROOT/scripts/backup/deployment_ops.py" --config /etc/cpag/operator.json \
  restore --source /var/backups/cpag/checkpoint-001 \
  --destination /var/lib/cpag-restored/shared --control-destination /var/lib/cpag-restored/control
```

备份要求停写、所有计算/核验退出。部署 restore 仅接受本部署 backup_root 直属、具有本部署 owner、成功外置回执和bundle SHA的包；拒绝跨部署或R19旧包直接混入。目标DB/目录须全新，已存在明确失败；不通过改库名、删除原目录或手改authority绕过。恢复后用独立配置指向新DB/roots并轮换内部凭据，保留旧配置；旧会话应401，新登录后重新核验原件与下载。017 Worker瞬时观测表清空，不把旧心跳当恢复后的在线证明。

root执行restore后，新shared/control由root创建。先保留成功的字节/元数据核验回执，再将这两个明确的新目标交接给实际服务UID；不要递归修改备份根、旧源目录或数据库卷。例如本包服务UID为1001：

```sh
chown -R cpag:cpag /var/lib/cpag-restored/shared /var/lib/cpag-restored/control
chmod 0700 /var/lib/cpag-restored/shared /var/lib/cpag-restored/control
```

交接只改变属主/权限，仍须复算原件SHA并记录新旧目录身份。新配置的数据库、shared/control和Worker挂载必须一致；在新目标启动前保留旧配置及其哈希，禁止覆盖源备份。以相同冻结二进制启动后，先实际发送备份前有效的会话确认401，再新登录、等待重新核验、查原任务/回放/评估和下载；不能用随机cookie或源库已通过的记录替代恢复目标核验。

process模式以 `cpag-service start --config /etc/cpag/recovery/operator.json --mode process` 明确选择恢复配置。systemd模式调用固定unit，不会根据operator路径重写unit的ExecStart；在目标systemd主机必须先分别为API/Worker安装drop-in，清空并重设ExecStart到新app/worker配置，同时把新shared/control/log/run目录加入ReadWritePaths，`daemon-reload` 后检查 `systemctl cat` 的实际结果再启动。本轮没有实跑systemd恢复，不可只换operator文件就宣称unit已切目标。

## 保留和有限清理

只先生成预览，再以 deployment ID确认并写独立审计：

```sh
python3 "$CPAG_OPS_ROOT/scripts/backup/deployment_ops.py" --config /etc/cpag/operator.json \
  cleanup-plan --log-days 14 --temporary-days 1 --output /var/backups/cpag/cleanup-plan.json
python3 "$CPAG_OPS_ROOT/scripts/backup/deployment_ops.py" --config /etc/cpag/operator.json \
  cleanup-apply --plan /var/backups/cpag/cleanup-plan.json --confirm-deployment my-cpag \
  --audit /var/backups/cpag/cleanup-audit.json
```

仅受控的旧轮转日志和明确关闭的 `*.tmp.closed` 可进入清理；持维护独占锁并检查Linux打开FD、硬链和符号链。活动日志、PID、业务原件、控制回执、结果、bundle不在此自动删除范围。`retention-plan --keep 3` 只是bundle保留预览，不自动删除历史证据。每次拒绝/失败和原始测量均保留，停止本轮隔离服务不等于删除其数据卷。

## Windows 操作与现场交接

1. 域名负责人从目标 Windows 电脑验证实际域名解析到目标入口。用 Edge 或 Chrome 打开交接的实际 HTTPS 域名下的 `/workbench/`，保留正常证书校验，记录系统和浏览器版本。
2. 首次管理员凭据由服务器负责人从受控的 `credentials.json` 通过已有安全渠道交接。管理员创建分析员和只读者，按数据集分别授权。日常客户端无需 Docker、命令行或服务器凭据。
3. 分析员进入「数据与配置」，上传同批抓包和工艺表，选择接收配置、运行预检，再选择分析配置和离线模式。记录提交返回的任务 ID，关闭浏览器、重新登录，从「任务中心」找回该 ID。
4. 在「分析结果」点击操作，核对请求、响应及前后两条工艺原件；通过受控链接下载。打开一份回放及一份已保存评估，分别核对选定快照和错误案例的原始记录。改用只读账户，验证授权范围内可读，无权数据集的下载链接被服务拒绝。
5. 验收单填实际 URL、版本、任务 ID、预期拒绝状态和下载文件摘要。密码、会话、数据库副本与证书私钥留在受控位置。测试回环地址不能供另一台电脑访问。

## 临时退回已有入口

同一 Go/V3 部署在 `/workspace/` 保留既有网页入口。切换只改变网页地址，数据库、发布绑定和持久目录继续使用同一份；回到 `/workbench/` 按原任务 ID 重开。双源导出仍经有数据集 ACL 的 `/api/v3/runs/{id}/artifacts` 读取。没有数据集 ACL 的旧 M4 normalized/packet 成功结果，登录管理员可用 `/api/v3/history/jobs/{id}/artifacts` 查看核验清单，并在其后追加 `/{清单成员}/download` 下载。缺源、错误绑定、未知格式会拒绝。

需要原 V1/V2 协议时，由运维在原受控环境使用旧 Go 网关和对应版本的上游。V1/V2 使用 `/api/v1/cpag/result/{id}`、`/api/v2/cpag/result/{id}`；旧 `/api/cpag/result/{id}` 指向 V1。公开反向代理只连接 V3 公共监听；旧网关不能继承 V3 浏览器会话的授权语义。保留原结果目录和上游后，可在授权的旧环境只读打开，再按原 ID 回到新系统。已知独立导出可由运维运行只读核查器；未知导出须交原版本核查。在同机切网页入口与跨版本迁移恢复之间保留边界，后者留给 R22。

## 值班告警与处置

管理员登录后可在同一浏览器单独打开 `/api/v3/health/operations`，无需获取 Worker token。命令行探针读取公共监听的 `/health/live` 与 `/health/ready`；管理员业务审计在 `/api/v3/audit`。逐个运行的实际阶段、最近错误、attempt 和退出状态在「任务中心」查询。

| 信号 | 值班动作 |
|---|---|
| live 不通 | 查看 `cpag-service status` 和受控日志；先核对是否处在计划停写，以及 Go 是否监听公共端口，再查代理。 |
| live 200、ready 503 | 暂停接单，按响应中的 database/storage 布尔值检查 PG 或实际挂载、属主、可写权限及磁盘余量。恢复目录或数据库后等 ready 200。 |
| 可领取队列最老等待超过 60 秒；有排队任务但没有新鲜 Worker | 核对 `last_seen`、内部回环连接、Worker 和 Docker 状态；先检查当前计算或核验是否依旧占用唯一名额。 |
| 活动 Worker 观测陈旧超过 120 秒或租约已过期 | 查该运行的 attempt、容器身份和退出回执；由恢复器收尾。退出未确认时保留待处理，不能手动释放名额或直接改为成功/已取消。 |
| 存储不可用或任一必需目录可用空间低于 64 MiB | 暂停新提交，先看容量账本和已保留快照，再对可清理类别预览。恢复到 Worker 配置所需执行余量后才接单；64 MiB 仅是最低就绪门槛。 |
| 有退避重试、解析或资源失败记录 | 使用查询参数 `errors=parse`、`errors=resource` 或 `errors=storage` 核对具体运行。先修正实际输入或环境，再按原 attempt 策略重试。不可将过往错误条数当作实时失败率。 |
| 上传或配置保存显示 `commit_unconfirmed` | 按原上传幂等键重查，或按数据集重读配置版本；核对数据库与文件后再决定重试。保留可能已经入库的原件，不手工删除。 |
