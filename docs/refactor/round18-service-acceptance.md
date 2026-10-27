# R18 服务、隔离 Worker 与终态目录核验

实施前登记为 [cc2db77 对应计划](round18-plan-scenarios.md)，基线 `25b2f1c8985fe7b68323cfea224e785c124679f2`。本页记录本轮服务子范围及实际局部结果；最终实现提交、完整 CI、七任务主链、空库恢复和普通点击结果由主验收报告绑定。未新增任务状态、未切换默认入口或冻结 RC1，未进入 R19。

## 服务契约

显式 `dual_source_replay` 运行模式派发 `dual-source-replay` 任务，复用原身份、排队、租约、fencing、取消、重试、退出证明和幂等发布。009 只扩展运行模式并添加 nullable `replay_version`：旧 offline 行为 null，回放版本必须与不可变 `profile.replay.version`、payload 和产物一致。现有来源、授权、映射、时间依据、当前预检和同一入队事务中的输入/配置复核继续执行。

Go 独立检查 ReplayRunManifest、完整输入/配置绑定、语义配置指纹、每条 snapshot/revision 的身份与旧新链、到达前缀可见性；从各快照 analysis 重建 events、graph、claims，核对变化前后原始观测及 claim 原始引用，不能只重算文件哈希放行。PCAP 记录头+帧、PCAPNG EPB、CSV 原始逻辑记录分别校验 record SHA；完整文件 SHA 仅留在最终完整性绑定，不冒充前缀记录身份。CSV 证据保留 quoted CRLF 字段原值。

终态可信产物提供 `result`、`revisions`、`snapshots?revision=N`、`snapshots/N`，以及 `evidence?revision=N` 配合互斥的 `operation`、`change` 或精确 `trigger=true` 选择器；N 是从 0 开始的 snapshot_number。trigger 仅解析该快照触发记录中的证据引用，包含未成为候选的 too_late/discarded 原始记录，仍受已到达前缀约束，不接收任意原始引用。图可选择历史快照，未指定时返回已核验的最终图。下载仍只能选择 manifest 明列文件，包含 snapshots/revisions/arrivals JSONL；不提供任意路径。新读取沿用数据集 ACL 和审计，运行中未校验临时产物不可读。OpenAPI 为 0.4.0；cpagctl 已通过同一 JSON API 的显式 mode 请求，无须另造队列客户端。

隔离计算继续使用既有网络隔离、只读原件、独立凭据与资源限制，总输出仍为 16 MiB。输出/缓冲超限不得发布可信截断成功。备份审计增加新 kind、模式与版本绑定、完整回放 inventory 和历史证据重验，沿用 format4；旧 format2/4 与旧任务规则不改。

## 预期与实际

| 场景/预期 | 实际及证据 |
|---|---|
| 合法新产物、历史 pending、原件与 claim 验证；篡改不得靠重哈希通过 | Go 跨语言测试通过；逐 snapshot 重建投影与 claim 引用、pending 原件查询、禁止未来响应/fullfile 引用、错误 claim 与次件原件篡改拒绝 |
| 历史触发记录即使被丢弃也可核验，禁止选择未来记录 | 实际新导出 too_late 快照的 process record4 未进入 analysis 候选，但 `trigger=true` 返回其原始记录；未来 record6 引用、非精确 true、重复 trigger 和混用选择器均拒绝。[定向回归](validation-round18-service/trigger-evidence-after.log) |
| 新 mode 进入同一隔离交接，缺历史不得成功 | 隔离 Worker 22 项通过，包含 replay 版本/attempt、全部原件及历史 inventory、重哈希截断 snapshots 拒绝。[日志](validation-round18-service/isolated-tests.log) |
| 旧 Worker 与恢复行为保留 | Host Worker 15 项通过。[日志](validation-round18-service/worker-tests.log) |
| 终态新目录全历史、版本与原件可追踪 | 备份 50 项通过，包含新 kind 全字节目录复制后历史查询相同、丢历史/篡改原件/绑定版本错误拒绝。这里的目录复制测试不代替主链的真实 PG 空库成套恢复。[日志](validation-round18-service/backup-tests.log) |
| 队列取消不创建 attempt、不发布 | 正式 Go/PG API 取消后 cancelled、attempt=0，无计算实例；退出证明标明不适用 |
| 实际回放运行中取消，先确认执行退出才终态 | 在第三条真实到达、请求已可见且状态 pending_response 时注入取消；cancelled、未发布部分目录，保留 inspected container/removed=true/running=false/pid=0 证据 |
| 无效 PCAP 明确失败，不发布部分历史 | 实际计算 native returncode=2、stderr=unsupported_capture_magic；遵既有重试 backoff，三次有退出证明的 attempt 后 failed，无 artifact_path |
| Worker 中断与真实租约到期，新 attempt 从头重放 | 同一 pending_response 前缀 SIGKILL Worker，实际等 lease 过期、恢复确认旧容器退出/删除后，attempt2 从 snapshot0/arrival_seq0 重放成功，旧 attempt 未发布 |
| 旧 attempt 不得完成、重复完成只发布一次 | 旧 attempt complete 返回 409；同一成功身份/SHA 重试 complete 成功且只有一个可信 anchor，结果 SHA 不变 |

正式生命周期八项检查完整记录见 [通过报告](validation-round18-service/lifecycle-passed.json)，[原始通过报告](validation-round18-service/lifecycle-passed-original.json)原样保留。该故障注入窗口只证明“实际回放第三条到达时”的取消/中断边界，不扩大为解析中所有位置、磁盘写入中或数据库提交中均已故障验证。

## 首次失败与修复分开记录

- 主链首先发现新 replay CLI 未接收 Worker 追加的 `--synthetic`；root 补齐明确 ack 且仍以 profile 来源声明核验。其间暴露旧 Docker 日志读取只返回 stdout、丢弃 stderr 的软件缺陷：本轮已合并并限制输出为 65,536 字节，private failure receipt 明确 compute_returncode 与输出流；容器随后清理导致的 Exit137不再被误当计算原始退出原因。新增回归和上述无效 PCAP 实测均证明 native2/原 stderr 被保留；[已去凭据的实测错误](validation-round18-service/lifecycle-first-native-failures-sanitized.json)可查。
- 生命周期第一次测试在有效的 queued/running cancel 之后，未等待既有一/二秒重试退避就再次 claim，把返回空误判为“wrong task”。只修测试等待 eligible claim，未改生产任务状态机或退避；[首次失败](validation-round18-service/lifecycle-first-failure.json)保留，第二个全新目录正式通过八项。
- 收尾独立检查发现最终 graph API 丢弃 envelope 后 `replay_version=null`，历史 snapshot 图不受影响。先增加回归复现 final 失败/snapshot 通过，再修为传递受信 envelope 精确版本，不猜默认值。见 [修复前](validation-round18-service/graph-envelope-before.log)、[修复后](validation-round18-service/graph-envelope-after.log)。主链在最终 Go 重启/恢复后另核对全部任务图版本；该 API 元数据修复不改变计算镜像或回放语义。
- 收尾范围复核发现仅支持 operation/change 无法查询未成为事件的触发证据。主链旧 Go listener 的真实历史快照 `trigger=true` 返回 409，见 [修复前原响应](validation-round18-service/trigger-before-old-go.json)。新增第三个受限选择器及到达前缀检查后，定向测试通过；计算产物生成和历史字节不变，主链另重建 Go 并核验同一历史请求及普通点击。
- 一次 fresh CLI 测试被本机端口绑定权限阻止，保留 [原日志](validation-round18-service/go-tests-local-port-blocked.jsonl)；获准使用本机测试端口后重新 fresh 执行通过，不把环境阻止算作软件通过。

## 实际构建与复现

上述生命周期通过时的 Go build info 为 `bc11e2838acc1a736b5de1e25419ba47891c430c`、`vcs.modified=true`，二进制 SHA 为 `61b3a816638a52cb0e576ad1df339d5fe947d16015a8d401f5a01a49cd6ece12`；不是声称该父提交已包含全部未提交服务代码。[原始 build info](validation-round18-service/lifecycle-go-build-identity.txt)保留。

实际镜像为 `sha256:39341e7b05dd22aaeb2606cc4742e408467be3c528df1c27970ccb504be69d99`；从该不可变镜像核出的代码/Schema 清单指纹为 `21769a26a461dc546584e7b0ab65e648fa22f34fdfc1184a1fabe7e9e5d9048c`，见 [逐文件清单](validation-round18-service/lifecycle-image-source-manifest.json)。此局部镜像早于后续 metrics-only 汇总字段及 Go graph envelope/trigger 查询修复，故只用于上述未受影响的生命周期边界，不冒称最终版本全覆盖。最终 CI 默认重建当前镜像；脚本现会在构建前后核对 source manifest、记录二进制 VCS/modified 和不可变镜像内容指纹。

需要可用 Docker、锁定模块依赖及 Python 虚拟环境；实际 host 使用 Python 3.11、Go 1.26.5，本次 PostgreSQL 使用既有固定 digest 镜像。测试创建专属随机端口/数据库/目录，自动停止自己创建的进程和容器；含 token 的 claim/config/execution 原件只留 private 工作目录，不复制入公开证据。

```sh
# 首次或最终提交验收：默认构建本轮镜像。
PYTHONPATH=services/worker:services/analysis/src \
  .venv/bin/python scripts/validation/round18_lifecycle.py \
  --output /absolute/private/new-r18-lifecycle

# 只在已核对相同不可变镜像时复用；脚本仍记录镜像身份。
PYTHONPATH=services/worker:services/analysis/src \
  .venv/bin/python scripts/validation/round18_lifecycle.py \
  --output /absolute/private/new-r18-lifecycle-repeat --skip-image-build

GOCACHE=/tmp/cpag-go-build GOMODCACHE=/tmp/cpag-go-mod \
  go test -count=1 ./internal/jobapi ./internal/catalog ./internal/contracts ./internal/jobs ./cmd/cpagctl
```

最新 Go 逐项结果见 [日志](validation-round18-service/go-tests.jsonl)。worker/isolated/backup 的复现分别为 `python -m unittest discover -s tests/worker`、`tests/isolated`、`tests/backup`，使用上面的 PYTHONPATH。本页局部验收不代替主链正式历史查询/受控下载/权限/空库恢复、页面内容核验或最终准确 SHA 的完整 CI。

## 工作包状态

| 工作包 | 本轮限定增量与保留边界 |
|---|---|
| R09 / 任务与配置 | 显式回放模式、不可变版本绑定、原件与当前预检、历史读取已接入；完整任务/运维边界仍为部分完成，不把这一个故障窗口扩大为所有注入位置 |
| R10 / PG 与 Worker | 新 kind 真实隔离计算、取消/退出证明、租约失效与从头重试、旧 attempt fencing、幂等发布已实测；没有新状态机，生产部署/全故障矩阵/R21仍待完成 |
| R13 / 备份与恢复 | 新模式目录审计、版本和所有历史 JSONL、原件完整性已覆盖；真实空库新目录成套恢复以主链报告为准，通用历史迁移、活动热迁移和真实旧实例不因此关闭 |

结论仅适用于软件实现及生成样例工程验证。真实授权双源材料、现场映射/时钟依据、独立标注和真实历史实例仍是单列的外部材料缺口。

## 保留问题：私有旧 kind 的不合规新字段

仅限已持有 Worker 凭据的私有 M4 `POST /v1/jobs`：把一个原本合法的 legacy synthetic（`kind=""`）或 packet payload 增加非空 `replay_version="dual-source-replay-1"`，当前 `validPayload` 未在所有旧 kind 顶部统一拒绝，可能先入队。现有正常 Worker 对旧 kind 不生成该版本字段，后续 wrapper 版本校验会拒绝；没有公共 V3 正常回放成功发布绕过，公共 V3 的 old dual/replay kind 检查仍在。

后续接口加固的预期是：此不合规请求在入队前返回 4xx，无 job 或 binding；建议在私有隔离测试库复用合法旧 payload，仅增加该字段验证，不改旧合法请求的结果。本项按根任务裁定保留为私有无效请求的 fail-fast 缺口，列入 R09/R21 后续加固；不作为本轮合法公共回放路径的阻断，也不因此宣称整个 R09 完成。未继续扩大本轮 runtime 修改范围。
