# R19 容量审计与正式链路开发测量

基线：`402d0b0bc253e124d2b7bd7fba7d33d746dde851`；2026-10-27。此审计对应 `round19-plan-scenarios.md` 的性能预登记，不关闭 R19 容量项，也不改变旧版本语义。

**结论：容量扩展尚未实现，参考容量验收待办；现有正式 Worker 连 S100 稠密样例也未完成。** 本轮新增可复查环境门禁、原始稠密输入生成器和正式链路记录器。不能用通过这些记录器的单元测试、R18 倍速演示、旧 JSONL 基准或其他 CI 结果代替容量通过。

## 已观察环境与全部实际尝试

公开证据：`validation-round19/capacity-public-evidence.json` 和各尝试目录的 `public-summary.json`。摘要对白名单字段取值，移除 Worker token、Docker Config 环境、登录配置与数据库凭据；原始完整记录在下列本地私有目录保留，不能递归加入公开提交。

| 尝试 | 事实和结果 |
|---|---|
| `capacity-reference-probe-attempt1` | 默认参考门禁，进程权限无法读 `hw.memsize`/Docker socket；原始 stderr 保留，记录 `failed`，未启动 Worker。该次不能用来声称实际 Docker 不可用或内存不足。 |
| `capacity-dev-probe-attempt1` | 显式 `--dev-run`、可读硬件/Docker。主机 Darwin/arm64、10 CPU、17179869184 bytes RAM；Docker Desktop aarch64、10 CPU、8217448448 bytes RAM。`reference_accepted=false`。 |
| `capacity-reference-probe-attempt2` | 可读权限下重做默认参考门禁，保留硬件不匹配原因；参考 Ubuntu 24.04/x86_64/8 vCPU 环境不具备，SSD未证实，Docker 分配内存也小于拟设8GiB。第一份失败记录不覆盖。 |
| `capacity-S-offline-dev-attempt1` | 真实 PG、正式 API、登录、原始上传、预检、配置保存、排队、正式隔离 Worker。原始 PCAP 23424 bytes/200帧（100请求+100响应），CSV 3010 bytes/100逻辑数据行。三次自动 attempt 均 `compute_returncode=-9`；每份退出检查均 `OOMKilled=true`、ExitCode137。最终 `failed`；提交至失败终态110.603261秒。未产生已校验最终分析，不能称100操作处理成功。 |

S 样例运行使用现有镜像 `cpag-isolated:r18-acceptance`，镜像 ID `sha256:6a44c15c25f6c9e9040053735b190fa07e7d9b126b246ac80ef1095954979b55`。实际资源检查为0.5 CPU、268435456 bytes内存、swap合计同值、64 PIDs、120秒、输出tmpfs16MiB。三次失败原因和检查已保留，数据库已导出，临时数据库容器已停止清理，未调高旧配置重试。

完整私有记录根目录：

`/Users/nbtechx-pyf/Documents/ChatGPT/FYP/cpagx-go/docs/refactor/validation-round19/capacity-S-offline-dev-attempt1/`

其中 `control/jobs/8e4f65b41f466c83bd984cdf86698907/attempt-{1,2,3}.worker/` 保存 `failure.json`、`stopped-inspect.json`、退出凭据和输入；`database.sql`、`app-config.json`、`worker.json` 为私有证据。公开摘要保留其来源哈希与少量资源/错误字段，不复制凭据。

## 当前链路的实际限制

这些限制分布在入口、解析、执行、验证和查询；单改解析器参数或 Docker 内存无法扩展整条链路。

| 层 | 当前限制/成本 | 对候选容量的影响与必须联动的位置 |
|---|---|---|
| 原始上传 | `internal/catalog/datasets.go:uploadFile`：抓包每件64MiB、工艺每件8MiB；最多4网络文件由分析选择约束 | 上传上限不等于分析支持。分析还会在更小上限拒绝；须增加一致的总量/件数选择和+1测试。 |
| 配置 | catalog配置请求体65536 bytes；预检读取配置65536；jobapi请求体65536；profile上限65536 | M/L逐条到达配置远超64KiB。拟8MiB必须贯穿外层JSON请求封装、预检、存储、Worker快照、服务校验及恢复；只把profile本体设8MiB而外层请求同设8MiB仍有封装开销。 |
| 正式任务有效性 | `internal/jobapi/server.go:validPayload`：网络合计16MiB、工艺2MiB、配置64KiB；文件检查一般64MiB、manifest64KiB | 会先于128MiB/8MiB目标拒绝。64MiB通用文件检查也会挡大产物，必须按版本和角色分界。 |
| PCAP/多抓包 | `packet_envelope.Limits`：单件16MiB、10000帧、单帧262144 bytes；`CaptureSetLimits`：最多4件、合计16MiB/10000帧 | 新版本须显式单件64MiB、合计128MiB、总100000帧；单帧上限不能误当单文件上限。 |
| TCP/协议 | `packet_pipeline.StreamLimits`：128流；每流2048段、262144 bytes；2048 PDU；300秒捕获跨度；每次解析10秒 | 10000请求+响应可先撞段数、流字节、PDU及时间限制。需版本化流/段/字节/PDU总预算和独立处理deadline，保留畸形、重传、歧义边界。不能仅放宽帧总数。 |
| CSV | `ProcessLimits`：2MiB、1000逻辑行、16列；`dual_source._process`另有1000逻辑行检查 | 目标8MiB/10000逻辑行/16列必须两路一致；使用CSV逻辑行计数，不能以物理换行数或字节填充替代。 |
| 双源关联 | `dual_source._analyze_prepared`：100操作、10000候选；映射100、有限规则100、规则发现10000 | M1000/L10000必先撞100操作；目标10000操作、10000变化、100000候选须同时贯穿结果schema/执行限制声明/服务验证。 |
| 回放原始输入 | `replay_inputs.ReplayInputs`：合计11000已到达记录；硬限不能通过调用参数越过默认解析上限 | L网络请求响应+工艺行超过30000，须版本化总输入及活动缓冲的不同计数语义；不能丢原始记录或只保留新窗口冒充历史。 |
| 回放控制 | `ReplayProfile.schema.json`：buffer_seconds<=300、buffer_records<=11000、snapshots<=4096、revisions<=8192、output<=16MiB；`replay_export.execute`/Go序列校验<=22000步 | 除原上限不足，预登记22000步也与L密度冲突（见下）。Worker/Go/schema/查询/备份目录必须识别同一新版本。 |
| 隔离计算 | `DockerExecutor`默认120秒、0.5 CPU、256MiB、64PIDs；只读原始输入、无网络；service可选配置字段不支持新性能预算 | 目标4CPU/8GiB/1800秒尚不能通过service配置启用；现有路径没有拟6000 CPU秒硬限。不能把非隔离guardian的RLIMIT_CPU60秒误称正式容器CPU限制。 |
| 输出/磁盘交接 | 默认16MiB输出、/tmp18MiB、host预算1GiB、最低空闲64MiB；tar全量读内存、移交30秒；服务JSONL/总产物16MiB | 1GiB输出、临时/交接各4GiB及空闲8GiB尚未落地。需流式有界交接与全链deadline，不能将1GiB tar整份再复制进内存。多网络容量预留少算的独立缺陷已由主任务修复并留测试，不等于扩容完成。 |
| 服务历史校验 | Go snapshots4096、revisions8192、每份JSONL16MiB，`os.ReadFile`全读；多个API每次重新验证全套产物 | 即使Worker写出大产物，也不能被当前服务接受/查询。需版本绑定、有界分段/索引及损坏检测，不能跳过完整引用验证。 |
| 证据查询 | 当前没有拟100条/8MiB的统一输出预算；回放Python `_verify`每次重跑完整回放，服务也验证全历史/原始证据 | <=10秒尚无大规模证据。须在版本化的已验证索引上选择有界证据并处理超限；不得截断证据后暗示完整。 |

## 预登记算术修正，先于 L 执行

L10000请求操作配套10000响应帧及10000工艺数据行，再加CSV表头、EOF和控制步，现逐条输入需要至少30000条数据到达，生成器准确生成 **30004步**。原拟22000步无法容纳，不能用删除响应、减少CSV行或缩小L掩盖。

一次到达可能先发布超期窗口结算，再发布本次状态；还存在初态、EOF与收尾发布，快照数量并不严格等于到达步数。主任务在L实跑前将预登记补充为新版本候选 **40000到达步、45000快照、90000修订**；这是需要实现、设计校验与实测的预算，不是此审计宣称已经足够。尤其每条到达均触发窗口结算的最坏情况还可能先到45000快照上限，应明确失败，不能发表半产物。原始128MiB/10000逻辑记录/10000操作目标保持不降，输出1GiB门禁保持。

S原始生成尝试1的回放profile有 `buffer_seconds=3600`（超过旧schema300），此配置未执行回放，也未影响该次离线profile。已保留尝试1原件；生成器修为300并增加profile schema检查；`capacity-S-raw-attempt2`保留修正后的新原件。不能覆盖尝试1后把它说成原本有效。

## R18 前缀重算的结构性成本

`replay_export.execute`每条原始到达调用 `inputs.snapshot()`；`ReplayInputs.snapshot`重新组装已到达帧、重新做协议重组、重新拼接/解析工艺前缀并深复制。`ReplayCore._collect`又按获准引用调用一次 `frame_accessor.snapshot()`；每次consume的过期结算和新到达判断还会多次调用 `_judge()`。

`dual_source._analyze_prepared`对每个请求扫描网络回复、对操作扫描变化与候选；前缀不断增长时，逐步全量重算可把单步二次扫描再累计为更高阶总成本。`_publish`深复制全量analysis、计算指纹、提取引用、保留完整快照与修订；最后还为每个快照重建graph/events、一次拼接所有JSONL。快照和最终投影视图都计入输出/内存，不是只有原始输入大小。

此外 `replay_export._verify`调用 `execute(..., pace=False)`重放全部输入，再重建并比对每个语义产物。导出自检、Worker接收、发布恢复与Python证据查询会分别触发这类重算。不能把核心`runtime_metrics.elapsed_seconds`单独当成排队至可查询全链路耗时。

以上是代码审计推断；三次S100 OOM是直接实测证据。尚未做分配器剖析，不能将OOM唯一归因为某一处复制，也不能从一次失败外推已测M/L耗时。

## 可实施的版本化扩展顺序

1. 定义独立新分析/回放/资源profile版本和解析选择；旧版本schema、历史哈希、旧版读取与默认入口保持既有语义。把所有输入/配置/帧/行/操作/候选/历史/磁盘预算集中成显式不可变契约，服务端重新校验，不能由任意请求提升旧硬限。
2. 在输入层维护到达前缀与验证引用的增量状态，按流增量重组、按标签增量邻接，建立相关ID/资产/窗口索引；保留R18迟到、歧义、结算前缀和撤回语义。对小例和原R18逐步快照做等价回归。
3. 持久化可验证增量修订/必要检查点及历史索引；以新版本表达历史，避免每条到达留完整全量对象。原版完整快照格式不原地改写。恢复必须验证原始输入/配置/规则/产物绑定，不能凭缓存存在就放行。
4. service显式启用4CPU/8GiB/64PIDs/1800秒/6000CPU秒，按实际所有输入预留磁盘；落实4GiB临时/4GiB交接和至少8GiB空闲。流式写入/交接/验证、有界分页证据和超限失败均须到正式路径，保留原始失败凭据。
5. 给解析、关联、写盘、验证、排队/容器启动分别加非语义耗时和RSS/CPU/磁盘计量；这些目前缺少，记录器填null并说明，不编造阶段分解或把Docker CPU%当累计CPU秒、容器内存占用当进程RSS。
6. 完成同一提交/镜像/配置绑定的S/M/L离线及回放各3次和独立字节边界（4×32MiB合计128MiB、单件64MiB、CSV8MiB）；+1件/+1byte/+1逻辑行/输出超限必须在正式链路明确拒绝。当前生成器只提供稠密样例，不冒充这些字节边界。参考环境可用后执行完整验收，当前保持待办。

## 新增记录器的用法与验证边界

`scripts/validation/round19_scale_fixture.py --scale S|M|L --output <全新目录>` 只按字面协议生成原始PCAP、CSV与独立到达序列，无analysis/gold输入。每规模固定请求数=数据行数，响应另完整保留；每次生成拒绝覆盖旧目录。

`scripts/validation/round19_capacity.py --output <全新目录> --probe-only` 默认参考门禁；非参考环境必须明确 `--dev-run`。`--case-manifest <原始case.json> --image <已构建镜像>`走R16正式验收公用函数建立PG、迁移、应用、授权上传/预检、正式Worker，并保存逐阶段记录、状态、Docker资源采样、磁盘空闲、源/提交/镜像/配置哈希、全部失败。按完整原始引用核验结果，再查询证据；门禁失败不进入后续成功检查。该记录器一次仅跑一个样例，不自动证明其他Worker服务没有全站并发；全站最多1活动attempt仍需新版本系统约束和并发测试。

任何一次成功最多是单例测量，脚本始终 `reference_accepted=false`：完整矩阵、冷缓存依据、阶段RSS/CPU分解、边界与回归门禁仍需独立评审。第一次缓存条件在本机无法清缓存时仅记 `unverified_cold`，不能宣称验证了冷缓存；禁止用旧JSONL或R18倍速结果替代。

验证日志：`capacity-harness-tests-attempt1.log`（9项）、`attempt2.log`（11项）、`attempt3.log`及最终`attempt4.log`（均12项，含公开摘要去凭据与三规模生成密度/schema控制）。这些是记录器/样例生成控制，不是容量通过。
