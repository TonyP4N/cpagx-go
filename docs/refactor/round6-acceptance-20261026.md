# 第六轮稳定性收尾验收

## 范围与基线

基线 `2f08784e153a0b614d9b4b0b941e51e5b63e197b`；核查时HEAD一致、工作区干净。分支 `refactor/m1-evidence-core`。保留第五轮成果及其九项CI成功记录，同时补记覆盖缺口。默认入口不变；没有新增协议、网页或回放功能。

本轮验收对象是现有合成核心、兼容Worker、opt-in隔离执行器、任务API/历史与备份恢复。真实工业数据验证、生产部署验收和软件故障验证分别判断。以下证据均在 `validation-round6/`；专属报告说明实际进程/容器测试和mock、故障注入的区别。

## 已发现并修复的问题

| 编号 | 复现及影响 | 修复与回归证据 |
|---|---|---|
| S01 | 恢复扫描遇到缺容器、损坏JSON或其他daemon直接抛异常，后续任务未处理 | 单job/attempt诊断后继续；全局依赖失败明确重试。`recovery-reproduction.log`、`recovery-unit.log`、实际`isolated-integration.log`及`mixed-recovery-outcomes.json` |
| S02 | 兼容Worker重复attempt因目录已存在发fail；隔离执行器在execution写入前也有同类并发窗口 | 兼容目录冲突不发终态；隔离attempt独占锁阻止第二控制器执行/释放预算。`legacy-before.jsonl`、`worker-regression.log`、`isolated-duplicate-before/after.json`。容量提前释放是在本轮新增预算实现的交叉复核中发现并修复 |
| S03 | 兼容Worker complete响应丢失后又发fail；CLI依赖不可用静默退出0 | 模糊完成保留产物、返回publication_pending；依赖失败结构化报告并退出75。隔离完成响应/本地marker失败保留handoff，不反写失败。`legacy-before.jsonl`、`worker-regression.log`、`isolated-integration.log` |
| S04 | 取消已完成但ACK响应丢失，再次ACK返回409 | 同attempt/token且退出证明齐备时幂等；旧token仍拒绝。`history-postgres.log`以真实PG+基线SQL复现原行为，不冒充运行旧完整binary |
| S05 | Go恢复将RecordExit数据库错误当单条无效证明吞掉 | 无效/缺失/坏路径证明逐项持久诊断；真实DB故障使整轮失败并重试。实际ELOOP坏记录后好记录仍处理；`history-postgres.log`、`database-outage.log` |
| S06 | create成功但登记未完成、领取响应丢失或容量拒绝后，缺乏未启动的取消依据 | 创建前持久intent+nonce，Docker/DB自动发现；isolated-v2领取同事务记执行类型和位置，数据库串行撤销未登记启动权限，产生明确not-started证明；登记先赢则必须真实退出。`history-postgres.log`、`isolated-integration.log` |
| S07 | 容器已移除而退出回执尚未落盘时中断，无法常规恢复 | 先持久停止检查和移除intent，再移除；恢复可核验同ID/标签Docker destroy事件后补回执。实际before/after_remove硬退出通过；完全失去这些依据时仍pending，见剩余边界 |
| S08 | 主机产物无协作容量上限；预算实现早期在ledger遗失、只有inputs/intent时漏计占用 | 同root/control文件锁预算、输入及产物预留、两目录文件系统最低空闲；遗失/损坏ledger禁止继续领取占用。`recovery-unit.log`、`isolated-capacity-missing-ledger-before/after.json`，实际容量拒绝和ENOSPC场景见隔离日志 |
| S09 | 损坏本地执行记录中的路径身份未经校验可引发jobs目录外读取尝试 | 校验身份、正attempt及文件所在路径一致，先拒绝再访问API/文件。`isolated-path-before/after.json`使用真实文件和mock API/Docker；不宣称真实服务可被绕过 |
| S10 | 备份缺目录/缺必需输入可误报valid；坏job/history中断后续审计 | 严格完整目录遍历，全部终态必需输入引用；逐项记录错误并继续。`backup-before.json`、`backup-after.json`、真实混合审计JSON |
| S11 | 并发恢复覆盖先前验收报告；初审后文件变化仍可生成无效但标成功的bundle | 独占报告保留、原子写报告；复制后重审引用，dump后源/目标inventory再核验，仅最终发布有效bundle标记。`backup-before-concurrent-restore.json`、`backup-before-file-database-race.json`、`backup-tests.log`、实际重复恢复记录 |

备份两项竞态的基线精确时序使用真实文件/线程并mock数据库调用，真实数据库集成另行验证最终路径。未填满用户宿主磁盘：宿主ENOSPC为明确注入；计算容器tmpfs满为实际发生。

## 完整流程验收矩阵

| 触发条件 | 预期行为 | 方法与证据 | 结果 |
|---|---|---|---|
| 正常领取→计算→交接→发布→查询 | 校验后才成功，原始证据可回溯 | 实际Docker/API/PG隔离日志；独立backup restore后字段查询 | 通过 |
| create后、登记前、start前硬退出 | 可发现准确身份；无部分成功，不可跨attempt发布 | 隔离日志after_create/before_register/before_start | 通过 |
| 领取响应丢失、无本地目录 | DB自动发现，撤销未启动权限后取消收敛 | 实际claim丢弃、discovery、not-started、cancel；PG注册/撤销并发 | 通过 |
| 容量拒绝，计算尚未创建 | 无假退出证明；撤销start gate，延迟登记拒绝 | 隔离实际容量拒绝与取消场景 | 通过 |
| 计算中失联/取消/租约过期及后续attempt启动 | 全部相关执行退出才取消，旧attempt禁止发布 | 实际双attempt/API与恢复器OS进程重启 | 通过 |
| 停止/移除前后硬退出 | 依已持久停止intent和真实destroy事件补证明 | before_remove/after_remove | 通过；缺事件须pending |
| 交接中、复制后、发布后中断 | 无部分成功，完整持久产物可核验恢复 | during_copy/after_copy/after_publish；哈希与原始抓包重解码 | 通过 |
| 第一个缺容器、后续坏记录、异daemon，再有好任务 | 逐项报告，重复扫描后续任务不饥饿 | 混合单元+实际Docker repeated scans，mixed-recovery-outcomes.json | 通过 |
| API/协调器连接中断 | 整轮明确失败、重试，恢复后继续 | 实际连接失效/恢复；兼容API进程终止测试 | 通过 |
| 数据库暂停或停止 | 不当作单条坏数据；进程保持重试，恢复后继续 | 独立真实PG pause/stop/start、Go恢复器重启，无新claim | 通过 |
| Docker连接暂时不可用 | 全局retry结果；恢复连接后重新扫描 | 实际Docker客户端指向不可达socket，再恢复 | 通过；不是Docker daemon崩溃试验 |
| 同attempt并发/重复ACK/重复完成 | 不扰动活跃owner、不改变既有终态 | 真实线程/文件锁、PG幂等与竞态、实际HTTP完成重试 | 通过 |
| complete响应丢失、成功后本地marker写失败 | 不反写fail，保留可核验handoff | 隔离实际API提交后注入回包丢失/marker写失败 | 通过 |
| 计算tmpfs满、宿主预算/最低空闲不足、handoff ENOSPC | 拒绝或明确失败，不发布不完整目录 | 实际tmpfs；预算回归；注入宿主ENOSPC | 通过限定方法 |
| ledger缺失/损坏、进程重启和并发预留 | 不清零活跃预算、不绕过占用约束 | recovery-unit、独立before/after重放 | 通过；丢ledger需修复后继续接单 |
| 缺文件、篡改、DB/文件不一致、孤儿文件 | 明确错误；孤儿保留并报告 | 独立DB/目录restore和packet证据query负例 | 通过 |
| 未启动撤销证明的备份恢复 | executor/location/revocation/identity保持一致 | 真实isolated-v2 cancelled任务恢复，summary字段true | 通过 |
| 混合坏/好备份记录、重复及并发restore | 不隐藏后续诊断、不覆盖已存在目标或终态报告 | backup单元+实际重复恢复、DB行内容比较 | 通过 |
| 升级前bare-daemon本地执行记录 | 在同control精确身份下仍可收尾，拒其他daemon/scope | 实际旧location兼容取消场景 | 通过 |
| 默认旧入口/原核心回归 | 默认不切换、现有测试无回退 | Go测试/build/vet，core/parser/packet/legacy/service/网页/回放回归及CI | 本地及远端通过 |

## 单机支持范围与仍未解决边界

- 支持同一Linux Docker daemon、固定共享根和控制根，单机协作执行器；新位置标识含root/control范围。自动发现只处理本作用域，保留已知本地旧bare-daemon记录兼容。没有扩展跨主机能力。切换路径/daemon必须按迁移处理，不能冒认旧执行身份。
- 独立恢复可周期运行；全局依赖失败退出码75/重试，单项pending退出码2。默认隔离Worker租约15秒、心跳1秒、计算墙钟120秒；API调用3秒、单次Docker命令30秒。Go恢复器每1秒触发、每轮数据库上下文10秒；Python恢复以显式`--recovery-interval 5`配置为例，上一轮结束后5秒重试。识别界限为租约到期加调度间隔和本轮扫描耗时，不宣称固定5秒完成全部回收。操作说明见[隔离收尾说明](round6-isolated-stability.md)。不能保证阻塞内核文件I/O或无限历史规模下的固定整轮时限。
- 缺容器且没有可信退出回执、停止intent和可核验destroy事件时，仍保留pending。事件历史被淘汰、daemon重启造成事件丢失、控制证据同时损坏时不能自动编造证明，须恢复证据或人工核查。旧legacy未登记执行不套用not-started规则。
- 容量是受控root/control内合作执行器的预算及最低空闲约束，保护预留与交接；不等同于OS磁盘配额，不能限制其他程序、Docker镜像库或宿主root写入。满盘的错误路径已测；宿主断电、内核/daemon崩溃、全部控制存储丢失未作生产级验证。
- 备份支持静止终态任务及当前版本成套恢复，不支持活动任务继续运行、PITR、跨版本生产恢复。失败目标保留诊断，不自动删除或覆盖。丢失容量账本时拒绝新占用，账本重建/管理员修复工具仍待实施。
- 新旧执行器全部任务类型的产物一致性、完整生产迁移/回滚、离线安装仍未验收；默认入口继续保留。对已知覆盖范围之外不宣称没有问题。

## 对照原方案退出条件

| 阶段 | 当前状态 | 已满足 / 未满足 |
|---|---|---|
| M0 | 部分完成 | 有精确基线、启动/故障/来源记录；干净目标环境整套安装仍待验收 |
| M1 | 已完成既定骨架范围 | 标准契约、纯核心、合成样例与可追溯输出已有回归；不包含真实验证 |
| M2 | 部分完成，真实验收受阻 | 已有有限解析/证据；真实字段、设备映射、时间对齐未核验，本轮未扩协议 |
| M3 | 部分完成，真实验收受阻 | 已有协议观测图和查询；正常与攻击区间独立复核、双源算法退出条件未满足 |
| M4 | 部分完成 | 本轮收敛恢复、未启动证明、交接和故障矩阵；全旧任务一致性、生产迁移和剩余运行边界仍未满足，不能切默认 |
| M5 | 部分完成，正式评估受阻 | 保留已有回放骨架；本轮冻结功能，完整回放/保留测试集/正式效果与性能评估未完成 |
| M6 | 部分完成 | 成套备份恢复与证据重查通过；离线包、干净安装及发布候选综合验收仍未完成 |

| 工作包 | 状态 | 退出依据或剩余条件 |
|---|---|---|
| R01 | 部分完成 | 基线和启动日志具备；干净安装尚缺 |
| R02 | 已完成明确最小范围 | 不支持路径明确拒绝，不制造事件；既有回归保留 |
| R03 | 已完成当前核心契约范围 | 双语言契约回归；新增任务历史字段及证明有API/PG/备份核验 |
| R04 | 已完成既定纯核心范围 | 无队列/数据库核心运行回归 |
| R05 | 部分完成 | 解析软件测试保留；真实字段核验受阻 |
| R06 | 部分完成 | 批次配置保留；真实时间/单位/设备映射受阻 |
| R07 | 部分完成 | 观测关联语义保留；跨源推断/反证未完成 |
| R08 | 部分完成，受阻 | 缺独立标注、保留测试集和正式评估材料 |
| R09 | 部分完成 | 并发/取消/恢复收尾通过限定矩阵；默认应用仍保留兼容 |
| R10 | 部分完成 | 新持久执行链路已测；全部旧任务产物一致性仍待验收 |
| R11 | 部分完成 | 原证据界面仅回归，不新增；正式鉴权/任务导航/双源时间线未完成 |
| R12 | 部分完成 | 原顺序回放骨架仅回归；完整任务和持久回放未完成 |
| R13 | 部分完成 | CI、资源预算、故障/备份记录；离线安装与生产回滚未完成 |

## 材料、决定与后续

本轮工程修复无需用户追加材料或降低标准。真实验证仍需同一授权批次PCAP/PCAPNG、同期工艺CSV/Excel、文件清单与哈希/使用条件、设备/IP/标签与字段单位映射、时区及同步依据、正式攻击记录与独立标注/保留集。公开规则不能当独立标准答案。

在不扩功能前提下，后续应针对剩余控制证据丢失的运维处置、容量账本重建、全部旧任务一致性及离线安装/迁移回滚建立专项验收。未具备证据时保持受阻或部分完成，不改写为阶段完成。

## 最终提交与CI

本地共143项Python测试通过（含16项隔离恢复、20项备份及14项兼容Worker测试）；Go全仓test/build/vet通过。实际PostgreSQL竞态、独立恢复器数据库故障/重启、兼容Worker/API中断、隔离容器完整矩阵及独立数据库成套恢复均通过。日志去除了行尾空白，测试结果未改写。功能与验收代码提交：`61d22b5e386b6254e7e5eb949924c222f72afa97`，已推送原分支。

[远端CI 40216400959](https://github.com/TonyP4N/cpagx-go/actions/runs/40216400959) 九项全部success：core、go、frontend、service-regression、m4-postgres-prototype、m4-worker-integration、linux-isolation、backup-restore、isolated-executor。不可变headSha和各job链接见 `validation-round6/ci.json`。本条是CI完成后的文档补记，不改变已验代码。
