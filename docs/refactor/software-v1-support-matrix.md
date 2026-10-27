# 软件首版支持矩阵（R15 范围决定 v1）

基线：`refactor/m1-evidence-core`，`a7171ba23c23a698afdfb5ea9e58031b24e1cc49`。依据为[原方案](CPAG_系统化重构方案_v1.0.md) §§1.2、3、5、8、12—13、工作区 `outputs/CPAG_软件重构收尾路线图_20261027.md` 及该提交源码；这是 R15 决策清单，不是新增实现验收。以下“现有”仅表示源码或既有固定提交的合成工程证据；“承诺”须在 R16—R22 实现、预登记并验证后才成立。

## 三种状态与目标架构

每项分别报告 **软件实现 / 合成工程验收 / 真实数据验收**，不得合并。现有第十四轮合成双源、持久 Worker、取消和终态恢复证据见 [round14 验收](round14-acceptance-20261027.md)及 `validation-round14/`，提交固定为本页基线；RC1 仍是 `49e9985`，归档 SHA-256 为 `c199dd417e1c59c55563c5535e32d26197b164c95ae17c0ef3bb621f7228b49e`。最终 CI `40440173011` 的 15 项成功属于该基线，不替代未来版本验收。

目标基础部署：同一 Go 进程在 `127.0.0.1` 提供公共 API 与静态前端，并以**独立的仅 loopback 内部监听器**保留 M4 Worker 协调接口；Python Worker/子进程负责解析、关联、回放及评估计算，不能通过公共路由领取内部任务；PostgreSQL 保存数据集、文件、版本配置、运行绑定、用户、会话、ACL、审计及任务元数据；受控本地文件保存原件与不可变产物。局域网模式如承诺，必须经明确 TLS/权限部署，不能沿用 loopback 假设。Neo4j、Celery/RabbitMQ/Redis、InfluxDB、Flower 可作为兼容/可选路径，不是新主流程常驻依赖。`api/`、`internal/jobapi/`、`services/worker/`、`services/analysis/`、`webui/` 是当前分散入口；R16 固定单一外部服务契约及兼容适配，R21 实测三服务基础部署。新增常驻组件须记录 ADR、职责、成本和不可替代理由。

| 维度 | `a7171ba` 可证实范围 | 软件首版待定/退出门槛 | 真实验收 |
|---|---|---|---|
| 环境 | macOS arm64、Linux/aarch64 工程记录；Linux/amd64 CI 及合成基准；RC1 已冻结 | **首验目标 Ubuntu 24.04 LTS x86_64**（R22 需锁定镜像/内核/容器版本）在干净机器、无依赖/镜像缓存、断公网完成新包安装、流程、备份、升级/回滚。其他 Linux 发行版与 macOS/arm64 为未承诺或另列实验性；旧 Celery 冷启动若落在承诺兼容入口须复现定位（R21） | 工厂现场条件另验 |
| 运行 | 双源现有 opt-in 离线 CLI、Celery、PG/Worker 与页面桥接；`replay.py` 仅 arrival-driven 骨架 | R16 统一入口，并可接收真实单源/双源文件及完成**元数据、完整性预检**，状态为 `accepted_unvalidated`；当前核心要求 `synthetic=True`，真实输入不得绕开该门槛或调用核心宣称分析成功，R17 负责真实输入可解析的软件路径。R18 实现真正输入增量的双源顺序回放并接持久任务；R21 不启动旧队列也可全流程 | 真实双源离线/连续表现待数据 |
| PCAP 容器/链路 | `parsers/packet_envelope.py`：经典 PCAP 2.4（两端序、微秒/纳秒）和严格 PCAPNG 单 section/单 interface 的 SHB/IDB/EPB 子集；仅 Ethernet linktype 1、IPv4/TCP。未知/选项/损坏明确失败；`packet_pipeline.py` 为另一有界解析路径。 | R17 先固定承诺容器、链路、分段/重传/乱序/跨文件行为和独立字节参考。未列项明确 unsupported，不能生成替代事件；多文件若承诺须保持会话/重组边界。 | 真实抓包链路、覆盖和字段待授权样本 |
| ENIP/CPF/CIP | `parsers/packet_protocol.py` 合成 opt-in：TCP 44818、单 TCP payload 完整 `SendRRData` (`0x006f`)、空 address + `0xb2` unconnected data、CIP `0x0e` Read Attribute 与 `0x10` Write Attribute，8 位 class/instance/attribute 路径；状态、原始 data_hex、唯一匹配/歧义。该适配器**没有 TCP 流重组，也不发 NetworkEvent**。`packet_pipeline.py` 是有界网络事件路径；`dual_source.py` 对 write 精确规则构造候选。 | R17 对完整服务入口明确最终采用哪个解析器及其操作子集，逐项验证字节、请求/响应、截断、无响应、重复、重传、分段、乱序。未知服务和不支持布局保留原因；不声称全 CIP、数值语义或物理执行。 | 服务/路径/数据类型、字节序、设备语义待现场字典与真实样本 |
| 工艺输入 | `parsers/__init__.py`：显式列定义的 CSV 逻辑记录，保留原时间、列、缺失与质量；`dual_source.py` 使用相邻有效采样产生变化，不插值。`intake.py` 允许 `.csv/.xls/.xlsx` 作**接收预检类型**，后两者尚非分析解析格式。 | R16 接收与转换来源链；R17 固定 CSV 编码、字段/时间/单位/状态、重复与缺测规则。Excel 若首版承诺，须可追溯转换并验收，否则标“接收待转换，不能直接运行”。状态变化、阈值、有限工艺约束规则均须有版本、参数、反证及受控运算。 | 真实列名、单位、状态字典、阈值/工况待批次依据 |
| 合成 JSONL 与历史格式 | `parsers/__init__.py` 只在明确 `synthetic=True` 时接收规范化 `.jsonl`；`scripts/validation/round8_compatibility.py` 只读核查两种 **synthetic schema 1.0.0** 历史形态。本表称 `core_v1`（脚本参数 `kind=normalized`：`dataset/events/graph/quality/run_manifest.json`）和 `packet_v1`（`kind=packet`：再加 `packet_observations.json`），均要求原 network/process 文件及哈希；名称是矩阵别名，实际脚本参数为 normalized/packet。round14 双源是另一个 11 文件标准导出，见 `internal/jobapi/dual.go:dualFiles`，不自动等于旧历史格式。 | 保留合成 JSONL 回归入口；R21 对已列两种格式及 11 文件导出做只读/下载/完整性适配，旧 V1/V2 API 路由逐项登记。未知旧 JSON/JSONL、真实旧任务和任意中间文件明确拒绝或由旧环境只读；不能许诺通用历史兼容。 | 真实历史实例另需原任务/配置/原件/产物及必要图导出 |
| 时间/身份 | `dual_source.py` 保留原始引用、按有依据的 offset 与 uncertainty 关联；`intake.py` 只检查材料完整性；缺映射/冲突保留 unknown/ambiguous | R17 明确 offset、drift、精度、有效期及多义映射；无依据禁跨源关联；旧运行绑定原版本 | 真实时区、同步、设备 IP/CIP/tag 映射待核 |
| 证据/图/界面 | 标准 schema、候选/支持/反证/未知、原始帧与 CSV 证据查询、显式双源页已有合成验收；见 round12—14 | R20 数据集/任务/分析/回放/评估全页；默认子图以原方案最多 1000 节点/3000 边作交互测试上限，底层证据不裁掉。R22 全部发布引用可解析 | 真实正常/攻击区间独立复核待数据 |
| 数据治理/历史 | `intake.py` 有完整性/来源预检；round14 终态备份含 PG 与原件；尚无完整数据集目录、权限、审计、真实历史实例证据 | R16 原件哈希、来源、版本、运行引用、服务端角色与审计；R21 只读支持的旧格式、明确拒绝未知格式、维护停写与恢复。历史**格式**可用构造夹具验证；实际旧实例另列待材料。 | 历史实例缺失与工业双源缺失分开 |
| 容量 | 当前代码：抓包 16 MiB/10,000 帧/单帧 256 KiB；双源 CSV 2 MiB、配置 64 KiB、逻辑记录 1000、列 16、操作/映射规则 100、候选 10,000（`packet_envelope.py`、`dual_source.py`）。Go 服务也有 16 MiB 输入约束。当前普通 host Worker `worker.py` 默认 1 GiB 内存、64 MiB 文件、60 CPU 秒、120 秒墙钟、stdout/stderr 各 64 KiB；隔离 `isolated.py` 为 256 MiB memory/swap、0.5 CPU、64 PIDs、16 MiB 输出 tmpfs 加 dual 专用有界 `/tmp`、120 秒墙钟、宿主交接预算 1 GiB/最少剩余 64 MiB，见 [一致性记录](round7-support-consistency.md)、[round14](round14-acceptance-20261027.md)。这些限制与候选首版容量不兼容，须 R19 同步改并验，不能只调上传阈值。合成 5000 条/源基准属另一核心测试，不证明双源服务支持 5000。 | **首版候选容量决定**：单次数据集最多 4 个 PCAP/PCAPNG，每件最多 64 MiB、合计最多 128 MiB；工艺 CSV 合计最多 8 MiB / 10,000 逻辑记录，最多 16 列；全站同时最多 1 个活动分析 attempt，输出和查询仍须设明确上限。此为有界研究版验收目标，选 4 件检验跨文件会话、较开发限额有实际扩展，同时保持单机/有限并发；并非已测性能或工业容量承诺。R17 实现流式/有界多文件路径。R19 在测试前固定 8 vCPU/16 GiB/SSD 参考环境、容器 CPU/RAM/磁盘配额、输入构造、候选/输出/查询上限与时限，完整双源和回放各三次，报告耗时、RSS/CPU/磁盘、积压及所有失败；超限明确失败且无可信半产物。达不到则优化，或显式批准新的有限首版容量，不得默默退回当前 16 MiB/1000 行。 | 真实规模及生产吞吐待样本/现场验收 |

## 范围边界与决定记录

首版为单站点、单机、有限并发、离线与顺序回放。维护停写且任务终态后的成套备份是必需；运行中一致性快照、原地续算、活动任务热迁移、跨主机执行、整机迁移、任意旧版本兼容、所有中间文件迁移、全工业协议/全 CIP、无上限大图和生产默认切换不作门槛。此边界不删原方案包含的回放、规则、UI、独立评估及运维。若调整原方案既有能力，须单独记录范围变更与批准依据；不得以矩阵空白默认为完成。
