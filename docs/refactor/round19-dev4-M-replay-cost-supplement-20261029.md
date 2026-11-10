# R19 dev4 M replay 终态成本补充（partial）

本补充只读整理 `outputs/cpag-r19-core-matrix-dev4-M-replay-attempt1` 已有终态记录，保留此前[三格成本归因](round19-dev4-cost-attribution-20261029.md)及原始矩阵不变；没有重跑、打开源数据库或修改运行代码。结构化原值、源文件 SHA256、固定输入/镜像/运行代码 SHA 及复制一致性记录见[补充 JSON](validation-round19-dev4-cost-attribution/dev4-M-replay-supplement.json)。本次仍是开发环境核心层单次记录，瓶颈未全解，不能代替完整矩阵或验收。

## 终态与时钟

**M replay 在导出阶段 deadline 失败，未进入完整来源核验或查询。** 固定镜像 `eb80e205…615f8c`，generator6 / `phase-resources-3`；额度仍为4 CPU、8 GiB内存、4 GiB临时空间、完整输出1 GiB、全链1800秒，查询10秒/8 MiB/100项。

| 观察项 | 实测值 | 范围/解释 |
| --- | ---: | --- |
| controller 全链 | 1800.945449 s | 包含失败收件与保留交接 |
| 导出 controller | 1800.578495 s | 容器阶段及控制器生命周期 |
| 导出 native | 1799.929907 s | 模块首段开始，含导入/参数处理等，排除解释器执行首段代码前的启动 |
| 导出进程 CPU | 1555.353146 s | native packet 的进程统计 |
| cgroup CPU usage | 1606.877116 s | 容器从创建至最终报告，含采样 exec，不能等同进程 CPU |
| 完整来源核验 / 冷查询 / 重复查询 | null / null / null | 导出失败后未到达，无对应 result packet |

controller 与 native 的差值未被单独分解，不能直接归因为 I/O。容器终态 `exited`、`ExitCode=1`、`Running=false`，`OOMKilled=false`；cgroup `nr_throttled=0`、`throttled_usec=0`。这些记录不支持将此次失败归为 OOM 或配额节流，也不能证明已充分使用全部4 CPU。

| 内存项 | 字节 | 范围 |
| --- | ---: | --- |
| 进程 RSS high-water | 91,971,584 | 进程累计高水位，不是某阶段增量 |
| cgroup memory peak | 194,269,184 | 容器记账峰值，包含与 RSS 不同的成本 |
| cgroup current（最终报告时） | 59,445,248 | 报告时当前值，不是峰值 |
| 内存限额 | 8,589,934,592 | 固定额度未扩大 |

两种内存口径不可相减后宣称缓存或泄漏；最终协议序列化/退出不在 cgroup packet 的声明范围内。

## 失败前的阶段成本与进度

下列均为**嵌套调用累计跨度，互相重叠，不得相加或作为互斥占比**。`standard_projection` 含存储 identity callback；不能拿旧 dev3 的另一口径直接宣称算法变慢。

| 阶段 | wall s | CPU s | calls / returned / failed |
| --- | ---: | ---: | ---: |
| complete_export | 1799.631939 | 1555.039630 | 1 / 0 / 1 |
| history_generation | 1214.852144 | 970.628465 | 372 / 371 / 1 |
| compact_store_write | 1042.887116 | 798.809359 | 4834 / 4833 / 1 |
| association_and_evidence | 495.782898 | 495.514558 | 372 / 372 / 0 |
| standard_projection | 300.437397 | 236.718520 | 372 / 372 / 0 |
| stored_graph_composition_1 | 324.443955 | 255.138849 | 372 / 372 / 0 |
| replay_input_snapshot | 16.072199 | 16.021415 | 742 / 742 / 0 |
| replay_network_prefix | 5.718535 | 5.689061 | 742 / 742 / 0 |
| replay_process_prefix | 0.183606 | 0.179414 | 742 / 742 / 0 |
| network_parse | 3.446357 | 3.424689 | 273 / 273 / 0 |
| process_parse | 0.006608 | 0.006280 | 99 / 99 / 0 |

`association_and_evidence` 是判断与证据组织等合并段，独立规则判断/独立证据组织耗时仍为 null。当前记录显示历史生成、存储及合并关联/投影仍有显著开销，不能将主要成本归给只有几秒的原始解析；各段没有独立因果实验，不能再细分或承诺优化收益。

测量终态汇总观察到8921个完成的装饰器调用，保留256条原始行，其余8665条按既定策略只进汇总；362次持久进度写入、0次写入失败。最后 `progress.json` 仍标 `in_progress` / `terminal=false`，这是最后完成调用的检查点，不代表容器仍运行。终态由汇总、失败 packet 与容器退出共同确认。371次正常 history 返回不是最终快照数，也不能除以预检到达数算完成率；最终快照/到达/候选数量均未取得。

## 失败位置、残留与未测范围

traceback 定位 `compact_replay._publish` 的 `revision_ref=writer.intern(revision)`，经 typed 节点写入到 `_deadline` 抛出 `ValueError:shared_store_deadline_exceeded`。`FAILED.json` 明确 `trusted_result=false`。这是修订对象存储期间的 deadline 失败；没有记录 `SQLITE_FULL`，不能改写为磁盘失败。控制器通用 `complete_chain_time_or_output_budget_including_handoff` 标签并不单独证明输出超限。

保留的 partial artifact 共 **84,640,132字节**，其中 SQLite为84,094,976字节，其余为原件/profile与失败标记；没有 `run_manifest.json` 或 `shared/manifest.json`，所以完整 artifact 字节数为 **null**，这些部分文件不能当作容量通过。完整 attempt（含脚本/测量）85,697,629字节，另有同量交接副本，合计保留171,395,258字节；复制失败残留的状态为 `complete_bytes_verified`，只说明该副本保留通过，不说明计算成功。报告明确 bind mount 没有独立文件系统大小 quota，完整输出仍由原生预算和最终/采样检查约束。

本次未到达完整节点核验、source Merkle重建或查询。完整来源策略虽已去掉第二份 SQLite，仍须重算全部业务与历史根；不能拿“无副库”宣称核验成本已解，本格也没有该阶段的实际成本。此前 M offline 完整 artifact **100,668,118字节**仍是另一格实测，不可代替 M replay。旧平铺 M 的1,795,907,870字节只是数学下界，并非旧产物实测。本补充不外推 L，不判断服务、Worker、备份、参考硬件或工业数据验收。

## 来源与保留

原始 `report.json`、`export-result.json`、traceback、phases、progress、失败标记和三件输入逐件记录 SHA256；与 `/private/tmp/cpag-r19-core-matrix-dev4-M-replay-attempt1-20261028` 对应小文件的 SHA 一致。源记录与旧归因两件 SHA 在生成补充后复核未变；未读取84 MB数据库内容。JSON保留完整 runtime 哈希表、输入哈希及预检声明，原始记录本身未复制改写到本目录。
