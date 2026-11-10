# R19 dev4 L offline 终态成本补充（partial）

只读整理 `outputs/cpag-r19-core-matrix-dev4-L-offline-attempt1` 的终态记录；没有重跑、操作容器、打开SQLite或修改原始材料。保留此前[三格归因](round19-dev4-cost-attribution-20261029.md)及[M replay补充](round19-dev4-M-replay-cost-supplement-20261029.md)。原值、源/输入/镜像/代码SHA及复制校验见[新增JSON](validation-round19-dev4-cost-attribution/dev4-L-offline-supplement.json)。本格失败，核心层瓶颈仍未全解。

## 终态更正与已测范围

**L offline全链1802.076417秒失败；关联合并段实际已正常返回，不能沿用早期“关联无返回”的推测。** `association_and_evidence` returned=1、wall1711.233803秒、CPU1710.355197秒；`offline_analysis`也returned=1、wall1776.362178秒。随后第一次 `writer.add('analysis.json',analysis)` 在22.879863秒的写入尝试中触发deadline，未形成完整产物。

固定镜像 `eb80e205…615f8c`、generator6、`phase-resources-3`，限额保持4 CPU / 8 GiB内存 / 4 GiB临时空间 / 完整输出1 GiB / 全链1800秒，查询10秒/8 MiB/100项。此次没有收集到 `export-result.json`，所以**完整native模块时长/CPU为null**，不能把下表中装饰器跨度改名为native packet。

| 实测范围 | wall s | CPU s | 返回状态 |
| --- | ---: | ---: | --- |
| controller全链（含失败保留交接） | 1802.076417 | null | failed |
| export controller阶段 | 1801.526539 | null | failed |
| complete_export装饰器 | 1799.293483 | 1796.976042 | failed，非成功完整导出成本 |
| network_parse | 64.772704 | 64.737694 | returned |
| process_parse | 0.069659 | 0.069435 | returned |
| association_and_evidence | 1711.233803 | 1710.355197 | returned |
| offline_analysis | 1776.362178 | 1775.444632 | returned |
| compact_store_write | 22.879863 | 21.509073 | failed，仅失败前尝试成本 |
| 完整存储 / 标准投影 / 节点核验 | null | null | 未完成或未到达 |
| 完整来源重建 / 冷查询 / 重复查询 | null | null | 导出失败后未到达 |

这些是嵌套累计跨度，**不能相加、堆叠或作为互斥占比**。`association_and_evidence`合并判断与证据组织等成本，独立规则/独立证据耗时仍为null。解析和关联已返回，关联合并段耗时显著且CPU接近wall；这支持将本格的主要已测成本定位于该合并业务段，却不能细分到某个内部算法、数据库吞吐或证据单项。失败的22.88秒写入并非完整存储耗时，不能据此预测若延长时限后的总成本。

## 退出、OOM与资源口径

控制器记录 `TimeoutError:core_chain_1800_seconds`，冻结的controller代码在到达总deadline时抛出，finally中对仍运行的容器执行kill清理。容器终态 `exited`、`Running=false`、`ExitCode=137`，但 **`OOMKilled=false`**。退出137不能单独当作OOM证据。原生traceback与 `FAILED.json` 另外记录了 `shared_store_deadline_exceeded`，位置为首个analysis写入的typed scalar `_put`；内部deadline与外层超时/清理发生在边界附近，精确先后和最终packet丢失路径没有单独计时，不作更细推断。没有 `SQLITE_FULL` 记录。

| 资源项 | 观察值 | 限制 |
| --- | ---: | --- |
| 装饰器记录的进程RSS累计高水位 | 2,551,193,600 B | 不是阶段增量或cgroup峰值 |
| Docker采样显示内存最大值 | 2.37 GiB，1774.861460 s时 | CLI有舍入，仅764次采样中最大，不是kernel `memory.peak` |
| Docker采样CPU显示最大值 | 101.26% | 不是积分CPU时间或4CPU全部占用证明 |
| cgroup精确peak/current/CPU/throttling计数 | null | 没有native最终packet，不能由显示采样重建 |
| complete attempt文件采样最大值 | 26,148,808 B | 不等于最终发布产物；不是连续文件系统高水位 |
| retained scratch + tmpfs采样最大值 | 0 B | 仅采样口径，不宣称无其他内存/文件成本 |

RSS和Docker/cgroup记账范围不同，不能互相替代或相减做成本归因。最终packet缺失时不能补出cgroup峰值或声称“未发生CPU节流”。报告中的8 GiB配置限额与CLI显示的7.653 GiB分母分别保留为不同来源字段，不用显示值改写冻结额度。

## 进度、残留与保留状态

阶段文件包含6条调用记录和1条terminal汇总，6条全部保留，无采样丢弃；361次进度写入、0次写入失败。最后progress虽仍标 `in_progress` / `terminal=false`，已经包含关联returned和写入failed记录，不能解释为进程仍活着。最终容器退出及controller报告确认失败。

失败目录中SQLite只有16,384字节，连同三件输入与失败标记共 **2,658,755字节**；这与采样时曾出现更大的文件量并不冲突，失败后回滚/清理后的终态大小不能当最大存储占用。没有 `run_manifest.json` 或 `shared/manifest.json`；完整artifact大小、validated counts及逻辑根均为null。complete attempt含输入/测量/脚本为5,791,230字节，另保留同量交接副本，共11,582,460字节；`complete_bytes_verified`只说明失败材料复制保留成功。

控制器通用 `complete_chain_time_or_output_budget_including_handoff` 标签不能证明1 GiB输出超限；本格直接观察是总时限失败。报告仍声明bind mount无独立文件系统大小quota，输出预算由原生和最终/采样检查约束。预检旧平铺17,959,075,000字节仅为数学下界，不能当作旧实测产物或压缩比。本次没有完整标准graph/events、完整来源核验和查询结果，不能宣称L核心闭环完成，也不涉及服务/Worker/备份、参考环境或工业数据验收。

所有普通源文件已按字节SHA只读复核，与交接inventory声明一致；输入原件、profile、失败材料、测量文件及冻结harness均在JSON留SHA。与 `/private/tmp/cpag-r19-core-matrix-dev4-L-offline-attempt1-20261029` 对应普通文件一致（两份inventory的自/对方摘要字段按其设计不同，分别保留）。写入本补充后再次核对原件及此前报告SHA未变。未执行核心分析或测试。
