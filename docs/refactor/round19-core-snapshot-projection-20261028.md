# R19 核心历史标准投影修复与对照

独立旧/新比较发现：DAG6第一版快照保存完整analysis与core metadata，但旧`replay_export.execute`还会为每个快照加入graph/events。直接逐完整快照比较在snapshot0失败，原始失败保留于`validation-round19-core-compact-unit/snapshot-projection-gap-before.log`，没有删除graph/events来获得相等。

修复通过显式 `replay.standard_projection='standard-graph-events-1'` 开启。只有新声明时，`compact_replay._publish`使用既有标准投影函数构建完整graph/events，并作为完整共享子节点放入snapshot。graph包含全部nodes/edges/claims；graph_id按已声明的`merkle-json-dag-1`，其余业务字段保留。缺省省略字段保持第一版DAG6容器及source重建行为，已有第一版测量不能因此误记为含标准历史投影。

本次不修改物理1GiB、1800秒、查询8MiB/100项限额。Root另持显式storage-budget-2累计逻辑extent上限；这不是物理/HTTP限额放宽，也不是容量验收通过。生成器新版本由另一owner绑定该预算和标准投影；旧生成配置不被重新解释。

`test_compact_semantic_regression.py`参考路径仍运行旧ReplayCore的判断、闭合、deepcopy、canonical历史身份。仅将参考ReplayProfile验证分派到同一新schema，并用原ReplayInputs方法的子类避开新cache dispatch，所有容量和profile验证保持。新路径读取完整快照和revision，逐字段/canonical JSON对照：

- analysis全部值、trigger、到达时刻、available records、时钟与映射质量、未知、反证、业务event/operation/change/candidate/claim ID全部相同。
- 允许且验证完整双射的差异仅是已版本化state/snapshot/revision容器摘要及其链引用、graph_id。新ID还独立从完整对象重算Merkle检验，不把它冒充旧canonical SHA。
- graph/events字段与旧完整投影对照，不删除claims、原件refs或未知字段。
- 全部deterministic metrics相同。仅wall-clock runtime metrics不作源时间确定性比较。

最后5项测试覆盖14份配置，11.592秒PASS。包含正常过程、duplicate、冲突digest声明、允许late、too_late、未来原始字节/未来时序/速度变化不改过去前缀，以及R17请求/响应有效期、缺basis、precision重叠/接触和mapping冲突。另单独验证省略标准投影字段仍可由当前source verifier重建第一版DAG6模式。

这些是核心小例语义和完整性回归；不代替S/M/L每格完整运行，不代替真实工业数据或参考环境验收。新增逐snapshot标准投影的实际CPU/节点/物理空间成本尚需完整矩阵测量；没有据小例推断M/L通过。
