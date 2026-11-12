# R19 完整标准图投影的存储组合优化

范围为 DAG6 核心层，策略名 `stored-graph-composition-1`，计量阶段 `stored_graph_composition_1`。不改变关联规则、到达顺序、窗口、计数、逻辑格式或完整 typed-Merkle 根；不构成 S/M/L、参考环境或正式服务集成通过。

## 已观察瓶颈与测前小例

父任务 dev3 S 回放实际 export 1166 秒，其中 standard_projection 311 次累计148.3秒、history_generation 310次796.7秒、store 2178次627秒。各阶段有嵌套，不能相加。此前先用未改源码的单请求小例（2网络事件、5过程事件、1变化、1候选）进行组件定位，再实施本优化。

测前30次带 profiler 的完整投影0.13817秒，其中单独图身份 LogicalHasher 30次0.07618秒，schema验证270次0.05989秒。15轮完整 analysis 存储、完整标准投影、graph/events 存储：原路径0.11995秒、精确compose原型0.11924秒，近似持平。原型使用测试mock替换身份计算器，不能当生产实现提速证据。

原始受控输出为 `outputs/cpag-r19-core-projection-microbaseline-attempt1` 与 `outputs/cpag-r19-core-projection-microafter-attempt1`（FYP工作区下）。公共副本见 [validation-round19-stored-projection](validation-round19-stored-projection/)，完整源码SHA与命令清单保留在该目录。

## 实现与边界

`event_graph` 新增内部可选 `graph_identity_callback(complete_sans_id_graph) -> digest`，仅显式 `identity_strategy='merkle-json-dag-1'` 可用。回调接收所有字段，返回值必须为64位小写十六进制；省略回调的旧默认路径、原Merkle路径保持原实现。此回调不是外部输入的信任开关，也不接受旧根作为答案。

新 `compact_projection.store_standard_projection(result, writer, *, replay=False, graph_name=None, events_name=None)` 仅接受DAG6 sink。逐个完整intern图的所有容器子值（包括nodes、edges、claims、statistics、truncation），用当前sink已计算的引用compose不含graph_id的完整图，以此根生成完全相同graph_id，再compose含graph_id的完整图。events仍完整intern一次；命名参数可直接登记最终根。返回完整projection、graph/events descriptors与显式strategy。没有跨调用可变对象身份缓存、字段删减或抽样；每次原件/声明/反证等全部内容仍参与计算。

`CompactReplayCore` 仅在原已显式 `standard_projection='standard-graph-events-1'` 时使用返回descriptor组成历史快照。缺省无该字段的DAG6旧产物语义保持；其它旧格式不切换。最终业务根与独立source sink共用协调器，由父任务接入。原schema检查保留；失败不返回成功投影、不追加成功历史或seal，未seal节点可以作为失败现场保留。

图身份的无ID完整根多产生一个节点（该小例356→357），是避免第二遍完整图遍历的可见代价，仍受原节点、逻辑extent、物理/内存预算约束。

## 实现后小基准与回归

实现后采用每轮30次、三轮、交错执行顺序，每次同时存储完整analysis并比较完整projection及独立LogicalHasher根：

|轮次|原路径秒|组合路径秒|
|---|---:|---:|
|0|0.21435|0.19388|
|1（组合先执行）|0.21315|0.19933|
|2|0.21375|0.19602|

小例中位数0.21375→0.19602秒，约8.3%下降；这只是组件结果，不能外推S100或M/L。完整projection SHA256 两次均为 `76331e334be1ead923ea8063a726b967fce92ff446b2b8a82a93ff5278c4b3e8`。

专项4项测试通过（含12业务case）：完整图/事件逐字段及根比较，真实seal/read，嵌套同对象变更必须重算，回调门控/错误digest，sink/schema失败不seal。首次专项测试失败是测试误将底层reader当context manager，13个相同TypeError；原日志保留，修正为显式closing后通过，没有删除失败。

完整compact replay独立旧算法对照10项通过（17.169秒），覆盖每步快照/修订、graph/events全部字段与身份对应、重复/冲突/迟到/时钟/映射/未来前缀隔离；shared_export6项通过（0.755秒），包含完整源重建、产物目录复制后重新核验、原件查询和篡改拒绝；这里的目录复制不是数据库/服务成套备份恢复验收。完整核心矩阵由父任务另行固定源码测量，本记录不替代它。
