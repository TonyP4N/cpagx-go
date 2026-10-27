# R19 最终产物适配补充说明

测前登记：[round19-plan-scenarios.md](round19-plan-scenarios.md)，提交 `402d0b0`。
本页只说明独立评估的输入适配，不替代性能、服务授权、参考环境或最终 CI 验收。

## 冻结投影语义

`evaluation_artifacts.py` 的适配版本为 `final-artifact-evaluation-1`，策略版本为
`final-observations-upper-bound-1`。只读取通过 `dual_source_export.verify_task`、
`replay_export.verify_task` 或独立版本的 `single_source_export.verify_task` 校验的最终成套产物。校验器为核验来源可以重算；
适配器从保留的 `analysis.json` 选择预测，不从重算结果选择、补齐或替换预测。
校验失败直接拒绝，无可信评估输出。

|对象|进入 evaluator 的 kind|asset 编码|标量时间|意义|
|---|---|---|---|---|
|捕获的网络请求操作|`network_operation`|规范 JSON `[destination_ip,destination_port]`|已配置且可信的修正请求区间上界|捕获端点的操作观察，不确认设备、用户、攻击或执行|
|保留的工艺样本变化|`process_change`|规范 JSON `[asset_id,tag]`|保留变化区间上界，即 `time_range.end`|变化发生于样本间，不能确认动作时刻|
|候选关联|不进入事件预测|无|无|仅进入 `unlabelled_relations`，无关系 gold 时不计算关系或路径准确率|

网络映射缺失、映射冲突、错误响应、未响应不会使已经观察到的请求消失。
缺乏可信的配置时间时，输出带原 ID 和查询选择器的 `exclusions`，不编造时间。
资产编码采用 JSON 数组避免地址、端口、资产名和标签连接时发生分隔符碰撞。
标量上界投影会丢失区间分辨率；以此匹配得到的指标不等于物理动作时间准确率。

`network`、`process`、`dual` 分别投影网络观察、工艺变化或二者。
作用于已有双源产物时，它们是视图，并非独立执行的单源算法实验。
作用于下述 `single_source` 产物时，必须显式选择与实际执行源一致的投影；
不能使用默认 `dual` 或另一单源投影掩盖未提供的数据源。
网络与工艺类别不可直接混用 gold 或分母。只有同类别、同一独立参考、同一分母才能横比。

回放必须绑定最后一个经过校验且 `phase=finished` 的快照；所有操作窗口已关闭，
快照分析与最终 `analysis.json` 一致。同一稳定 ID 只计一次，重复 ID 内容冲突则拒绝。
历史出现次数不累计进终态预测，已经撤回的候选不进入终态关系列表。
`process_statistics` 另列候选首次可见快照及每次从可见集合中消失的记录，
均可使用既有历史证据查询，不把首次可见解释为因果确认。

## 适配和绑定接口

```python
adapted = adapt_artifact(
    artifact_root, batch=registered_batch, sample_sha256=registered_sample_digest,
    projection='dual', expected_binding=frozen_binding_or_none,
)
predictions = adapted['predictions']  # 兼容既有 EvaluationPredictions
evidence = query_prediction(artifact_root, adapted, prediction_or_relation_id)
```

函数不接受标注、gold、划分或标签路径。批次和样本摘要来自调用方的可信登记上下文，
不能把调用方声明误写成适配器已经验证了采集批次或保管链。
`predictions` 保留来源运行的 `input_fingerprint` 和 `config_fingerprint`；
既有 evaluator 的注册契约仍须检查这两者。

额外的 `binding` 绑定运行 ID、attempt、来源模式、synthetic 标志、分析/回放/核心/
规则/配置/适配/投影策略版本、完整产物 SHA-256、来源结果哈希、语义配置指纹、
最后快照 ID/序号/状态指纹、批次/样本上下文、投影视图及最终预测摘要。
另记录 `source_mode`、`source_presence` 和 `source_execution_version`，区分实际单源执行与双源视图。
调用方应在解封独立标注前冻结完整 `binding`；之后传入 `expected_binding`
逐字段比较。只冻结旧 `EvaluationPredictions` 的配置指纹不足以绑定新增的投影策略。
当前模块不证明登记早于解封，声明时间与独立性仍需评估层和操作证据单列核验。

`query_prediction` 重新校验并重新生成完整适配结果，拒绝旧 attempt、变更版本、
变更预测或过期摘要后，再委托既有操作/变化查询返回原件及字段证据。
双源候选通过其操作查询关联证据；显式排除项也可查询。
已经撤回且不在终态中的候选用 `process_statistics` 的历史快照定位后查询，
不伪装成终态预测。服务授权必须由调用它的服务层先行完成；此本地模块不是权限边界。

## 真正的单源执行

`single_source_export.py` 提供独立的 `bounded-single-source-1` 合同；
`SingleSourceRunManifest.schema.json` 不修改既有 RunManifest、ReplayRunManifest 或版本分发。

```python
manifest = export_task('network', captures, bounded_profile_path, new_output)
manifest = export_task('process', csv_path, bounded_profile_path, other_new_output)
verify_task(new_output)
query_task(new_output, operation_id='first')
```

CLI 用 `--source-mode network|process --source PATH --profile PATH --output PATH`，
网络模式可重复 `--source` 传入最多四件抓包；`--verify` 或 `--operation/--change`
查询保留的最终原件。只接受显式 bounded 配置，拒绝携带 replay 配置的离线执行。

网络执行只解析真实抓包，不要求、打开、解析或保留 CSV；工艺执行只解析真实 CSV，
不要求、打开、解析或保留抓包。它们直接复用现有 `_analyze_prepared` 的
协议操作、时钟、工艺变化及有限规则判断；未提供的一侧使用其已支持的空前缀结构，
并用 `source_presence` 明确标为不可用，不能作为“已经观察为空”的数据或证据。
不改变现有双源函数、规则或版本的行为。基础判断版本为 `bounded-dual-source-2`，
外层单源分析/发布版本单独绑定，不可被旧双源校验器当成同一种产物。

网络操作保留协议观察，其跨源 assessment 为 unknown；工艺变化独立保留。
没有另一源不能建立候选关联；缺源原因明确保留，不推断不存在变化或不存在攻击。
进程、网络和双源运行只有共享类别、独立参考和分母相同时才能比较。
当前机制保持 R17 执行上限：四抓包合计 16MiB、10000 帧、CSV 2MiB/1000
逻辑记录/16列、配置64KiB，单源全部产物16MiB；不代替 R19 候选容量验收。
此处实现为本地 CLI/成套产物/评估接口，正式 Worker 上传与任务 kind 接入的状态须另列。

## 有限测试

新增 `tests/evaluation/test_evaluation_artifacts.py` 使用实际双源/回放导出产物，
手写固定端点、工艺资产、10 秒请求与 12 秒变化的投影预期；检查三视图、
缺时排除、映射/响应不筛选观察、终态去重、真实 TCP 重叠冲突造成的候选撤回、
历史和终态证据、离线/回放共同类别、attempt/版本/策略/哈希篡改拒绝、
独立标注文件改变不影响预测以及缺件拒绝。
生成数据的 `synthetic=false` 分支只测试声明保留，不表示真实工业验证。

`tests/evaluation/test_single_source_export.py` 另检查：删除相反来源原件并阻止对应
解析器/证据索引后，实际单源导出、校验、适配和查询仍通过；共同观察与人工预期及
双源对应类别一致；源存在性、无伪造候选、严格 schema、同执行身份的全文件字节一致、
缺件/额外相反源/符号链接/重新哈希篡改/未知版本拒绝、失败不留半产物、备份与旧attempt拒绝。

本适配器保留所有终态预测，不截断到旧 evaluator 的 500 事件上限；
超出 evaluator 已支持范围必须明确拒绝或通过另行版本化能力处理，不能静默删事件。
