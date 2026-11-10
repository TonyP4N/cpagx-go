# R19 显式共享存储正式接入预登记（2026-10-28）

记录时间：DAG3 实际 M 物理失败与 DAG4 实际 M 180 秒组件超时之后，DAG5 实际 M 全 root 对照与正式入口实现之前。

## 固定边界

- 既有默认离线格式、JSONL 历史、checkpoint-delta-2 与 engineering-capacity-1 不变；现有产物读回和身份计算路径保留。
- 新格式只接受 `storage_format=shared-observation-dag-5`，新容量 `engineering-capacity-2`；物理产物总额仍 1 GiB。新预算由 root 与 Go/Python 同步登记，候选/节点/快照预算不以默认值暗中放大。
- 网络/工艺原件、全请求/响应、全部候选/反证、GraphArtifact 全部 nodes/edges/claims、快照与 revision 全留，不缩窗、不降低密度、不静默截断。
- 现有判断算法和到达顺序不变。新 replay 的前缀摘要策略明确选择 `incremental-prefix-digest-2`；逐步 prefix SHA 必须与旧 canonical-prefix-1 完全相同。

## 允许改变的身份字段

Root 明确授权新历史格式使用 `merkle-json-dag-1`，不要求每步为旧容器 canonical SHA 扫数 GB。新 profile 的 replay 同时声明 `history_format=shared-observation-dag-5`、`identity_strategy=merkle-json-dag-1`、`prefix_digest_strategy=incremental-prefix-digest-2`。旧 profile 不接受这些新值。

新历史 `state_fingerprint` 是完整 analysis 的 DAG5 节点摘要，包含类型、所有值、顺序、完整已认证 extent；不是旧 canonical JSON SHA。新 snapshot/revision 身份是对应完整节点的 Merkle 摘要，明确带 `identity_strategy`。旧 ID 与新 ID 不混称相同算法。禁止通过跳过未知、反证、原件引用或任何业务字段来获得一致。

独立新旧小例比较预登记：逐 snapshot 的全部 analysis、trigger、available_at、arrival_seq、status、revision_number、config/rule 版本、完整引用与所有业务字段一致；只允许本段显式列出的容器身份算法字段差异及其 old/new snapshot 链引用按双射映射。业务 event/operation/change/candidate/claim ID 在相同 semantic profile 下必须一致。storage/history/identity/prefix 策略作为 transport 从 semantic profile 去除，capacity version 的身份差异须显式声明，不能无说明丢除 config fingerprint。比较程序逐路径报告差异，不能“删掉 analysis 后比较”。

## Python 与跨层正式接口（实施目标）

- `cpag_core.shared_export.export_task(network, process, profile, output, run_id=None, attempt_id=1, mode=offline|dual_source_replay)`；失败不封存、不发布。
- `artifact_files_for_inputs(count, mode=..., storage_format=...)` 返回精确真实库存；`artifact_files(output)` 验证显式 manifest 分派；`verify_task(output)` 默认完整源重建与完整业务比较。
- 实体库存：run_manifest.json、shared/manifest.json、shared/shared.sqlite3、sources/profile.json、sources/process.csv、sources/network.pcap（多 capture 使用现行 network_names 命名规则）。原 analysis/events/graph/quality/dataset、历史/指标等成为完整 logical roots，不落平面副本。
- `SharedStoreRunManifest` 保留通用运行身份、mode、状态、warnings/limitations、真实 artifacts 列表；新增 storage_format、shared_manifest_sha256、logical_artifacts（有限数量的最终逻辑 root descriptors），replay 新增 history_format/identity_strategy、snapshot_count/revision_count/final_snapshot_number。全部历史名称索引本身为逻辑数组 root，分页，不能把 60000 快照元数据塞进 manifest。
- root descriptor：name、digest、logical_bytes、kind、items；完整 canonical_sha256 仅作为明确扫描得出的额外摘要，不能把 Merkle digest 冒充 canonical SHA。历史完整性由按顺序的 root/index 及 snapshot/revision 引用认证。
- CLI `python -m cpag_core.shared_cli --root <服务授权目录> --action verify|metadata|page|selection|snapshot|revisions|evidence`。verify 返回完整源核验标志与有限 manifest；其余返回当前鉴权与发布库存核验下的节点认证结果。page 的 root/path/offset/limit、证据 ref-offset/ref-limit 受严格预算，无用户任意路径。
- 最大 envelope 8 MiB；页最多 100，原件引用页最多 100。完整业务 selection 超限要明确拒绝或显式结构分页，不能删字段。重建 canonical stream 必须显式 max_bytes/logical_scan_bytes 和 deadline。

## 原型与正式测试分层

1. DAG3/DAG4/DAG5 小例完整 canonical roundtrip、数组保序、单项删除重同步、跨 root 可变对象不误复用、压缩/extent/引用/库存篡改、复制恢复、字节缓存及输出失败不 seal。
2. 同原 M 实际 core→全 roots 存储组件探测，允许预登记总限 600 秒；仍非正式 Worker 1800 秒验收。保留前次所有失败。必须测 graph/events/quality、重复 analysis alias、恢复完整节点校验、最终节点数与物理库大小；未完成不推导 L 已可用。
3. 正式小例旧/新逐字段比较、历史前缀不变、未来原件不可见、wrong-run/context/tamper、复制恢复、CLI 分页与错误状态；Go/Worker/备份显式分派后做正式闭环。
4. 再按固定版本重跑 S/M/L offline 与 replay，1 GiB 输出、候选/快照/节点、查询/准备时间独立记账；软件未通过项继续列出，不归环境。

新格式暂未发布，因此尚无旧用户资产迁移。将来迁移必须保留原件与旧 manifest，独立完整验证，记录旧新容器身份映射；不得原地改写旧产物。
