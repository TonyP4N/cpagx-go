# 显式历史存储与正式 Python 分支

旧 `dual-source-replay-1` 的默认 JSONL 文件、旧 schema、默认预算和读写路径保留。完整 profile 的 `replay.history_format="replay-history-checkpoint-delta-2"` 显式选择新存储；它属于 transport 字段，单独改变存储不会改变旧业务配置指纹或逻辑 snapshot/revision。`capacity_profile="engineering-capacity-1"` 与新格式共同出现才允许扩大预算；只选新格式仍受旧 Budget 限制。

## 稳定接口

- `replay_export.artifact_files_for_inputs(count, history_format=None)`：省略返回旧清单；显式新格式返回新清单；未知值拒绝。
- `artifact_files(output)`、`export_task(...)`、`verify_task(output)`、`snapshot_task(output,n)`、`query_task(...)`、`list_revisions(...)` 自动按完整 profile/run manifest 分派。
- `iter_verified_snapshots(output)` 为逐条 generator，含旧完整 analysis/graph/events 字段，结束时关闭原件与只读索引。
- 新 profile schema：`DualSpoolProfile` / `ReplaySpoolProfile`；新 run manifest schema：`ReplaySpoolRunManifest`。逻辑 `replay_version` 仍为 `dual-source-replay-1`，新增 required `history_format` 和 `history_manifest_sha256`；`capacity_profile` 仅 engineering 分支出现。

新库存仅把 `snapshots.jsonl`、`revisions.jsonl` 换成 `history/manifest.json`、`history/history.sqlite3`。其余 dataset/events/graph/quality/analysis/replay/arrivals/metrics/runtime_metrics、sources 和 run_manifest 文件保留。唯一新增目录是 `history`。外层 publication wrapper 也必须绑定同一 `history_format` 和精确库存。

## 服务桥接

只读 CLI：

`python -m cpag_core.replay_spool_cli --root <服务器已授权产物目录> --action verify|metadata|snapshot|revisions|graph|evidence`

`snapshot/graph/evidence` 使用 `--snapshot N`；revisions 使用 `--after N --limit 1..100`；evidence 只允许一个 `--operation ID`、`--change ID` 或 `--trigger`。没有任意 SQL/pragma 或跳过验证参数。JSON stdout 最大8MiB，超限明确失败，不输出半 JSON。

verify 返回 `history_format`、完整 `manifest`、`history={manifest,manifest_sha256}`，以及精确标志 `verification="source_replayed_storage_and_business_fields_verified"`。metadata 仅返回计数、最终 snapshot 编号/ID 和指纹。snapshot 为旧完整逻辑快照。evidence 保留原件真实解析并补齐正式 Go 旧 envelope 的 snapshot_id、quality、operation 关联 changes；新增引用也重新解析原始字节，并核对属于目标前缀已到集合。

Go 必须先校验当前 DB published attempt、用户 ACL、publication wrapper SHA 与版本绑定，再选择 root 调用 CLI；用户不能传 root、数据库路径或 SQL。CLI 目前每次进行完整源重放验证，没有语义验证缓存。这保证正确性，但不构成已通过10秒查询验收。

## 存储与恢复

SQLite 仅包含 objects、snapshots、revisions 三张受控表和自动主键索引；只读 URI、query_only/trusted_schema 固定，额外表/视图/触发器、额外 WAL/journal、软/硬链接、缺件和哈希变化拒绝。没有用户可控 pragma。

只存新增的不可变行对象与64路共享数组块；每128步最多一个完整字段索引检查点，其余为字段根引用差量。核心只保留当前状态、上一字段索引和4096个最近对象摘要，不常驻全历史快照/修订。源输入仍按到达逐条读取和判断，没有离线预解析替代。

恢复先按外部 run manifest 中的历史 manifest SHA 检查库存、SQLite 字节哈希、上下文、节点哈希和逻辑链；再按原到达序列重执行到临时 spool，逐条比较全部逻辑快照和修订、终态/图表/指标及原始证据。不比较跨 SQLite 版本的物理数据库字节重建。新目录复制后的历史查询走相同验证。

最终持久上限是声明 `max_bytes`；SQLite rollback journal 的工作上限另列 `max_working_bytes=3*max_bytes`，没有把持久预算暗减为三分之一。展开解码也受节点数与字节预算限制，避免共享引用绕过内存边界。整个产物（含原件）仍受 profile `max_output_bytes` 限制；任何限制失败删除未完成正式输出，不能发表半产物。

## 已验证与缺口

初始 storage 原型7项通过，实际旧 replay 回归含原型43项通过；正式分支加入后48项 replay、7项 contracts 通过，保留原始日志。初次字段对照因旧 RAM 中 tuple 与正式 JSON array 的类型差异失败，日志保留；改为旧产物实际 canonical JSON 后逐字段完全一致，没有删字段。

已实跑正常/过期/迟到、前缀未来修改不变、全部小例 snapshot/revision 与旧版等价、CLI 真原件查询、目录恢复和篡改拒绝。Go、Worker、完整备份恢复由对应分工实跑并单独登记，不能由本文件替代。S/M/L 密集回放、大容量全链、参考 Ubuntu 环境和真实工业材料未由这些小例证明。每步原判断及完整 state SHA 的 CPU 成本仍在，磁盘历史优化不等于全流程性能通过。

## 最终预算修复与当前证据

最终源码指纹见 `replay-spool-final-source-sha256.json`，aggregate SHA256 为 `466fc21cf2c4d7d79e4eb825a0bbbc4d135d3fe5ca5ab4faec30556ce9daaa85`。此前 v2 尚未发布；旧 wip 产物的 history limits 数值与最终修复不同，必须保留此前实跑原件并标为 preliminary，不替代最终镜像重跑。

历史数据库预算现在先从声明总输出上限扣除真实保留 sources 字节，再预留两个64KiB控制文件（history manifest 与外层 run manifest）。最终 JSON/JSONL 文件逐件、逐块按剩余总预算写入；极小声明预算在构造索引前明确拒绝。历史索引自身的 SQLite journal 工作预算仍单列，未暗改持久预算。SQLite 写入失败统一保留 `history_sqlite_write_failed:SQLITE_FULL` 等明确名称，未完成正式目录删除。无任何语义验证跳过开关。

原件分页参数为 `--ref-offset`、`--ref-limit`（默认0/100，最多100）。完整 selection 的全部引用先核对目标前缀可见性，随后只对页内引用解析真实原件和页内帧字段；selection 业务内容不删。返回 `evidence_page` 版本 `source-reference-page-1`，包含 total/returned/has_more 和 canonical_source_reference 顺序。整体8MiB约束继续生效，不能以分页掩盖巨大 selection 的输出超限。

最终只读回归：50项 replay、7项 contracts、12项 replay_inputs 成功；最终完整记录以 `*-final.log` 为准。source budget 补充用例覆盖小声明早拒绝、控制元数据预留、总字节与 SQLite_FULL 清理。完整 evaluation/backup 最终日志另列。

`replay-spool-small-measurement-final.json` 为固定小例本机开发样本：16个快照，历史文件从514,402字节变为217,871字节；新格式含验证导出约0.517秒，旧格式约0.288秒，因此不能宣称小例导出提速。新格式独立验证与原件查询均约0.38秒，进程生命周期 RSS 高水位约44MiB，含两种格式，不是独占内存。此前 probe JSON 保留，均不能替代正式 Worker 或 S/M/L 密集回放测量。
