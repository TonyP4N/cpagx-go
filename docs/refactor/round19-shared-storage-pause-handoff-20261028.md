# R19 共享存储暂停交接（2026-10-28）

用户在当前节点后要求暂停。本文只记录已发生结果、未实现接口和恢复工作入口；没有启动新的试验或新增正式功能。原始目录不覆盖、不清理。

## 当前可确认结果

- 密度生成器第一阶段已由 root 接测量入口并纳入其阶段提交；S/M/L 原请求/响应/工艺记录/窗口保留，显式版本和预算预检区分允许尝试与物理可用性。后续 capacity3 生成器由 root 持有，不以本文代替其测试。
- 孤立 DAG3/DAG4/DAG5（`shared_artifact_store*.py`）仅是存储组件，不是正式 core publisher、Worker、CLI/API、评估或备份完成。
- 暂停前最后一次完整独立单测：旧/新存储 16 项，3.035 秒，PASS。日志 `validation-round19-shared-dag/compressed-unit-final.log`。覆盖完整值/顺序/类型/canonical SHA、保序分块、变更后 root、别名、intern/compose、复制、篡改、压缩炸弹、预算、缓存；没有把这些小例当 M/L 验收。
- 新 `SharedStoreRunManifest.schema.json` 只是草稿，待 root review/注册。`shared_export.py`、`shared_cli.py`、正式共享 history sink、正式 evaluation adapter **尚不存在**。

## 三次实际 M 组件对照

相同原始 M 文件和原 `engineering-capacity-1` 离线 profile，实际 2000 network、1000 process、1000 operations、999 changes、31801 candidates。不减密度/窗口/反证；均不是 PG/Worker 正式任务，也不是 L 结果。

| 次数 | 格式与限额 | 实际已完成 | 最终状态 |
| --- | --- | --- | --- |
| attempt1 | DAG3，1 GiB/2M nodes，总组件软限180s | core39.161s、graph/events52.608s | 首analysis写入触发SQLITE_FULL；516929节点，145.999s；无root/seal。失败不能归环境 |
| attempt2 | DAG4 BLOB32+zlib/raw，原1 GiB/2M，总软限180s | 首analysis完整root逻辑2563787143bytes，522050nodes，DB876687360bytes | 重复第二analysis遍历触发180s deadline；无seal；180.422s driver退出1 |
| attempt3 | DAG5另加保序内容定义分块+明确完整root alias，原1 GiB/2M，总软限600s/外部630s | 五root seal，539566nodes，DB574586880bytes；完整恢复节点校验；完整analysis重建canonical SHA与源对象独立json_chunks SHA完全相同 | graph完整流哈希阶段触发600s deadline；driver600.733s退出1。总体仍FAIL，已完成项目单独保留 |

attempt3 的完整 analysis SHA 为 `3003f6cbf34c7a5d232091d57b8af55a16334376a9a1494ea53e863e6bb10b3e`。这是真正逐字节 canonical JSON 流摘要，不是 Merkle digest。

五 root：analysis.json、dual/analysis.json（明确同一完整root别名）、events.json（逻辑3259141bytes）、graph.json（逻辑942431348bytes）、quality.json。完整恢复节点校验结束至258.939s，随后完整流检查。graph/events/quality 的全部独立流对照未完成，不能以 seal 或 analysis 对照通过替代全套 PASS。

attempt3 数据库及原始完整日志保留：
`<workspace>/outputs/cpag-r19-density-generator-aa16a4d/shared-probe-M-attempt3-dag5/`。

相邻 attempt1、attempt2-dag4 目录也完整保留；不复制大型数据库进 Git。各次 measurement/driver/traceback/一秒大小监控/stdout/stderr/当时源码快照已复制到 repo `validation-round19-shared-dag/actual-M-dag{3,4,5}-attempt{1,2,3}/`，源码前后固定检查为 true。

attempt3 一秒监控观察 DB+journal 合计峰736183072bytes，是采样峰，不冒充瞬时精确峰。attempt1 回滚后12KiB不能当失败前峰值；其最后采样数据库1068957696bytes+9728bytes journal。

## M 真实结构 profile 与 L 未解决风险

attempt3 结束后只读 SQL 聚合，耗时3.796秒，记录 `actual-M-dag5-attempt3/structural-profile.json`：

| kind | nodes | stored payload bytes |
| --- | ---: | ---: |
| array_branch | 114754 | 13885578 |
| array_leaf | 182921 | 150027325 |
| dict | 186563 | 65498540 |
| scalar | 55328 | 3168803 |

SQLite page_size4096，payload合计232580246bytes，但实际数据库574586880bytes。`dbstat` 不可用（no such table），该限制保留，没有伪造 overflow/page 细分。固定数组分块产生的共享不足与页布局/overflow值得后续实际对照；未做这些变更，不把猜测当测量结论。

M 最终约575MB已经表明不能凭8M节点上限或小例压缩比宣布 L 满足1GiB。尚未运行 L；没有推算其实际节点数、physical输出或1800s正式耗时PASS。

## 已实现组件 API

DAG3文件保持原型原表示。新模块 `shared_artifact_store_compressed`：

- FORMAT：DAG4 `shared-observation-dag-4`，DAG5 `shared-observation-dag-5`，codec `blob32-zlib-or-raw-1`；所有摘要绑定完整未压缩类型值、顺序及extent/height，Merkle与canonical SHA不混称。
- Writer：`add(name,value)`、`alias(name,target)`、`intern(value)`、`compose(name_or_none,values,references)`、`seal()`；intern不额外占root，compose只引用已存在完整节点。失败关闭/不seal。
- Reader：constructor(expected_manifest_sha256,expected_context,deadline)、descriptor/roots/get/page/iter_canonical/canonical_sha256；constructor全库完整性验证，不代表source验证。
- limits：physical仍1GiB，默认node2M，可显式最高8M；root160k、node8MiB、dict4096项、logicalroot512GiB、array500k项、depth64；decoded cache4096项且16MiB。reader extent逐child累积，避免所有decoded child同时常驻。大HTTP输出不因logicalroot512GiB而放宽。
- manifest状态固定 `sealed_store_source_unverified`。该声明绝非源验证或发布权限。

## 已约定但尚未实现的正式接口

设计/预登记见 `round19-shared-storage-integration-plan-20261028.md` 与 `round19-shared-artifact-dag-design-20261028.md`。Root已实现 capacity2/shared profile schemas/storage budget；未接通runtime时不叫全链可用。

1. Python共享 export/verify/query/evaluation读取：`shared_export`、`shared_cli` 尚未写。实体库存计划 run_manifest.json、shared/{manifest.json,shared.sqlite3}、sources/{network.pcap（多capture现规则）,process.csv,profile.json}；所有旧JSON是完整logical roots。
2. 显式新 profile storage_format=DAG5；replay history_format同DAG5、identity_strategy=merkle-json-dag-1、prefix_digest_strategy=incremental-prefix-digest-2。Root批准新容器Merkle身份；旧history ID/reader保持原语义。新旧比较只允许预登记容器身份及链引用映射差异，完整业务字段/引用不能删。
3. CLI已向capacity约定 flags：`--logical-root NAME --path JSON-array --offset N --limit<=100`，actions verify/metadata/page/selection/snapshot/revisions/evidence（graph兼容envelope）；evidence operation/change/trigger互斥、ref-offset/ref-limit最多100。metadata须有counts+first_operation_id，不能展开analysis。
4. 热查询权限分离已与capacity认可：内部 `--service-run-manifest-sha256` 只由Go在trusted semanticapproval+current DB/ACL/publication/allbytes之后传入；Python核manifest exactSHA、完整库存及physical/input SHA，并把请求路径绑定manifest中被批准的logical root digest，输出 `bound_page_integrity_source_approval_required`。默认CLI仍完整source replay。此路径尚未实现，不能声称当前Reader支持跳过核验。
5. 全新共享评估读取必须只取operations/time、network endpoints、process time、changes和candidate三ID等必要字段，保留全部observations/relations，不展开2GB analysis。需要显式分页projection/event_links；旧128MiB全JSON包未证明能容纳L。此项尚未实现。
6. Root提出独立 `merkle-semantic-1` 跨run摘要：仅递归忽略原VOLATILE的run_id/ingest_time，按缓存节点重算Merkle；不能删业务字段，也不冒充canonical SHA。尚未实现。

## 继续工作的顺序与停止状态

继续时先核当前branch/commit和本文件的pause-source-freeze.json，保留三次失败。优先确定实际L物理存储方案，再把严格版本化的共享 exporter/verify/query/history/evaluation 贯通，并做独立往返/前缀/未来隔离、旧回归和正式小例。不能只接sink就声称增量判断已解决；ReplayCore._judge全量重算、_publish副本及原完整SHA成本仍是软件项。

本agent全部已知exec sessions均已完成；未启动Docker任务，M driver退出1已落report。工具环境不能枚举macOS全进程（pgrep/sysmon不可用），所以仅声明无本agent已知遗留任务，不代替主代理整体进程审计。暂停后不再编辑源码或启动测试/试验。
