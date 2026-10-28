# R19 共享完整观测存储：设计与实际边界（2026-10-28）

## 状态和不可替代的验收

本文件讨论软件容量修复。现有合成小例、局部组件、孤立存储原型与正式 Worker/API/备份恢复测量分别记账；不构成真实工业数据或参考硬件环境验收。旧 `engineering-capacity-1`、旧离线平面 JSON、旧 replay JSONL 与 checkpoint-delta-2 默认和读取语义均未由本原型修改。

当前代码 `shared_artifact_store.py` 是 **孤立 DAG3 原型**，`shared_artifact_store_compressed.py` 是 **孤立 DAG4/DAG5 原型**，尚未接入任何正式 export/Worker/API。首轮实际 M 存储失败保留在 `validation-round19-shared-dag/actual-M-dag3-attempt1/`；不可以把它作为 M 可用的证据。下一阶段正式入口必须显式版本化后接通，不能仅以新增文件名宣布容量完成。

## 独立密度与平面格式冲突

原密度保留请求、响应、全部 CSV 工艺记录、5 秒窗口及 3 秒 gap。独立预检版本 `r19-density-preflight-2` 的候选范围为 S 2594–2596、M 31751–31813、L 317500–318125。原材料导出的实际 M 候选为 31801。L 必须使用新的候选预算，旧 100000 上限不相容；候选 500000、快照 65000、revision 90000 只是待实测的新版本建议，尚未上线。

M 平面产物的严格下界已超过 1 GiB，L 更大。不能通过删响应、减少候选、缩短窗口、丢 counterevidence 或删除 GraphArtifact.claims 消除冲突。物理输出仍限制为 1 GiB；完整逻辑 JSON 可以更大，但完整校验必须单独声明逻辑扫描预算与时间预算。

## 实际字段测量

保留的旧 S100 分析文件为 168329050 字节，另有一份同哈希的 `dual/analysis.json`。graph 为 61570515 字节。只读扫描保留在 `retained-S100-field-duplication.json`，没有改动原产物或调用判断算法：

| 字段 | 出现次数/不同值 | 原逻辑字节 | 可共享的不同值字节 |
| --- | ---: | ---: | ---: |
| source references | 809026 / 288 | 139219839 | 48757 |
| complete candidates | 2596 / 2596 | 165420683 | 无整项重复 |
| candidate counterevidence | 2596 / 2596 | 84768282 | 无整项重复 |
| claim counterevidence | 2596 / 2596 | 57082552 | 无整项重复 |
| unknown reasons | 2596 / 2 | 114477 | 123 |
| support | 2596 / 1 | 197296 | 76 |
| assumptions | 2596 / 1 | 334884 | 129 |

整个 candidate/counterevidence 向量不同，常见模式是“同一全集少一个项目”。所以只为完整快照/完整列表做去重仍会重复嵌套内容。现有 replay history 的 DAG 思路可复用，但新节点应细化到标量、字典、保序数组及其分块，离线/图/历史使用同一节点库。

## 首次实际 M 失败（必须保留）

`actual_M_probe.py` 用新生成器 M 的真实原始 pcap/CSV 和现有容量 profile，直接执行既有 core 与标准图 projection，然后尝试孤立 DAG3。没有 PG、Worker、发布、评估入口；总软限 180 秒，外部 210 秒。

- 输入：2000 network records、1000 process records、1000 operations、999 changes、31801 candidates。
- core analysis：39.160766708 秒；标准图/事件：52.608304500 秒。
- 首个 analysis root 写入时 `shared_storage_failed:SQLITE_FULL`；总墙钟 145.999461875 秒。
- 当时已生成 516929 个节点，低于原型 2000000 节点上限；先触发的是物理限制，不能归为环境。
- 一秒监控最后观察数据库为 1068957696 字节，加 journal 9728 字节。它是采样值，不是精确峰值。SQLite 回滚后文件仅 12288 字节，不能把回滚大小误报为峰值。
- 没有成功 root、没有 seal/manifest；该 M 未通过。运行前后五个源码 SHA 完全相同。

首轮原型与源码快照均保留。不得通过抬高 1 GiB 或节点上限把失败改记通过。

## 新的独立物理 codec

DAG4 `shared-observation-dag-4` 只改变物理表示：SQLite 主键和子引用为 BLOB32，节点 payload 为显式 `blob32-zlib-or-raw-1`。每节点 zlib level 1 只有比 raw 更小时才采用；摘要绑定版本、codec、kind、完整未压缩 payload、logical_bytes/items/height。SQLite 物理文件 SHA 另绑定实际压缩字节。

读取先受 `max_node_bytes` 限制有界解压，拒绝超过长度、未 EOF、尾随/拼接流及未知 codec。节点认证之后才使用 extent；局部 child extent 与严格递减 height/bytes 证明无环。数组返回时保持全部原位置和值。reader 的解码对象缓存同时限制 4096 项和 16 MiB（按 Python 对象大小保守重复记账），不能只靠项目数限制压缩后的大节点。单节点超缓存预算仍可读取，但不放入缓存。

DAG5 `shared-observation-dag-5` 进一步使用内容定义的数组分块：每块 16–64 项，取当前 child digest 的固定 bits 确定切点，各层同规则；不排序、不抽样、不删重复值。删除一项后可以在后续相同内容边界复用块。DAG4 与 DAG5 分别验证，不能用小例比例外推 L。

14 项旧/新原型独立单测覆盖完整 canonical stream SHA、标量类型、Unicode、4097 项分页边界、完整观测/claims/counterevidence、少一项 alternatives、变更后不同 root、复制恢复、extent/payload/引用篡改、压缩炸弹/截断/尾随流、字节缓存、物理/节点/节点字节预算与失败不 seal。它们只证明测试输入下的格式行为。

## 正式接入接口草案（尚未实施）

新 profile 顶层 `storage_format` 显式指定经实际测量选定的 DAG 版本。新的 capacity profile 只允许这个格式；旧默认字段省略仍走原路径。replay 保持逻辑 `dual-source-replay-1`，显式 history format 使用共享存储，并选择已独立验证的 `incremental-prefix-digest-2` 到达前缀摘要策略。新增存储字段属于 transport，不能改变业务身份/判断结果。

实体库存：`run_manifest.json`、`shared/manifest.json`、`shared/shared.sqlite3` 和已验证的保留原件/profile。所有原 analysis、dual analysis、events、graph（包括全部 claims）、quality、dataset、每个快照与每个 revision 都是完整逻辑 root，禁止再同时落巨大平面副本。每份逻辑产物声明 name、root_digest、logical_bytes、kind/items、完整 canonical_sha256；run manifest artifacts 仍只列真实物理库存。恢复必须核验完整当前库存、上下文、原件 byte SHA、节点/roots 索引与完整源重建。

Python 出口建议是独立 `shared_export.export_task(...)`、`verify_task(...)`、`artifact_files(...)` 和 `shared_cli --root <authorized dir> --action verify|metadata|page|selection|snapshot|revisions`。发布时 full source verification 与 prepared locator 持久化绑定 run/attempt/profile/input/manifest 所有 roots。热查询继续现有 ACL、publication/revocation、当前原件及库存 guard，不能增加无条件 trust 开关。

`page` 路径指向任意逻辑数组（observations/candidates/edges/claims/event_links/relations/history），offset/limit<=100，明确 total/returned/has_more。selection 返回完整所选业务字段；证据原件按 canonical source ref 分页，先核验完整 selected refs/prefix，再读所请求页的真实原件。单个完整 selection 超过 8 MiB 时明确失败或另走显式结构分页，不静默删字段。

跨层预算需要共享同一版本：既有 operation/change/candidate/arrival_steps/snapshot/revision/output_bytes，加 max_nodes/max_node_bytes/max_roots、query_bytes、decoded_cache_bytes、logical_scan_bytes 与验证/查询时间。数据库根不能按每 candidate 单独建 root（500k 会越 root 数预算），应使用完整数组 root + 可认证的 ID 索引。ID 索引本身也须分块，避免 500k 键单字典超过 8 MiB 节点。

## 不能遗漏的评估/图/准备预算

实际旧 S100 projection 的 canonical 大小 1016280 字节（原 stdout 为 1040763）；events 199、relations 2596；event_links 755390 字节（relation entries 711304）、predictions 257341（events 57152、unlabelled_relations 199893）。详见 `retained-S100-projection-fields.json`。

按结构估计 L 的 318125 个 relation ID 约 24.5 MB，relation link 约 87 MB，观测/其 link 另约 10 MB；replay first_visible 还会增加几十 MB。这里只是规划估计，不能用来声明 L 满足 128 MiB projection。正式新评估入口必须允许完整 predictions、全部 unlabelled relations、event_links 和 first-visible index 共享存储/分页传递，绑定同一 root 与样本身份。现有 full JSON 评估包默认与历史校验保留，不能给旧 schema 塞省略字段。

Graph 的 nodes/edges/claims 全留；prepared DB 不应再物化整个 graph/projection 副本，应保存受验证且可恢复的 root/索引与完整原件身份。history 的同一共享节点库仍须写全序列、保留 revision、快照可独立重建，不能仅优化 final analysis。查询 envelope 仍 8 MiB、证据页 100，不把单次扩大输出当容量修复。完整逻辑源校验扫描与首次准备的 CPU 成本仍须实测；共享物理表示本身不会证明其时间合格。
