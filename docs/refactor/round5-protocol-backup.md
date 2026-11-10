# 第五轮：TCP 控制状态修复与抓包任务成套恢复

基线 d4974c0397e9b2a00f3bc8469eabd60a16fc69d2；本轮仍限合成数据和既有
ENIP SendRRData / canonical CPF / CIP Get、Set Attribute Single 子集，不扩协议。
默认 M1 入口不变。真实工业数据、时钟对齐、攻击/因果/物理成功均未验收。

## TCP 缺陷与修复

基线中，flow 级 closed 集合把单侧 FIN 当成双向终止，后续纯 ACK 也向已有
payload stream 加入错误；最终整个方向被丢弃。原本 2 events / 1 association
的观测在 FIN/ACK 后变为 1/0，双侧关闭后变为 0/0。基线实测保存在
`validation-round5/tcp-before.json`，本轮不能再沿用第四轮绿色 CI 作此行为的证明。

现在纯控制 ACK/FIN/RST 独立记录，不回溯抹去已观察字节。FIN 只关闭发送方，
允许另一侧继续发送响应；重复同序号 FIN 和 ACK 不污染载荷。RST 拒绝后续载荷，
但保留此前有效观测。控制包携带载荷仍不支持。半关闭后的同侧新载荷明确拒绝，
不猜测新连接。完整关闭后无 SYN 的新载荷也拒绝。

SYN 建立新观测 epoch；数据开始前的同方向同序号 SYN 重传、以及正确回应对端
SYN 序号的 SYN/ACK 留在同一 epoch。FIN/RST 后，即使 tuple、SYN 序号、session、
context 全相同，新 SYN 也开启新 epoch。不同 epoch 的请求响应不得配对。数据开始
后的异常 SYN 保守视作新边界；此实现仍不是完整 TCP 状态机、端点接受性或握手验证。

`tcp-after.json` 对应请求响应、FIN/ACK、双侧关闭、半关闭响应均为 2/1。
`tcp-tests.log` 当前 37 项通过，新增完整 SYN/SYNACK/ACK+请求响应+关闭、重复 SYN、
重复 FIN/ACK、半关闭、RST、同 tuple/context/序号重用、不跨 epoch 配对，以及
关闭后新数据不被默认为新 epoch 的回归。既有分段/乱序/重传/缺口/冲突/限额仍通过。

## 抓包任务与可查询产物

任务显式 `payload.kind="packet"`；省略仍走既有 M1。保持 network/process/profile
三个不可变输入引用兼容现有任务接口：network 是 PCAP/PCAPNG，profile 必须明确
`{"synthetic":true,"adapter":"synthetic-packet-1"}`。process 是兼容声明输入，不产生
过程事件，manifest 的限制和 warning 明确标记 unused，不能据此声称网络/过程融合。

计算入口 `python -m cpag_core.packet_job`，参数兼容现有 worker。成功产物精确六件：
`dataset.json`、`events.json`、`graph.json`、`quality.json`、`run_manifest.json`、
`packet_observations.json`。core manifest 精确记录其余五件 SHA-256/大小。
新增第十份共享产物契约 `PacketObservationArtifact.schema.json` 及 Go/Python 示例测试；
`SourceReference.json` 抽取既有标准引用形状供 sidecar 复用，不新增产物版本。
原帧/PDU offset、length、hex/hash、named fields、direction 和关联状态具有必需类型、
枚举及数值边界；跨片段完整覆盖和实际 byte ranges 由语义核验器负责。
原有标准 NetworkEvent/GraphArtifact 的字段不变。

单个 NetworkEvent source_ref 是锚点，GraphArtifact 节点和 claim 保留全部贡献帧引用，
包含相同重传。sidecar 保存完整观测、关联状态/原因、PDU bytes/hash、命名字段与所有
frame/PDU byte slices。控制边界记录另保留 source_ref、epoch 和 flags。

`cpag_core.packet_job.verify_artifacts(output, capture)` 校验 core manifest 文件集合、
每件 hash/size、dataset 原 capture hash/大小、input/result fingerprints，然后对原抓包
重新运行有限解码并精确比较 sidecar，逐个核验原始帧和字段片段。因而不仅能拒绝未重算
manifest 的篡改，也能拒绝全链重算 hash 后与原字节不一致的伪造解析字段。

复用查询函数 `query_evidence(output, capture, event_id, field=None)` 先运行上述校验，
再返回 event、graph node、observation 和 verified_fields：原帧 hex、file/frame SHA-256、
字段 hex/hash、frame 与 capture 绝对偏移，以及捕获字节的 IPv4/TCP checksum residual。
checksum 只描述捕获字节，offload/端点接受性未知；关联过程不以 checksum 作端点成功证据。
本地只读 viewer 可调用此函数，无需自行解析抓包或相信客户端提交的字段。

可复制的合成包在 `validation-round5/packet-job-demo/`，其中 inputs 是合成源，artifacts
是六件实际输出，query.json 是实际命名字段查询。没有 worker/API token 或数据库凭据。

Go API 校验发布文件的精确集合和原始 frame→PDU/字段 byte ranges、hash、完整覆盖及
sidecar 与 events/graph 的一致性；允许相同重传产生重叠证据。完整解码语义重算目前由
Python verify/backup/query 提供；不要把 Go byte-range 校验单独称为完整协议语义验证。

## 双表快照与恢复

备份 bundle format_version 升为 2。必须同时快照 `m4_jobs` 与 `m4_job_attempts`；
同事务对两表加 SHARE 锁、导出 pg_dump snapshot，再复制文件并前后核 hash。
旧的缺 attempt 历史格式拒绝，不会静默当成完整恢复。

history audit 核查每个 job 的连续 attempt、最新 worker/token 身份、已存在 exit receipt
的身份/时间，以及 published attempt 的产物指针。它保留未知退出状态，不把“备份成功”
解释为历史计算均已证明退出。restore 比较两表完整元数据、完整 file inventory；任一
不等强制失败并保留阶段报告。packet audit 复用上面的原 capture 重新解码/逐字段验证，
不再把二进制 PCAP 当 UTF-8 JSONL，也不丢弃多贡献帧引用。

真实本地验证 `scripts/backup/validate.py` 使用独立容器、PG 55443、API 18098：
真实 host worker/API 完成 legacy success、failed、queued cancellation 和 packet success；
随后恢复至新 `m4_restore_validation` 数据库和新目录，重启 API 读回状态，并对恢复后的
PCAP/六件产物调用真实 `query_evidence(...,'cip.path')`。查询保留 request 三个贡献帧。
另外的副本注入缺 capture 和 capture 同大小篡改，backup audit 与真实 query 均拒绝。
孤儿诊断文件保留并报告，不自动删除。

证据：`backup-integration-summary.json`、`backup-integration.log`、
`backup-restore-audit.json`、`backup-packet-restored-query.json`、
`backup-packet-{missing,tamper}-audit.json`、`backup-packet-query-negatives.json`。
测试 runner 只清理自己的临时 bundle/目录/容器，报告保留；报告不保存完整任务/token rows。

当前单测：37 packet、10 backup、6 Python shared-contract tests（含 27 个 Go/Python/独立
jsonschema 共享嵌套字段负例），以及 Go
`internal/contracts` 通过。容器执行器的真实 packet/API 验证由独立隔离子任务记录；
此文列出的 backup 运行使用 host worker，不能据此替代容器隔离验收。
