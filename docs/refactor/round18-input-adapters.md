# R18 已到达输入适配器核验

实施前标准固定于签名预登记 `cc2db77`，基线 `25b2f1c`。此页仅记录输入读取、共享解析与原始记录证据，正式任务/时序判断/UI/最终CI另行验收。

`ReplayInputs` 构造只登记路径，不打开或扫描文件；每次 `advance` 仅消费指定槽位的下一个完整原始帧或CSV逻辑记录。网络槽位为network-0至network-3；process槽位逻辑序号包含表头1，首个数据记录为2。PCAP按record头和长度读取，PCAPNG逐block处理SHB/IDB/EPB子集；CSV按字节状态机处理UTF8/BOM、引号转义、多行和LF/CRLF边界，之后只把已经到达的缓冲交给共享R17 CSV解析器。独立Guard会在任何read请求跨越当前帧/逻辑记录边界时立即失败。

TCP会话、乱序/重传、分段、冲突、缺口和FIN/RST复用packet_pipeline提取的同一个prepared-index计算入口；不调用PacketEvidence全文件扫描。可以重复计算有界的已到达prefix，不能把全离线解析结果逐条播放。重算代价未被证明满足R19候选容量或生产吞吐。当前raw缓存硬限仍为网络合计16MiB/10000帧、CSV2MiB/1000数据逻辑记录/16列、累计最多11000已到达unit（包含CSV表头）；active规则窗口与缓存过期由ReplayCore独立执行。允许更小限额，禁止提高默认硬限。

回放引用为source_slot、record_sha256、原frame_number或CSV record_number、column、raw_time；record_sha256为已到达完整容器record/CSV逻辑记录的字节SHA，不伪装成file_sha256。当前snapshot不含原件完整SHA、未到达记录总量或后缀派生身份；最终原件绑定与完整性校验由外层导出维护。记录查询验证已到达字节SHA、位置、原时间，字段切片继续核查其原字节范围和SHA。CSV的BOM及原引号/换行保留在记录字节中。

回放PDU事件身份依据端点、连接epoch、PDU绝对TCP序号和已到达PDU字节；相同重传扩展证据但不新建事件。`snapshot(allowed_record_refs=...)`只选择已到达且被core接纳的unit重新重组，避免已丢弃late片段在后续步骤重新影响事实；CSV保留原physical ordinal，并提供`filtered_record_numbers`明确指出哪些已见物理记录被过滤，不能据此跨缺口构造相邻变化。历史快照由core深拷贝保存。

`finish()`只终结已到达缓冲，不读取后缀；`finish_source(slot)`是显式source_eof控制动作，才检查EOF。`all_sources_exhausted()`只读显式closed集合，正式完整任务由外层要求每个slot已closed，否则input_not_exhausted，不能发布可信partial成功。

真实原始内容冲突使用TCP已到达冲突重叠，以及CSV同时间不同值两条真实记录测试；两侧原引用均可查询，不覆盖旧字节。同slot/ordinal的不同hash声明只是`conflicting_reference`，返回旧verified ref和独立`claimed_record_sha256`，不伪造第二份原件或第二条可信证据。原件在到达期间改动由外层完整原件校验失败；本适配器的缓存哈希验证不能冒充完整文件验证。

## 实际核验

使用仓库`.venv/bin/python`，`PYTHONPATH=services/analysis/src`：

| 测试 | 实际结果 | 记录 |
|---|---|---|
| tests/replay_inputs | 12项通过 | [已到达输入](validation-round18-inputs/arrived-inputs.log) |
| tests/packets | 48项通过 | [旧抓包回归](validation-round18-inputs/packet-regression.log) |
| tests/parsers | 19项通过 | [旧CSV回归](validation-round18-inputs/csv-regression.log) |
| tests/backup | 47项通过 | [旧备份回归](validation-round18-inputs/backup-regression.log) |
| 基线25b2f1c packet_pipeline与当前正常/分段乱序重传/缺口/半关闭/未知服务五种输入的规范化字节 | 逐字节相等 | [offline比较](validation-round18-inputs/offline-byte-compatibility.log) |

独立测试覆盖两端序PCAP/PCAPNG；相同prefix下更改/追加未来PCAP及CSV后缀，当前events/refs/pending/quality/prefix_fingerprint逐字节相等；明确负向对照证明全离线路径会被Guard拒绝。还覆盖跨文件原切片查询、重传稳定ID、admission过滤、CSV BOM/多行/CRLF、0与重复时间冲突、未知记录查询拒绝、无IO finish和每槽位显式EOF门禁。单独的raw cache断言不替代core完整历史修订、超迟到/取消/恢复和真实工业数据验证。
