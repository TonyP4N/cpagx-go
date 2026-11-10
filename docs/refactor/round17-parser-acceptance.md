# R17 解析及与双源核心集成核验

日期：2026-10-27。实现基线 `6897707`；独立场景在实现前登记于 [round17-parser-scenarios.md](round17-parser-scenarios.md)，已随预登记提交 `ec89ef0` 固定。本页核验本轮工作区实现，最终实施提交由 R17 总验收记录绑定；不以预登记提交冒充实施提交。

## 实现范围

正式双源 CLI 与服务使用同一 `packet_pipeline.analyze_capture`；不增加占位事件路径。最多四份 PCAP/PCAPNG 使用声明文件顺序及各文件原始帧顺序，跨文件保留连接 epoch、分段重组、重传和请求响应匹配。原帧号从每个原文件分别计数；索引与所有拒绝/关联判断使用 `(file_sha256, frame_number)`，避免不同文件的帧号碰撞。字段切片回查原文件、原帧和原字节偏移，查询重新验证文件及字段哈希。

相同序号/相同字节重叠合并为一个 PDU、保留全部重传切片；连续序号的重复 PDU 是多个观测，匹配明确为 ambiguous。冲突重叠/缺口/截断/关闭后数据明确报告；没有响应为 missing。R17 模式中长度明确但不支持的 PDU 不擦除前后已解码观测，该连接 epoch 禁止关联。重复输入文件哈希拒绝，避免重复提交同一原件。声明顺序是确定性规则，不是因果依据。

CSV R17 模式保留每个逻辑记录、原始时间和列，零值与缺失/非法/非有限值分开；重复整记录与同一列等价 UTC 时间的所有成员附质量原因，不静默去重。仅支持 UTF8/UTF8 BOM。超过微秒的 CSV 时间不静默截断：`event_time=null`、`timestamp_precision_unsupported`，原文保留；无时区依据仍为 unknown。双源扩展模式对原始 PCAP ticks、CSV 微秒使用向外舍入区间，缺 drift/precision/映射依据不能默认零并产生支持。

## 历史语义与版本

`analyze_capture(..., extended=None)` 对标量 synthetic 单文件维持历史默认；真实或文件列表自动选择扩展，正式 R17 模式显式 `extended=True`。扩展返回 `bounded-packet-2`，旧标量保持 `synthetic-packet-1` 及原产物字段集合。`parse_process(..., extended=False)` 保留旧重复值/时间精度行为，正式 R17 显式启用新的质量与容量检查。共享一个算法，通过有版本的分支保留旧结果重算语义；不修改既有导出。

独立启动 `6897707` 模块与当前模块，对原支持夹具的标量 packet+dual 规范化字节逐字节比较通过，SHA256 为 `2816e9eab9587e379026af943ae85ff7718a02da12d8ad389cda42fc8df62e52`。另由旧模块分别生成“不支持 PDU 后缀”“重复 CSV 时间和整记录”“CSV 亚微秒时间”三个历史 11 文件导出，当前 `verify_task` 均通过，核验前后所有文件字节哈希不变。这证明所列夹具，不外推任意未知历史格式。

## 当前容量与支持边界

正式运行默认最多四件抓包，合计 16 MiB / 10000 帧，单帧 256 KiB；每件读取也有 16 MiB 上限。只缓存当前一个原件，原帧索引及连接/流缓存有界。默认最多128连接/方向流、每方向2048段/256KiB跨度、2048 PDU、300秒捕获跨度、10秒解析计算限额。正式 CSV 2MiB /1000逻辑记录 /16列。更小注入限额用于超限测试。4件/128MiB、CSV 8MiB/10000记录是 R19 待测候选；本轮没有验证该性能或工业容量。

容器/协议支持仍限预登记子集；多 section/interface/options、未知链路、IPv6/VLAN/IP分片、其他 ENIP/CIP 服务和布局等不作支持承诺。TCP 序号回绕、冲突重叠与流缺口不猜测修复。旧 `packet_protocol.inspect_protocol` 仍为 synthetic 单 payload 兼容检查器；正式双源不调用该旧检查器。真实格式以显式 `synthetic=False` 进入有限解析，事件/图标志保持 false，质量与标准导出保留 `real_source_unvalidated`；来源/授权文本未被独立核验。

## 实际测试

在仓库根使用 `.venv/bin/python`，各命令前设置 `PYTHONPATH=services/analysis/src`：

| 命令（`-v` 输出存档） | 结果 | 记录 |
|---|---|---|
| `-m unittest discover -s tests/packets` | 48/48通过，含11项独立字节场景 | [packets](validation-round17/parsers-packets.log) |
| `-m unittest discover -s tests/parsers` | 19/19通过，含6项独立CSV场景 | [CSV](validation-round17/parsers-csv.log) |
| `-m unittest discover -s tests/contracts` | 6/6通过，包含独立 jsonschema 检查 | [contracts](validation-round17/parsers-contracts.log) |
| `-m unittest discover -s tests/dual_source` | 32/32通过，含扩展时钟/精度/映射、真实分支、CLI一致性和多文件证据 | [integration](validation-round17/parsers-dual-integration.log) |
| `-m unittest discover -s tests/backup` | 60/60通过，包含旧标量产物与目录/备份回归 | [backup](validation-round17/parsers-backup.log) |
| 旧模块/当前模块规范化结果比较 | 通过 | [legacy bytes](validation-round17/parsers-legacy-byte-compatibility.log) |
| 旧模块生成三类边界历史导出、当前只读验证 | 三类通过、原件与产物字节不变 | [legacy edge artifacts](validation-round17/parsers-legacy-edge-artifacts.log) |

一次系统 `python3` 试跑因缺少 jsonschema 失败；改用仓库已具备该依赖的 `.venv/bin/python` 后独立契约检查通过。实现并发修改期间的中间 CLI/API 原始 tuple/list 比较失败已由核心改为规范化字节比较，并在上述最终整套中通过。

这些是解析/核心集成及备份回归的合成工程证据。正式服务三次复现、Worker、浏览器和最终完整 CI 由 R17 总验收另行记录；真实数据字段核验待授权材料，R18 增量回放与 R19 性能/评估未在本页验收。
