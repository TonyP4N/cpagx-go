# R17 解析参考场景（实现前预登记）

基线 `6897707`；依据软件首版支持矩阵、完成清单 R02/R04/R05 及原方案 §§4—5。本页先于本轮解析改动写入。独立测试以 Python struct/固定十六进制自行构造容器、Ethernet/IPv4/TCP/ENIP 字节，不调用被测解析器或生产夹具生成器推导答案。测试范围是合成工程；真实字段正确性及工业适用性待授权材料。

## 输入合同与有限支持

正式双源入口统一调用 packet_pipeline 的解析实现。接受显式 synthetic 布尔；False 表示按支持子集解析真实格式、保留 real_source_unvalidated，不能等于真实数据验收。默认不作来源推断。经典 PCAP 2.4 双端序/微秒与纳秒；PCAPNG 单 section、单 interface、无选项 SHB/IDB/EPB；Ethernet/IPv4/TCP；ENIP 44818 SendRRData、空 address/0xb2 CPF、CIP read/write attribute canonical 8-bit class/instance/attribute。其他保持明确 unsupported/失败，不构造替代事件。

1—4 个文件按声明数组顺序、文件内原帧顺序遍历；不按时间排序。连接 epoch、双向流、重组和请求响应状态跨文件保留。相同 TCP 序号/相同字节视为重传，合为一个 PDU，全部原文件/原帧切片保留；不同字节重叠拒绝该方向并阻止该 epoch 关联。重复完整输入文件哈希明确拒绝，避免重复输入制造证据。排序是确定性合同，不据此推断物理因果。

本轮默认每文件与合计均 ≤16 MiB、合计 ≤10000 帧、单帧 ≤256 KiB；最多128方向流/连接，单流≤2048段、256KiB跨度、全局≤2048 PDU、流内时间跨度≤300秒、计算≤10秒。CSV 保持≤2MiB/1000逻辑记录/16列的正式运行界限。可注入更小限额测试边界。4件/128MiB、CSV 8MiB/10000记录是 R19 待测候选，不由本轮小夹具证明容量或性能。

## 固定预期

| 独立输入 | 预期 |
|---|---|
| 请求 PDU 首20字节在文件1、后28字节在文件2，文件3相同首段重传，文件4独立响应 | 恰好2事件、1关联；请求3原帧引用分属3原文件；命名字段切片还原固定 hex；每个文件帧号从1开始仍正确查询 |
| 同上乱序段（尾段先到） | 相同已解析请求字段；确定排序，不丢段 |
| 同序号相同字节重传 | 恰好1请求观测，保留全部证据切片 |
| 同一流中连续两个相同请求 PDU（不同序号）+一响应 | 3事件，无关联，duplicate_requests |
| 不同内容重叠/缺一字节/末字节截断 | 明确 unsupported，无该损坏方向替代事件；既有完整观测保留但关联阻断 |
| 完整合法 PDU 后未知服务 PDU | 保留完整合法观测；未知服务理由 cip_service_unsupported；该 epoch 不关联 |
| 只有请求 | 1事件、无边，response_missing |
| 未知 linktype、损坏 PCAPNG长度、容器截断 | CaptureError，无可信半结果 |
| 非 IPv4/非目标端口 | 无虚构协议事件；未知传输明确原因并阻断关联 |
| 请求、FIN、响应（可跨文件） | 保留半关闭响应并唯一关联 |
| 请求、RST、后续响应 | 保留请求，拒绝关闭后负载，不关联 |
| 旧请求、新SYN epoch、响应 | 保留2观测，不跨epoch匹配 |
| 第5文件、总字节/帧超限、重复文件哈希 | 明确错误，无半结果 |
| 显式 synthetic=False | 同字段/原始引用，所有事件/图 synthetic=False，质量包含 real_source_unvalidated |
| CSV值0/空/abc/NaN | 分别0/None/None/None；missing_value/invalid_numeric_value/nonfinite_value分开 |
| CSV重复时间（含等价时区）、重复整记录 | 不静默去重；每逻辑记录保留独立证据，所有冲突成员标 duplicate_process_time/duplicate_process_record |
| CSV非法时间、未知状态、多行字段、UTF8 BOM | 时间/状态有原因，逻辑记录号稳定，UTF8 BOM可读；非UTF8明确错误 |
| CSV重复表头/缺列/坏宽度/未闭引号 | 显式质量错误或unsupported；不能建立相邻可信观测 |

核验另包含旧单文件API回归、字段篡改与同尺寸原件篡改；双源 CLI/服务同输入同配置一致性由 R17 整链验证执行。本页不是 R18 顺序回放实现，不允许用全量解析冒充增量回放。
