# R19 核心到达前缀解析复用（DAG6 显式分支）

本项依赖 `round19-core-bottleneck-preregistration-20261028.md`，只改核心 ReplayInputs 与生成器。不接 Go/Worker/服务/备份，不切 RC1/default，不声称 M/L 或参考环境通过。此前容量2半接文件保持原样。

## 组件测量与真实边界

同一保留 S100 原始 PCAP/CSV，按原304步sequence中每个record/EOF之后做一次外层snapshot，再做同一全部admitted refs的内层snapshot，最后final，共607次。没有运行ReplayCore/关联/图/历史/导出/完整验证。本机macOS/arm64直接Python进程，未施加容器CPU/RAM/tmp硬配额，OS缓存状态未验证，不能当1800秒全链或容量接受。

| 项目 | 基线：incremental-prefix摘要、原解析 | 首个成功复用版本 |
| --- | ---: | ---: |
| 完整快照组件 wall seconds | 11.2727 | 7.1979 |
| 网络解析调用 | 607 | 202 |
| 累计解析frame数（含重复） | 63624 | 20300 |
| 网络解析 seconds | 4.4470 | 1.2721 |
| CSV解析调用 | 607 | 101（含1次header） |
| 累计CSV数据行解析 | 28176 | 100 |
| CSV解析 seconds | 0.2053 | 0.0065 |
| 进程累计RSS高水（bytes） | 43122688 | 50069504 |

新版本命中capture缓存405次，末尾缓存条目核算4337132bytes，最终网络/工艺事件计数200/100。网络解析仍在**每次新增或改变选中网络帧集合时**重建原TCP流；这不是完整增量网络引擎，也不意味着线性复杂度。剩余选择、校验、深复制和核心/历史成本不在“parse次数下降”中消失。

这次7.1979s来自首个成功复用版本。随后增加完整profile raw-canonical SHA身份修复及每条512byte LRU开销核算；最后源码只跑功能回归，尚未重新做同一独立性能probe，不能把前一个源码SHA冒充最后版本。S整链实际测量由独立核心runner负责。

## 已实现入口与不变的语义

仅 `capacity_config` 显式为 `engineering-core-capacity-3`、`storage_format=shared-observation-dag-6` 且replay字段匹配时，`ReplayInputs(...)` factory构造新 `CompactReplayInputs`。完整config的schema、容量和history/identity/prefix策略先校验；新类要求 `digest_strategy='incremental-prefix-digest-2'`。旧无配置构造仍是原 `ReplayInputs`，默认仍canonical-prefix-1；旧spool和DAG5不会隐式启用此缓存。

核心export/verify调用时传完整config，及 `parser_limits(config)` 中packet/process/stream三组limits（不把capture_limits误作构造参数），并传有限max_records。示例：

```python
limits = parser_limits(config)
inputs = ReplayInputs(networks, process, config['process'],
    synthetic=config['synthetic'], capacity_config=config,
    digest_strategy='incremental-prefix-digest-2',
    packet_limits=limits['packet_limits'], process_limits=limits['process_limits'],
    stream_limits=limits['stream_limits'],
    max_records=budget.frames + budget.process_records + 1)
```

新类使用原cursor逐个物理frame/逻辑CSV记录推进，构造不扫描原件，不预解析未来，不取完整原件SHA当作前缀身份。缓存键包含**选中帧身份的到达顺序**、final、synthetic与stream limits；新帧、过滤集合、TCP控制/冲突/重传或final变化会失效。复用的是原 `analyze_prepared_frames` 完整结果，没有重写协议判断。replay事件ID由endpoint/epoch/stream_sequence/PDU SHA构成，不取全前缀digest；capture的缓存结果没有错借graph input_fingerprint。

CSV缓存只保存已到达、当前选中记录的原parser单行模板，按完整process profile canonical JSON的原始SHA绑定。每次snapshot仍按实际选中集合重新计算duplicate record/time和聚合质量；invalid width错误按选中CSV序号重映射，SourceRef保留实际原件逻辑记录序号，过滤不会把第4行压成第3行。BOM、quoted multiline、CRLF、missing/invalid值与未来隔离继续走原cursor/parser。

缓存条目按对象遍历加每条512byte LRU开销核算，总预算16MiB，最多32768条、最多2组网络前缀。超预算不缓存或驱逐，不截断事实。它不是整个进程RSS/原始缓冲/返回深副本的16MiB限制。公开snapshot继续深复制；调用者改返回值不能污染缓存。即使命中，仍逐次校验所有已到达记录实际raw SHA；缓存/stat不替代字节校验。`parse_statistics` 是独立计量属性，不加入任何业务快照。新phase标签 `replay_input_snapshot`、`replay_network_prefix`、`network_parse`、`replay_process_prefix`会嵌套，不能相加当总时长。

## 失败与修复保留

1. 首个after probe脚本将`capacity_config`误加到profile.update而非构造参数，实际跑了legacy adapter，最终取parse_statistics报AttributeError。作为测量脚本失败完整保存report/stderr/probe，不算新实现成功。
2. 新增完整profile身份负例暴露：pipeline.fingerprint会递归剥除`run_id`键，新增名为run_id的CSV列定义后可能命中旧模板。先失败日志保留；改为**不剥字段的canonical JSON原始SHA**。最后相同负例与所有对象对照通过。

原始日志先复制到0700 controlled `outputs/cpag-r19-core-prefix-parser-evidence-20261028`；公开目录 `validation-round19-core-prefix-parser/` 只替换个人文件路径前缀，逐份记录原始/公开SHA。不删第一失败，不将组件round-trip/缓存命中写成完整核心接受。

## 兼容与限定验证

- ReplayInputs全部45项测试通过（原12、incremental策略14、compact19）。compact继承全部原到达隔离oracle，并对每个小例full/filtered/final快照完整canonical对象比较；覆盖跨文件/大小端PCAP/PCAPNG、未齐分段、重传增证据、冲突原件保留、FIN/RST、CSV重复/width/缺值、未来修改、缓存命中raw篡改、返回对象污染、profile身份变化及小缓存驱逐。
- 旧生成器9项测试通过，旧default raw/profile SHA和旧capacity-3保持；新core4的3项测试通过，含S/M/L原SHA、升级语义和现formal harness在image/Go/Worker前拒绝。
- 尚未对M/L重解析性能、完整ReplayCore/历史/图/新进程verify/10秒原件查询作本项接受；没有用减少响应、候选、反证或历史来换性能。

## 新生成器与核心限定门禁

新增显式 `r19-density-capacity-4` 对应 COMPACT3/DAG6。可从已生成S/M/L升级：

```text
python scripts/validation/round19_scale_fixture.py --upgrade-from SOURCE --output NEW_DIRECTORY --version r19-density-capacity-4
```

原raw SHA、请求/响应/CSV密度、5秒窗口、300秒缓冲、2秒允许迟到、完整sequence不变；升级仅允许transport/storage/budget字段变化，业务配置或schedule改变先拒绝，不覆盖源目录。新matrix明确`core_only/integration_ready=false/operator_resource_profile=null`，preflight为`admissible_for_core_attempt`，不是formal Go/Worker permission。现正式harness对该状态拒绝，缺preflight也不能回落旧模式。

实际轻生成目录为 controlled `outputs/cpag-r19-core-compact-generator-{S,M,L}-attempt1`，逐件最终SHA见 `final-source-and-fixtures.json`。它们是静态配置准备，不是M/L核心运行结果。4CPU/8GiB RAM/4GiB临时/1GiB物理输出/1800秒预算保持，是否实际施加必须由后续runner记录。
