# Round 7 — 有限支持范围与执行器一致性

基线 `1386a4f`，默认入口不切换。本报告只验证有限合成软件行为，不增加协议、界面或
分析算法。包平台、镜像 ID、Python 版本和本次运行标识以
`validation-round7/consistency-environment.json` 为准；同一标识应同时出现在
`consistency-summary.json`、`consistency-result.json` 和 packet 查询报告中。

## 共有输入与支持边界

共有验收任务是现有 M1 的 normalized-network + process：

| 输入 | 有限支持范围 | 本次真实验收材料 |
|---|---|---|
| network | 显式 synthetic 的 UTF-8 `.jsonl`；record_type 为 `synthetic_normalized_network`，已定义字段为 string/null；原始 PCAP 不属于此入口 | `tests/fixtures/synthetic/network.normalized.jsonl`，两条记录 |
| process | UTF-8/BOM `.csv`，按逻辑记录计数，支持引号内换行；必须有显式 timestamp/column profile | `tests/fixtures/synthetic/process.csv`，三条逻辑记录、两个映射列 |
| profile | `.json` 显式列映射；analog/state 类型和状态表；缺失/非有限值保留 null 与质量原因 | `profiles/synthetic-demo.json` |
| 时间 | 本次共有验收使用显式 UTC Z 时间；不做跨源时钟对齐 | 三个过程时刻与两个网络时刻 |
| 证据 | file SHA-256、逻辑记录号、column、raw_time；可回查原记录 | 引号内换行、0、缺失值和 NaN 均不丢失 |

代码还具有部分其他格式/时区处理分支，但“本次共有验收”不扩大为所有分支的跨运行时
保证。尤其不能把主机可用的 timezone 数据库默认为 Alpine 镜像也具备；依赖未核实
时区库的 naive 时间不列入本次共同支持承诺。未知 CSV 布局、缺少映射、标签泄漏字段、
未知 network 字段、非合成工业源和任意 live 抓包不属于可直接接入的共有输入。

API 每个 network/process/profile 文件引用上限 16 MiB，提交引用必须位于 shared-root 的 `inputs/` 下并匹配真实 hash；
API 另行生成每个 job 的不可变快照。路径逃逸和符号链接不可作为受支持输入。边界内输入仍可能因格式、
质量、限额或资源不足失败，不能把“未超过 byte limit”解释为必然成功。

## 执行资源和环境

| 项目 | Legacy Worker | Isolated Docker |
|---|---|---|
| 计算位置 | 可信主机 POSIX guardian/process group | 固定 Linux compute image；离线包平台见 release manifest |
| 默认计算限额 | 1 GiB memory、64 MiB file size、60 CPU 秒、120 秒 wall time；stdout/stderr 各 64 KiB | 256 MiB memory/swap、0.5 CPU、64 PIDs；output tmpfs 16 MiB、runtime tmpfs 1 MiB；120 秒 wall time |
| 文件/权限 | 受信任的本机 core，不提供不受信代码隔离承诺 | readonly rootfs、65532:65532、network none、无控制凭据/宿主 socket 挂载给计算容器 |
| 宿主持久交接 | 原 attempt 目录和 manifest | 先验证再持久交接；默认 aggregate host budget 1 GiB、min free 64 MiB，缺损账本 fail closed |
| 本次运行覆盖 | 真 Worker→guardian→同一 core→API 发布 | 真 DockerExecutor→同一 core→原始证据验证→持久交接→API 发布 |

本次统一使用 lease 30 秒、heartbeat 0.2 秒；容器计算 wall timeout 为 60 秒。PG 55457、
API 18127 使用独立临时环境。以上是配置与有限样本验收，不是满限额吞吐、任意硬件性能
或生产资源 SLA。原生 Windows guardian、离线包目标之外架构、任意用户命令/插件不在
此有限版本验收范围；Docker 内 Linux 计算通过也不能等价为所有裸机 Linux 控制环境通过。

## 实际对比与逐项允许差异

执行 `scripts/validation/round7-consistency.py`，先逐个比较主机 checkout 与固定 compute image 中全部 core `.py`、schema JSON 和
container entry 的 SHA-256，证明是相同 core 字节；然后从同一三份源输入，经真实 API 分别创建
legacy 和 isolated 两个任务。每件发布文件先核 hash/size、schema、input/config/result
fingerprint；随后比较，不以“任务都成功”代替结果一致。

`events.json`、`graph.json`、`quality.json` 必须**逐字节完全相同**。本次为 8 个事件：
2 network + 6 process。所有 event/graph 引用回查的原记录必须完全相同，CSV 换行仍在。
证据比较没有忽略 hash、record、column、时间、值或质量原因。

允许差异只限下表；每条实际值在 `consistency-exact-differences.json` 中逐项记录。
`consistency-result.json` 同时列出允许路径和实际差异路径，未列字段差异立即失败。

| 产物与精确字段 | 差异原因与核验 |
|---|---|
| dataset `/files/0/name`、`/files/1/name` | legacy core 读取 API 的 job-specific immutable snapshot basename；Docker core 读取真实命令的 `/inputs/network.jsonl`、`/inputs/process.csv`。前者绑定 API 源路径，后者绑定 stopped-inspect 中的实际 Cmd；源 bytes/hash/size/kind 必须相同 |
| run_manifest `/run_id` | 每次 core 调用独立生成 UUID，分别验证 UUID 格式 |
| run_manifest `/tool_versions/python` | 必须等于实际观测的主机/镜像 Python 版本，不能任意改写或通配忽略 |
| run_manifest `/artifacts/0/sha256`、`/artifacts/0/size_bytes` | 仅 dataset.json 的两个可核实 name 差异引起；与各自真实文件重新计算值完全一致 |
| publication manifest `/artifacts/0/sha256`、`/artifacts/0/size` | 同上，仅 dataset.json 派生元数据 |
| publication manifest `/artifacts/4/sha256`、`/artifacts/4/size` | 仅 run_manifest.json 的上述已限定差异引起；与各自真实文件一致 |
| publication manifest 文本末尾 LF | legacy 有一个结尾 LF，isolated 无；JSON 内容仍按上述精确规则比较 |

这里没有使用“删除所有时间/ID/hash后比较”的宽泛规范化。artifact 数组的文件集合、
顺序及其他 hash/size 仍受检查；warnings、event_time、ingest_time、质量或证据改变均
不能被这些允许差异掩盖。保存的两套 `consistency-*-artifacts/` 可直接逐件检查。

## Packet 按新契约单独验收

`kind=packet` 是独立的新有限支持入口，不宣称 legacy normalized JSONL 入口能解析 PCAP，
也不以第四轮或其他旧错误输出作为 packet gold。当前实现的 wire 范围仍是严格有界的
synthetic classic PCAP/单接口 PCAPNG、Ethernet/IPv4/TCP 44818、ENIP SendRRData、canonical
CPF、CIP Get/Set Attribute Single 的规范 8-bit logical path；不扩展协议。

本次另建真实 isolated packet 任务，要求精确六件产物，调用当前 `verify_artifacts`
从原 capture 重新解码并核原字节、范围与 hash，然后实际查询 `cip.path`。独立断言：
2 events、1 个协议关联边、字面 CIP path `200124013001`、request 保留全部 3 个贡献帧
（包括相同重传）。输入只是合成字节夹具，未读取旧 event/graph 结果作为答案。

process 仍是兼容声明输入、明确 unused，不产生过程事件；packet 不代表完成网络/过程
融合、一般 TCP 栈、IPv6/VLAN/IP 分片、任意 ENIP/CIP 服务、真实工业数据验证、因果/攻击
关系、物理执行成功或检测评估。

## 回归、复现和证据

6 项比较器测试通过：共同内容/有限元数据差异可接受；全链重算 hash 后的 quality 改变、
manifest warning 改变、原记录引用改变、未绑定 filename、未观测 runtime version 和伪造
publication hash 均拒绝；core source 或 schema 集合/字节不同也拒绝。日志为 `consistency-tests.log`。

真实运行日志为 `consistency-integration.log`；总体结论只读取本次
`consistency-summary.json` 的 completed/valid 和共同 run ID，不能把上次遗留成功文件当成
新一轮完成。脚本不保存实际 API/attempt token、control receipt 或 DB dump，只保存合成
数据产物、原始字段查询、环境和校验结果。

针对离线包固定 compute image 的最终验证，避免重新 build 覆盖包镜像：

```sh
CPAG_CONSISTENCY_SKIP_BUILD=1 \
CPAG_CONSISTENCY_IMAGE=sha256:RELEASE_COMPUTE_IMAGE_ID \
.venv/bin/python scripts/validation/round7-consistency.py
```

`CPAG_CONSISTENCY_REPORT_DIR` 可指定报告目录。开发环境不提供已有镜像时，默认只构建
独立的 `cpag-consistency:round7` 验证 tag，不使用或切换默认部署。离线包目标和固定镜像
对应的最终环境事实以 Linux 打包报告与本次环境 JSON 的同 ID 核对为准。

本次最终版本 `49e998545b9b7b47f2b1dc9b19e6d8562f780765` 的实际重跑通过，
run ID 为 `d432d34254654f46ab3456166fc03eae`。
宿主 OCI immutable image ID 为
`sha256:99d890615dbf7667af785470e77160b1d2f0ee77d97e6076069d876be0780c53`；
离线包 portable config ID 为
`sha256:bf4c9d0208dff86d6e7868c357a9f114697d544dc517f4a8d71bae7f56b556a9`。
二者是同一镜像在宿主 OCI 与 classic Docker 导入后的不同标识，不能要求字符串相等；
打包记录负责关联。本次共同 events/graph/quality 字节相同，8 个事件的原始证据相同，
镜像内 core/schema 文件逐字节 SHA 门与实际容器资源断言通过；packet 原帧独立契约通过。
包装安装、升级回滚和下载接口由离线包 C/D 单独验收，不以本项 core 一致性替代。
