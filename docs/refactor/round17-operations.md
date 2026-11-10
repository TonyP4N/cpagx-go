# R17 离线解析、版本配置与复现

本页描述显式新版能力，默认入口、冻结 RC1 及其离线包不变。来源声明与真实适用性分开；生成数据走 real 分支只验证接口，不构成真实工业验收。

## 正式路径

Go `/workspace/` → `/api/v3/datasets` 原件/版本目录 → 固定输入的预检 → `/api/v3/runs` → PostgreSQL 持久任务 → 隔离 Worker → `cpag_core.dual_source_export` → `dual_source` → **`packet_pipeline`**。独立 CLI 也调用此核心；`packet_protocol` 是该链路复用的有界协议解码组件，不另建关联算法。

沿 [R16 操作说明](round16-operations-20261027.md) 启动独立 Go/PG/Worker，先应用 `internal/jobs/migrations/008_v3_multi_capture.sql`。新增可空的 `network_file_ids` 固定运行抓包顺序，历史单文件保持 null/scalar；数据库约束及触发器保护所有已绑定原件。迁移不改写旧输入、配置或预检。

## 支持子集与限额

- PCAP 2.4，大小端、微秒/纳秒；PCAPNG 单 section/单 interface 的无选项 SHB/IDB/EPB 子集。Ethernet linktype 1、IPv4/TCP；其余容器/链路明确拒绝。
- ENIP TCP44818、SendRRData 0x006f，CPF 空 address 和 0xb2 unconnected data；CIP Read Attribute 0x0e、Write Attribute 0x10，8位 class/instance/attribute 路径。保留状态与原始 data_hex，不推断设备数值含义或物理成功。
- CSV UTF-8（含 BOM）、显式列及时间配置。空值/无效数值/非有限值/零值不同；保留逻辑记录、重复/质量标记与原时间。超微秒小数时间在新版明确未知，不静默截断用于关联。XLS/XLSX 可接收待转换，不能直接分析。
- 多文件按上传顺序（同创建时间以文件 ID 排序），文件内按原帧顺序；不按时间重新排序。最多4个抓包，运行内合计16MiB/10000帧；每帧256KiB；128方向流、每流2048段/256KiB跨度、2048 PDU、流时间跨度300秒、解析墙钟10秒。
- CSV 2MiB/1000逻辑记录/16列、配置64KiB、100操作/映射/有限规则、10000候选/规则结果。隔离 Worker 沿用既定资源约束。超限拒绝可信发布。
- 相同序号相同字节按重传处理并保留原始切片；冲突重叠、缺口和窗口耗尽不猜测补全；不同连接 epoch 不配对。重复整文件哈希拒绝。每条证据包含文件哈希和各文件自己的帧号。

**首版候选容量仍为4件、每件64MiB/合计128MiB、CSV8MiB/10000记录。** 上述是本轮实际执行界限，候选容量和性能仍由 R19 验收，不宣称达标或默默缩减目标。

## 配置和来源

示例配置生成器为 `scripts/validation/round17_profile.py`。新版显式 `analysis_mode=bounded-real-capable-v1`；原配置按旧版本语义核验。新版时钟包含版本、原时间/精度依据、偏移、漂移ppm与锚点、不确定区间、有效期；映射包含版本、依据及有效期。未知或跨有效期保留未知，多义映射不选择第一项。修改配置须创建新版本。

`finite_rules` 支持 state_change、threshold 及有限双变量 process_constraint；比较、加/减/比值运算由白名单限定。单位、适用条件、版本、参数、原始证据和缺失处理随结果保留；任意表达式、Python/shell 字符串不执行。阈值只是生成夹具的配置，不是未经核验的 SWaT 标准。

真实来源要求完整 `source_provenance`，与目录来源/批次/授权一致，并具有时钟/设备映射和规则材料依据。仍须当前有效预检，输出 synthetic=false、真实适用性未验证。来源/授权引用只是声明，不等于系统已独立验证真实性。

## 可重复验收

从仓库根目录、已准备 Docker、Go、Node/Playwright 与 Python 依赖的测试环境执行：

```sh
CPAG_PYTHON="$PWD/.venv/bin/python" \
PLAYWRIGHT_MODULE=/absolute/path/to/node_modules/playwright \
  bash scripts/validation/round17_acceptance.sh /tmp/cpag-r17-new
```

脚本使用新目录与独立 PostgreSQL，构建本次镜像；三次 Worker、独立 CLI、来源分支、完整终态备份/空库恢复，然后普通点击浏览器。私人连接信息只在测试目录，不提交；公开结果在 `environment/public` 和 `public/browser`。不应对用户现用部署做故障注入。

CLI：`python -m cpag_core --dual-source --network FIRST.pcap --network SECOND.pcap --process PROCESS.csv --profile PROFILE.json --output NEW_DIRECTORY`。Python 环境须包含 `services/analysis/src`。重复参数顺序即分析顺序；任何输入版本/顺序改变都应得到不同输入指纹。

三次对比直接哈希规范化 `events.json`、`graph.json`、`analysis.json`；这些文件不删字段。`run_manifest.json` 的运行ID、attempt、时刻与环境属于运行记录，不作语义哈希比较。CLI 与正式服务以相同输入顺序及配置比较。

备份沿用 R16 format4 全套终态机制，包含原有快照以及所有新抓包引用、版本配置、产物与证据。恢复必须空库+新目录，历史预检按固定快照重算，不以当前全部文件重解释。旧快照显式回填规则保持不变。
