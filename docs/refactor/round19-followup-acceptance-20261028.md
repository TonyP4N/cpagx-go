# R19 续作阶段验收（2026-10-28，持续更新）

R19 **未结项**，不进入 R20。RC1、默认入口及用户部署不变。所有本机结果为 macOS arm64 / Docker aarch64 开发验证，不替代 Ubuntu 24.04 x86_64、8 vCPU / 16 GiB / SSD 的参考环境验收。原容量目标不降低。

## 1. S100 同提交、同镜像、同资源三次正式通过

固定代码 `3e7340ea0e923820b21881dcb33740e0f2d0ec20` 的独立归档用于构建 API、Worker 与计算镜像；不使用正在修改的工作区。镜像标签 `cpag-isolated:r19-fixed-3e7340e`，不可变 ID `sha256:a29a211cd586ca4c5cef1da4b3d28c91c43d2e947b016f8d9d2e6d2018acd1f0`；输入 SHA、源码指纹及资源配置见[三次完整汇总](validation-round19-followup/fixed-s100-three-summary.json)。

同一原 S100（100 请求+100 响应+100 CSV 行），资源 `r19-dev-s100-1`，三个独立数据库/任务/容器，各成功一次，不以自动重试掩盖失败。

| 次数 | 提交至终态、校验与证据可查（秒） | 计算墙钟（秒） | 计算进程 RSS 峰值（bytes） | 完整发布产物（bytes） |
|---|---:|---:|---:|---:|
| 1 | 104.205 | 27.085 | 65,396,736 | 398,588,430 |
| 2 | 121.296 | 30.197 | 65,597,440 | 398,588,430 |
| 3 | 91.807 | 25.895 | 65,388,544 | 398,588,430 |

每次完整原件校验、结果 API、165 条原始引用（100+65 分页）通过；每页小于 10 秒和 8 MiB。同大小篡改、缺文件均 409，恢复原件后可查。三个分析/事件/图/质量文件的规范化哈希一致：只排除既定 `run_id`、`ingest_time`，不删除未知、反证、时间、证据或排序业务字段。

原三次 OOM、资源单独提高对照、首次完成请求超时三 attempt 失败、全部测量均保留，参见[测量与失败说明](round19-followup-measurements-20261028.md)。本次只证明固定 S100 软件链路；不扩大为 M1000/L10000、回放 S100 或目标主机吞吐通过。

计算阶段原始样本在每个 `fixed-s100-runN.json` 的 `worker_attempts.compute_phases`，包括网络/CSV解析、关联及证据组织、导出、标准投影、重新验证、完整计算；CPU、RSS、墙钟及 Docker 内存/块IO全部样本在汇总中。RSS 是进程累计高水位，阶段时间嵌套不可求和；Docker 内存包含 tmpfs，不等于 RSS。没有清理 OS 缓存，缓存条件为 `unverified_cold`。证据查询发生在结果 API 已验证并填充应用缓存之后；每页耗时是该热路径，不证明冷启动首次证据查询10秒达标，冷/热查询对照仍待测。

原测量 harness 的 `phase_breakdown` 仍是先前不可用占位，不修改历史原记录；上述新增原始 `compute_phases` 和 `compute_measurements` 才是本次实际测得值。汇总脚本第一次错误要求**容器**退出码为0，已保留 `fixed-s100-summary-first-classification.json`。实际计算子进程均0；计算结束后 PID1 为保留 tmpfs 等待交接，宿主按既有流程 kill 并取独立退出证明，因此容器137且 `OOMKilled=false`。修复汇总判据同时要求计算0、任务成功、无OOM、已退出且已移除的独立回执，新增回归不允许把OOM或失败混入成功。

## 2. 容量预算与边界

显式 `profile.capacity_profile=engineering-capacity-1` 已贯穿上传/配置封装、核心、解析、派生预算、Worker、交接、服务验证、查询及备份。旧省略配置保持旧限额；新回放容量必须同时选择显式新历史格式。具体预算见[版本化容量说明](round19-versioned-capacity-20261028.md)。操作员资源版本独立绑定，不允许上传文件扩大执行器配额。

实际正式 Worker 完成 **4件抓包（64+32+16+16 MiB）、CSV 8 MiB / 10000逻辑记录 / 16列**；完整提交至校验查询31.052秒，发布173,058,523bytes。独立预期2网络事件、10000工艺观测、1操作、1变化、1 unknown候选均符合，原始证据可查，损坏拒绝。[正式记录](validation-round19-followup/fixed-byte-boundary-formal.json)。额外抓包字节是明确不支持EtherType的占位帧，保留质量原因，不伪造协议事件；**该字节边界案例不能作为密集操作性能证据**。

自动化测试验证单件64MiB+1、合计128MiB+1、CSV8MiB+1、第五抓包、17列均拒绝，不存在已发布目录；10000/10001逻辑行测试保持。输出精确字节边界接受、少一字节拒绝且无法通过完整哈希。数据库12个并发领取只允许1个活动attempt，未确认退出的过期/取消attempt继续占位，证据见版本化容量报告。

## 3. 回放及评估

新增显式 `replay-history-checkpoint-delta-2`：磁盘历史、共享不可变行、128步检查点/差量和有界索引；逻辑判断仍复用原到达前缀，不先读未来。Go、CLI、Worker、评估适配和备份按格式精确绑定，旧 JSONL 仍可读且默认不变。完整源重执行、所有输入/产物/历史哈希和 run/attempt 校验保留；本轮**没有**宣称消除前缀重算或证明最大规模10秒查询。

新格式正式小例、状态修订与空库恢复见[回放备份说明](round19-spool-backup-integration.md)。首次小例是在最终总预算修复前，保留为preliminary。修复后 `spool-final-1` 镜像（`sha256:5979b0d9e5ad655c2340cfc1aa33148dd83085b153459eb91e34c788f644ab25`）七任务及空库恢复重新通过；八项正式生命周期检查亦通过：排队取消、实际arrival3运行取消与退出确认、无效输入有限失败、Worker被杀及真实租约失效、attempt2从头重放、旧attempt发布409、重复完成唯一发布，以及迁移幂等。构建前125件运行时文件及4件验收脚本逐件匹配52711e3提交；镜像内63件源码/schema/入口与清单一致，具体绑定见该专页原始清单；不能混用前次证据。

评估显式v2扩大为每侧22000事件，独立一对一、重复预测、争议和零分母语义通过；旧500事件v1默认不变。独立参考原件库存按哈希受控读取，缺失/篡改/权限拒绝和空库恢复查询见[原件验收](round19-reference-inventory-followup.md)。字节库存校验不冒称参考标注真实可信，也不冒称 CSV 任意定位字段均已独立验证。

## 4. 失败、回归和阶段提交

预登记 `e1ca1a7`；第一阶段 `3e7340ea0e923820b21881dcb33740e0f2d0ec20`。该阶段 CI [40628284336](https://github.com/TonyP4N/cpagx-go/actions/runs/40628284336) **失败**：旧迁移验收临时重放历史表时，011触发器在 disabled 条件下仍规划不存在的执行历史表。保留 CI 和原 fixture 本地失败；修复为先分支判断 enabled 再查询执行历史。未删除或跳过旧验收，同一旧迁移与12并发测试修后通过。最终提交 CI 另行核对，不用旧绿灯替代。

第二阶段签名提交 `52711e3497d0d23e4b926941b58b9ffefab9528d` 已推送。其CI发现Go共享schema显式清单遗漏四件新schema；本地原样复现并补充注册，保留未知schema拒绝检查，修后通过。该问题仅测试注册清单，不改运行时、镜像或历史语义。最终新格式本地验收通过；最终签名提交的完整CI仍须独立核对。当前代码的全部Go包回归、50项replay、7项contracts、12项inputs、75项evaluation、56项backup、31项isolated及24项validation检查通过，测试数量本身不替代上述业务退出证据。既有 R16 历史预检补传/服务端门禁/恢复，R17 时间质量/旧版本，R18 前缀/迟到/取消/重跑由最终CI及受影响新格式回归继续验证。

## 5. 仍未完成，三类状态

- **软件/开发验证待办**：更大密度离线与回放的完整链测量；新历史格式仍按前缀重算与完整源重验证，大规模查询和CPU成本未达标；必要优化必须以测量驱动，不能以本次小例替代。全面S/M/L、冷/热缓存、目标资源故障及所有上限组合尚未通过。
- **参考环境待验**：用户尚未提供指定Ubuntu硬件/VM；全规模正式 Worker 每模式每规模至少三次及参考资源/吞吐/查询验收仍待办。macOS成功不替代该门禁。
- **真实材料待验**：同批次授权网络/工艺片段、设备映射与时钟依据、独立正常/攻击标注和保留集尚缺；历史真实部署/中间格式实例另列，不与软件缺口合并。

M0/M1既有骨架证据保留；M2/M3未改协议或判断，容量子项推进但真实适配未验；M4推进单活动attempt、资源绑定、新库存发布/恢复但不整体完成；M5推进评估及磁盘历史但R19未完成；M6新增终态恢复证据，冻结RC1未重包。R01/R02/R05/R06/R07/R11没有新增完成声明；R03/R04/R08/R09/R10/R12/R13的容量契约、核心执行、评估、任务及恢复子项推进，剩余退出条件继续有效。

## 6. 复现

依赖：Python3.11环境及 `services/analysis/requirements-test.txt`，Go版本见go.mod，Docker/PostgreSQL镜像，已有 `webui/out`。先检出需测的固定提交到独立目录，构建镜像并保留不可变image ID。以下均为开发验证：

```sh
docker build -f deployments/isolated-executor/Dockerfile -t cpag-isolated:r19-measured .
python scripts/validation/round19_capacity.py --dev-run --resource-profile r19-dev-s100-1 --image cpag-isolated:r19-measured --case-manifest docs/refactor/validation-round19/capacity-S-raw-attempt2/dual_source-1.json --output /tmp/r19-s100-new-1
# 使用不同的新输出目录独立运行三次；保留全部退出，不覆盖或挑选最快值。
python scripts/validation/round19_measurement_summary.py --output /tmp/r19-summary.json /tmp/r19-s100-new-1 /tmp/r19-s100-new-2 /tmp/r19-s100-new-3
python scripts/validation/round19_replay_spool_acceptance.py --image cpag-isolated:r19-measured --output /tmp/r19-spool-new
python scripts/validation/round18_lifecycle.py --skip-image-build --image cpag-isolated:r19-measured --history-format replay-history-checkpoint-delta-2 --output /tmp/r19-spool-life-new
python scripts/validation/round19_byte_fixture.py --output /tmp/r19-byte-input-new
python scripts/validation/round19_capacity.py --dev-run --resource-profile r19-dev-s100-1 --image cpag-isolated:r19-measured --case-manifest /tmp/r19-byte-input-new/case.json --output /tmp/r19-byte-new
```

上述第一次S100固定3e测量与后续源码提交有明确边界；重新用后续提交执行会产生新记录，不能改写现有样本的提交身份。私有完整记录保存在汇总所指本机目录；仓库仅保存白名单测量/哈希/公开失败日志，数据库会话和Worker凭据不上传。
