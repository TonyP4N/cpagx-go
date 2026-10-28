# R19 统一预算入口：已实现边界与未完成门禁

本文件接续 `round19-followup-plan-20261028.md`，对应2026-10-28工作树。旧默认入口与无容量字段的配置保持原预算。新增预算、数据库单任务门禁和S100开发资源档不等于全链扩容验收；真实M/L、独立128MiB/64MiB/8MiB字节边界和参考机性能仍须按预登记实跑。

## 三个不同的版本绑定

| 字段 | 设置者、保存位置 | 行为 |
|---|---|---|
| `capacity_profile` | 用户选择的不可变dual profile，唯一新值 `engineering-capacity-1`；catalog复制进job payload | 必须同时声明 `analysis_mode=bounded-real-capable-v1`；包含在原配置指纹内。缺省严格使用旧输入/分析预算，未知、空值和payload/profile不一致拒绝。当前新容量profile与旧replay同时出现明确拒绝，属于尚未贯通的软件缺口。 |
| `capacity_policy` | 私有Go服务配置；唯一启用值 `engineering-capacity-1` | 显式启用数据库持久的全站最多一个尚未验证退出attempt；缺省不启用，也不会解除此前已持久启用的策略。新容量任务提交要求matching operator policy。 |
| `resource_profile` | 私有Go服务及Worker配置；`r19-dev-s100-1`或`engineering-capacity-1`，缺省保持旧资源 | catalog将operator选择冻结到job payload，不修改用户profile或原语义指纹。新提交/未完成发布及Worker计算要求资源选择绑定；历史读取只承认冻结payload的已支持资源版本及其原上限，不由当前operator更大的选择重新解释。 |

公共run请求不接受用户自行设置这两个operator字段。OpenAPI `OperatorBudgetSelection`只是私有配置字段片段，并未新增公共调高资源权限。

## 固定预算与阶段界限

Go `internal/capacity`、Python `cpag_core.capacity`均枚举固定版本，无任意表达式或无限上限。Python `resolve_capacity_profile(config)`返回frozen Budget，`parser_limits(config)`返回显式packet/capture/process/stream对象供核心使用。

| 项 | 无capacity_profile | engineering-capacity-1 |
|---|---:|---:|
| 网络文件件数 | 4 | 4 |
| 单件抓包 / 合计 | 16MiB / 16MiB | 64MiB / 128MiB |
| 合计帧 / 单帧 | 10000 / 262144 bytes | 100000 / 262144 bytes |
| CSV字节 / 逻辑数据行 / 列 | 2MiB / 1000 / 16 | 8MiB / 10000 / 16 |
| 配置document | 64KiB | 8MiB；外层请求另预留64KiB封装，不能用封装余量增加document |
| 操作 / 变化 / 候选预算 | 100 / 1000 / 10000 | 10000 / 10000 / 100000 |
| 输出预算 | 旧Worker16MiB；原Go单文件检查64MiB | 目标1GiB，还受operator实际资源档更早的限制 |
| 到达 / 快照 / 修订候选预算 | 22000 / 4096 / 8192 | 40000 / 45000 / 90000，当前正式新容量replay尚未启用 |

原始上传本来已允许抓包单件64MiB和CSV单件8MiB；上传成功始终不表示正式分析能处理。新预算贯穿Go配置请求、原始摘要校验、catalog提交、payload/profile绑定、CSV逻辑行计数、帧总数和产物验证入口；旧profile仍先到旧界限而拒绝。Go/解析器单测已测+1件、+1字节预算值、10000逻辑行/+1行/+1列，不能把这些函数级测试写成正式链路大字节样例已验收。

`r19-dev-s100-1`固定2 CPU、2GiB、900秒、512MiB输出，用于相同旧profile/输入的资源对照。`engineering-capacity-1`目标资源档固定4 CPU、8GiB、1800秒、1GiB输出；这些是运行预算，不是已经测得支持目标规模的结论。未完成的入口、输出历史、查询、备份与回放链路必须继续明确拒绝或标未验证，不能仅因新常量存在宣称整体贯通。

## 单机单任务门禁

迁移 `011_capacity_policy.sql` 新建 `m4_capacity_policy`，默认profile为空。显式启动配置通过 `Repository.EnableCapacityPolicy` 启用；已有任何未验证退出的attempt时拒绝首次启用，避免隐藏存量计算。重新应用迁移不重置已启用策略。

全部claim在同一数据库事务中取得固定advisory锁，检查所有历史未退出attempt及缺失退出历史，再领取候选。过期租约、failed、queued retry或cancelling均不能释放名额。已有外部退出核验或gated `RevokeUnstarted`证明确未启动后才允许下一次领取。数据库trigger还阻止连接同一库的旧SQL领取绕过新Go入口；policy行丢失明确拒绝，不能当默认关闭。

真实PostgreSQL测试 `TestSiteCapacityPolicySerializesAllUnexitedAttempts` 已通过：12个并发claim仅1个成功；策略未启用时旧独立claim仍可并行存在；有未解释旧attempt拒绝启用；租约过期/取消请求不释锁；旧原SQL被trigger拒绝；gated未启动证明与取消ACK后可领下一任务。这是数据库级并发与生命周期证明，未冒充多实际计算容器同时启停的完整端到端测试。

## Go HTTP预算与历史读取

`cmd/cpagx-v3`按operator资源档选择下表期限；未知版本在私有配置读取及预算选择均拒绝。请求文档无法改变连接期限。ReadHeaderTimeout仍5秒，IdleTimeout仍30秒。

| resource_profile | public ReadTimeout / WriteTimeout | internal ReadTimeout / WriteTimeout |
|---|---|---|
| 缺省 | 30秒 / 60秒 | 15秒 / 30秒 |
| r19-dev-s100-1 | 30秒 / 180秒 | 15秒 / 180秒 |
| engineering-capacity-1 | 60秒 / 600秒 | 60秒 / 600秒 |

Worker独立publication client按开发180秒/目标600秒，心跳仍原短超时；Go写响应期限现在与显式publication预算相容。连接deadline不是全流程SLA证明；目标全链1800秒和证据查询10秒仍需完整测量，不能以HTTP允许等待更久作为达标。

历史读取通过 `validHistoricalPayload/readPayloadBudget`验证冻结输入、配置及资源版本，仍重新校验原始字节、产物摘要、完整目录与发布身份。新增或未完成发布继续严格operator绑定。`Server`没有浅拷贝，缓存mutex不复制；已验证单条缓存不能绕过引用/字节校验。带资源档证据查询的分页最多100条、独立8MiB响应上限，与主任务S100查询回归共同验证，旧无分页请求保持原行为。

## 证据、失败与阶段提交范围

`validation-round19-followup/`中保留：

- `capacity-go-tests-attempt1.log`：根module依赖网络和构建缓存权限失败，未当成代码通过。
- `capacity-go-tests-attempt2.log`：新测试TempDir经macOS `/var`符号路径触发预期路径守卫，测试改为解析真实路径；同时adapter当时进行中的独立store测试失败已交回原负责者。
- `capacity-go-tests-attempt3.log`：capacity/jobs/jobapi包通过。
- `capacity-go-tests-attempt4.log`：历史读取调用点改造时metrics helper无payload变量的编译失败，原记录保留；仅这两处恢复旧调用后重试。
- `capacity-go-tests-attempt5.log`：新旧预算、历史资源兼容及旧真实投影校验通过。
- `capacity-go-tests-attempt6.log`：包含最终operator HTTP预算、配置未知版本拒绝/缺省不启用、新旧预算与历史资源兼容，capacity/jobapi/catalog聚焦测试全部通过；OpenAPI YAML亦已解析核对。
- `capacity-python-tests-attempt1.log`：3项版本/解析预算和10000逻辑行/+1拒绝通过。
- `capacity-postgres-attempt1/`：Docker daemon500，未开始PG测试，原stderr/report保留。
- `capacity-postgres-attempt2/`：PG已启动；测试准备数据将state置failed却未清租约，数据库CHECK拒绝。修正测试准备，未更改生产约束，失败原件保留。
- `capacity-postgres-attempt3/`：数据库级12并发及退出证明门禁通过，导出/容器清理均返回0。

PG完整SQL备份保留本地；提交可选择公开 `report.json` 与 `tests.log`，不递归加入所有私有运行目录。

本子任务可纳入第一阶段提交的文件：

1. `internal/capacity/{budget.go,budget_test.go,http.go,http_test.go}`；`internal/jobs/{capacity.go,jobs.go,migrations/011_capacity_policy.sql,integration/capacity_test.go,integration/cmd/cpagx-v3/main.go}`。
2. `internal/jobapi/{capacity.go,capacity_test.go,server.go,dual.go,dual_test.go,multi.go,packet.go,replay_validate.go}`。其中server/dual已与主任务缓存、分页实现整合，不能只取早期补丁覆盖后续工作。
3. `internal/catalog/{capacity.go,capacity_test.go,server.go,datasets.go,preflight.go,runs.go}`；`schemas/DualSourceProfile.schema.json`；`services/analysis/src/cpag_core/{capacity.py,dual_source_rules.py}`；`tests/core/test_capacity_profile.py`。
4. 本文件与 `api/openapi/v3.yaml`，及有选择的上述公开验证日志。

核心预算消费、流式导出、Worker资源和测量由主任务同期实现，必须协调成可运行的提交；本清单不宣称这些共享文件只由本子任务修改。固定提交/镜像后的三次S100独立成功、真实目标规模与字节边界、正式新回放历史、全链计量、恢复/授权与既有回归仍按各自门禁记录，R19继续开放。
