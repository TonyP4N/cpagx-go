# R17 服务增量与局部核验

起点为 `6897707`、`refactor/m1-evidence-core`。本记录对应未提交工作区，尚不代表最终提交、完整 CI 或第十七轮整体关闭；最终提交 SHA 和正式服务/恢复/浏览器记录由主验收报告绑定。预登记答案见 [服务场景](round17-service-scenarios.md)。R16 历史报告、旧配置、旧结果保持；默认入口、冻结 RC1 和 M4 任务状态机未切换，未进入 R18。

## 实现契约

- V3 当前不可变预检与原事务门禁保留。真实有限解析须明确 `analysis_mode=bounded-real-capable-v1`、`synthetic=false`；来源、批次、授权声明与数据集逐项一致，来源真实性及物理含义仍为 `accepted_unvalidated`。材料、配置类别、映射及时间依据不足不能入队；bounded synthetic 同样不能绕过映射/时间字段，旧 synthetic scalar 形态保留。
- `payload.network` 保留第一件；多件另有完整有序 `networks`（2—4 件，第一件必须相同、引用与 SHA 不重复）。V3 按上传时间、文件 ID 排序，并以 008 迁移的 `v3_run_bindings.network_file_ids` 固定全部 ID。旧/单件保持 null。008 可重复应用；数据库触发器检查全部捕获文件的所属数据集、角色和重复，并保护已绑定的第二至四件免于修改/删除。
- 导出保留 `dual/sources/network.pcap`，附加原件为 `network-001.pcap` 至 `network-003.pcap`；dual manifest 的 `network_inputs` 和发布 manifest 顶层 `networks` 分别固定完整顺序及 SHA。Go、Worker、发布和查询同时校验动态 inventory、每件原件哈希与原始帧。证据用 `(文件 SHA, 帧号)` 定位，不跨文件串帧。真实产物旗标、来源声明和有限规则 finding 的投影、查询均保持一致。
- Worker 对全部原件逐件校验后只读挂载，仍使用隔离执行和已有发布/退出证明。真实输入依配置确定类别，CLI 不添加不存在的 `--real` 选项。Excel 保持接收待可追溯 CSV 转换，不允许当 CSV 直接入队分析。
- 分析当前仍执行合计 16 MiB 网络、每件 16 MiB、10,000 帧、2 MiB CSV/1,000 逻辑记录等有界限制；上传限制不是分析能力证明。首版候选 64 MiB/件、128 MiB 合计和 10,000 条工艺记录的容量、资源及性能验收尚须 R19，未由本记录关闭。

## 实际局部核验

执行环境为本机锁定 Python 虚拟环境和 Go；输入均为生成样例，真实来源分支只证明软件路径，不证明工业数据正确性。

| 检查 | 实际结果与证据 |
|---|---|
| Go catalog/jobapi/jobs | 全通过；分别 13、16、3 条通过事件（含子测试），零失败。[逐条 JSONL](validation-round17/service-go-tests.jsonl) |
| Host Worker | 15 项通过，含取消、超时、凭据边界、幂等发布和退出证明。[日志](validation-round17/service-worker-tests.log) |
| 隔离 Worker/恢复 | 19 项通过，含新增真实分支双捕获归档交接、全部 SHA 顺序与 inventory、额外原件拒绝。[日志](validation-round17/service-isolated-tests.log) |
| 新 Go 跨语言产物 | bounded synthetic 与 real_unvalidated 各以两件捕获和有限规则导出；Go 校验完整产物与所有原始证据、拒绝次件篡改。通过 `TestBoundedRealAndSyntheticMultiCaptureExports` |
| 有限规则 HTTP 查询回归 | 正式集成曾暴露 `?change=finding_id` 返回 409；修复后同一 Go HTTP handler 对两种来源的每一 finding 返回 200，`selection.rule_finding` 和原始证据非空，真实来源声明保留。该回归包含于上述跨语言测试；正式 API 全链以主验收最新重跑结果为准 |
| 008 数据库约束 | 已登记 `TestMigration008CaptureBindings`：重复应用、旧 scalar、有效双件、重复/错角色/缺失/主件不符/第五件拒绝及次件修改/删除拒绝。必须由独立临时 `m4_validation` 数据库执行，结果以主验收执行记录为准；此处不把仅编译或无 DSN 的 skip 算通过 |

复现命令：

```sh
GOCACHE=/tmp/cpag-go-build GOMODCACHE=/tmp/cpag-go-mod \
  go test ./internal/catalog ./internal/jobapi ./internal/jobs
PYTHONPATH=services/worker:services/analysis/src \
  .venv/bin/python -m unittest discover -s tests/worker -v
PYTHONPATH=services/worker:services/analysis/src \
  .venv/bin/python -m unittest discover -s tests/isolated -v
# 仅在明确的隔离临时 m4_validation 数据库中：
# cd internal/jobs/integration
# M4_TEST_DATABASE_URL=<private-disposable-dsn> go test -run TestMigration008CaptureBindings -v
```

第五件网络文件可以作为接收材料保留，但 V3 运行入口以 422 `source_count` 拒绝，无 job/binding。`preflight_stale`、`preflight_incomplete`、`insufficient_basis`、`source_provenance_mismatch`、无权限直接 API 门禁、三次正式 Worker/CLI 一致性、终态成套恢复及普通点击浏览器由主验收独立执行；不能用以上局部测试替代其结果。

## R16 scalar 兼容回归修复

主验收在 `ac980a6` 后实际复跑 R16 时，scalar 运行创建返回 201，随后查询返回 404。该缺陷不是任务丢失：新 nullable `network_file_ids` 的 SQL NULL 无法直接扫描进命名类型 `json.RawMessage`，查询错误被隐藏为无存在性泄露的 404；多件非 null 路径不受影响。

先增加 `TestRunGETPreservesSQLNullLegacyCaptureBinding`，通过真实 `database/sql` 转换和同一个 HTTP handler 复现：scalar 失败 404、multi 通过 200；随后只将 SQL 扫描目标改为标准 `[]byte`，输出时再转为 `json.RawMessage`。未改历史绑定或运行状态。

修复后 catalog/jobapi/jobs 全通过；该 regression 连续两次执行，scalar NULL 和 multi 顺序数组均返回 200，scalar 输出仍为 null。独立结果见 [scalar GET 回归日志](validation-round17/service-scalar-get-regression.log)。正式 R16 数据库/隔离 Worker 全链仍以主验收后续实际重跑为准；不把这个局部回归冒称整个 R16 复跑已通过。
