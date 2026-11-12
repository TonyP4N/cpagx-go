# R17 响应时钟补验：服务版本兼容核验

基线 `288ffc068c0196d0725478c3404bdca0a2aaf26e`；本记录对应尚未提交的补验工作区，最终实现 SHA、正式 Worker/恢复/浏览器及完整 CI 以主补验记录绑定。预登记答案见 [服务版本场景](round17-response-clock-service-scenarios.md)。本增量不改默认入口、冻结 RC1、任务状态或历史归一化数据。

## 发现与修复

原 Go 校验器将 bounded 分析版本固定为 `bounded-dual-source-1`。直接切换该值会使历史结果无法读取；只宽松接收任意版本又会掩盖未知语义。因此按以下边界显式处理：

- 有界配置只读取 `bounded-dual-source-1`、`bounded-dual-source-2`；旧 synthetic 配置仍只读取 `synthetic-dual-source-1`。dual manifest 与 analysis 版本必须一致，未知或混合版本拒绝。既有 RunManifest 不增补字段，继续通过其产物哈希绑定这些文件。
- 新首次发布的 bounded 计算必须是 v2。v1 只允许已完成结果的幂等完成及历史读取，不因重试破坏原有结果；依旧执行全部原件、配置、产物、图与证据校验。没有新增任务状态。
- 历史 v1 的 result、graph、evidence 响应单独增加 `compatibility`：`analysis_version=bounded-dual-source-1`、`status=historical_semantics`、`known_limitations=[response_clock_quality_not_enforced]`、`reanalysis_required=true`。不改 retained analysis，也不把旧版本中可能存在的 supported_candidate 静默改成当前语义。当前 v2 不带该历史提示。
- Python 版本重算分派、操作时间质量与候选门禁由核心补验实现。Go 保持版本、投影及原始证据校验职责，不引入第二套关联算法。Go 接受 `succeeded_with_warnings`；不另行硬编码 operation 警告内容。

## 实际局部结果

[逐条测试日志](validation-round17-response-clock/service-go-tests.jsonl) 来自修复后新执行的 `-count=1`，零失败：catalog 14 项顶层测试、jobapi 13 项、jobs 3 项，共 30 项；含子测试共 38 条通过记录。

| 场景 | 实际结果 |
|---|---|
| 白名单与发布策略 | v1/v2 历史读取通过；未知版本、错误配置族、混合版本拒绝；新 v1 发布策略拒绝，已完成 v1 幂等允许，新 v2 与旧 synthetic 发布策略允许 |
| 原始 v1 产物 | 直接使用核心修复前保留的 `tests/fixtures/r17-response-clock-v1`，没有用新算法重新生成；完整 Go 原件/投影核验通过，原件与归一化结果未改 |
| 历史 HTTP 证据响应 | 同一个 Go evidence handler 返回 200，含 historical_semantics/reanalysis_required 提示；原始证据仍可查 |
| 新 v2 产物与证据 | 现有 bounded synthetic 和 real_unvalidated 双捕获跨语言测试明确断言新导出为 v2，完整 Go 核验和有限规则 HTTP 查询通过，不出现历史版本提示 |
| scalar 与多件既有回归 | catalog/jobapi/jobs 全部通过，包含旧 scalar SQL NULL 查询和现有双源/证据边界 |

复现：

```sh
GOCACHE=/tmp/cpag-go-build GOMODCACHE=/tmp/cpag-go-mod \
  go test -count=1 ./internal/catalog ./internal/jobapi ./internal/jobs
```

早先并行测试曾因 iCloud 的 `.venv/pyvenv.cfg` 占位等待解释器启动；单独下载该原有配置后完成。本报告日志使用恢复后的新执行，等待时间不是计算耗时或容量验收证据。`dual.go` 曾为不可读占位，按精确基线 GitHub 文件恢复；Git blob SHA `9878ed60a8eace1b498d88fe67ff3732b30942bf` 与本地索引一致后才编辑，原占位文件保留在本机临时备份，不作为公开结果。

上述是版本兼容与局部服务核验，不能替代正式数据库首次发布/幂等完成、原失败夹具的 Worker/CLI/图/恢复和普通点击补验，也不能单独关闭第十七轮。真实材料与真实工业效果仍未由生成样例验证。
