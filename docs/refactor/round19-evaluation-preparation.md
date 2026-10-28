# R19 受控评估准备（独立阶段，2026-10-28）

本阶段处理同一保留 S100 产物的完整评估服务冷请求成本。它不重跑 Worker，不改变原始分析产物或金标，不是 Ubuntu 参考机、M/L、真实工业数据或双 Worker 故障验收。

## 先前失败与实际瓶颈

固定 `aa16a4db525e55d0c435fc16bad5bb5edbab94b6` 的 CLI 10 秒试验超时，延长观察上限后的同一命令 11.026 秒完成；正式 HTTP 冷请求 17.121 秒后 409，热请求 10.013/10.014 秒后 409。根因包括 Go 首次完整语义验证及 Python 对同一请求重复验证/适配。只加 `service-publication-verification-reuse-1` 后，正式冷请求仍 18.890 秒后 409，热请求则 3.332/2.416 秒成功。不能把进程热缓存结果当作服务重启后的冷请求通过。

新增 `evaluation-preparation-1` 将首次完整核验、requested projection 适配和后置全字节核验作为显式持久操作；读取只复用服务自己产生并冻结的完整 projection，继续逐次核对当前权限、DB publication/attempt/payload、全部原件/产物实际字节、严格库存、配置与数据集注册上下文。没有准备记录时，旧直接适配路径仍保留；已有非 ready 或来源已变的准备记录时明确拒绝，不能借旧路径绕过。

## 接口与终态

- `POST /api/v3/runs/{run}/evaluation-preparation`，body 只接受 `{"projection":"dual"}`，可选 `network/process/dual`、默认 dual。需要数据集写权限；排队与审计在同一 DB 事务提交。202 仅表示排队；已 ready 的同一绑定可返回 200。
- `GET .../evaluation-preparation?projection=dual` 返回 `preparation`：`id/run_id/attempt/source_attempt/preparation_attempt/projection/strategy_version/state/reason_code/publication_sha256/document_size/cost`。`attempt` 与 `source_attempt` 均为源分析 attempt；`preparation_attempt` 为准备执行序号。ready 增加 `document_sha256/duration_seconds`。GET 也必须成功写审计。
- `GET .../evaluation-input?projection=dual` 在真实 ready 后才返回完整 adapted object；待处理、失败或来源变化返回 409，不返回半 JSON，也不把 202 当作计算完成。
- 已保存 evaluation 的导入、详情、下载、预测原件证据与 reference locator 通过内部 `evaluation-service-envelope-1` 复用核验后的 DB projection。外部用户 body 不携带信任上下文；默认 Python CLI 继续完整验证。

`cost` 记录 verification/projection/postcheck/storage/total seconds 及资源策略版本。每个真实执行在 `v3_evaluation_preparation_attempts` 单独保留终态与原因；重试不能覆盖先前失败。安全协调原因与私有服务日志区分，API 不返回 owner、内部路径、完整私有诊断或原始 bytea。

## 有限预算与恢复

| 项目 | 明确上限/规则 |
| --- | --- |
| 单份 projection | 旧资源版本 8 MiB；显式 dev/engineering 资源版本 128 MiB |
| 全部 ready projection | 1 GiB，完成事务内独立 advisory lock 串行求和 |
| 同时准备 | DB session advisory lock + 同一 ControlRoot 的继承文件锁，最多 1 |
| 准备执行次数 | 每条最多 100，原失败历史保留 |
| 准备 context | 1800 秒覆盖验证、投影、后检与 ready 写入；超时/取消不发布 ready |
| Python 资源 launcher | 独立 alarm 最多 1800 秒、CPU 1800 秒、文件 4 GiB、FD 128、Linux address space 2 GiB；macOS 地址空间限制未强制，实际 receipt 标明 false |
| 读取 | 原有 10 秒完整请求预算；evaluation evidence 完整序列化后最多 8 MiB，超限 409 且无半成功响应 |

Go JSON 语义重建在同进程同步执行，context 在 DB/文件哈希等检查点生效，不能在某次 JSON CPU 解析中硬抢占。Python 独立 alarm 不能被描述成 Go 所有 CPU 的硬杀界。超时后的 ready 写入使用已受限 context，不能过期后发布结果。

Go 退出后 Python 仍持有同一文件锁，下一进程只有在实际子进程退出（含独立 alarm）后才可重领。同一协调范围恢复将先前 preparing attempt 记 failed/service_restarted，再启用新 owner；旧 owner 的 CAS 不得提交新终态。跨 ControlRoot 的 preparing 不推断退出、不改 owner/state，给出 `coordination_scope_mismatch`，需要原协调范围/人工有证据恢复。DB/文件锁错误有安全 coordinator reason 与私有日志，unlock 本身也限 3 秒。仅在取得两把锁后清理本服务私有残留工作目录；有界子进程 receipt 先保留到私有 evidence。

迁移014只增加派生准备与 attempt 表。format6 备份由独立库存实现保留 bytea 与哈希/身份；queued/preparing 在终态停写备份时明确拒绝。旧 format4/5 的历史读取保留。全链恢复实际验收另记，不能只凭迁移或单测宣称恢复已通过。

## 已保留证据

`validation-round19-evaluation-preparation/` 保存小型公开收据、完整请求耗时及先失败后修复单测日志；含凭据的配置、SQL dump、完整返回体与运行日志只在私有 `/private/tmp/cpag-r19-*` 试验目录保存，未复制进文档或提交。

首个真实 ready + 进程重启 + 完整 v3 生命周期：`/private/tmp/cpag-r19-preparation-http-attempt2`。准备真实耗时 17.352 秒（verification 15.257、projection 1.846、postcheck 0.248）；重启后冷/热完整 adapted 为 0.240/0.231 秒。import/duplicate/detail/download 分别 1.391/1.375/1.287/1.242 秒；预测原件查询 2.916 秒、2,934,468 字节；reference locator 1.548 秒。独立生成的密度金标为 199/0/0。OS 缓存未清理；这是同一旧 S100 产物的开发机软件证据，不是固定最终配置三次或完整容量接受。

这个首次成功在后续原子审计、协调诊断和 evidence 8 MiB guard 补强前取得。当前源码必须另外复测，不把早先成功挪用为最后版本的结果。

保留的失败包括：默认 Go cache 权限导致的测试启动失败；新准备表尚未接入 fake DB fixture 导致旧视图测试失败；cross-scope 无安全原因的先失败测试；审计失败仍留下 queued、GET status 未审计的两项先失败测试；首次隔离 HTTP 因本机 listener 权限未启动。这些记录不被删除，也区分环境/脚本问题和项目实现失败。

真实双 Worker 竞争/租约/退出/取消仍需独立执行验收；DB 并发 claim 或准备进程恢复不能替代实际双 Worker 计算生命周期。M/L、128 MiB/10k 边界全层证明、参考环境和真实工业数据状态沿用各自未完成门禁。

## 最后安全修复后复测

`/private/tmp/cpag-r19-preparation-http-attempt3` 冻结运行源 SHA256 为 `68ccf1edb5ab7cef9db8b896f98248839286db4512a465eb9db89387aa4f1aae`，服务 binary SHA256 为 `4dd947c7fc18ebb116060d89845b261d7b87f6853f8b18adc5f318a9cba68f22`。基线 commit 是归档底座，实际执行包括独立逐件源清单中的未提交准备机制；不将底座 commit 冒称最后运行源码。

完整实际准备 16.977 秒（verification 14.833、projection 1.864、postcheck 0.232、storage 0.048）；等待真实 ready 17.493 秒。重启后冷/热 evaluation-input 为 0.235/0.228 秒，import/duplicate/detail/download 为 1.344/1.284/1.221/1.226 秒，预测原件 2.834 秒、reference locator 1.490 秒，完整返回体均在各自字节限制内；独立金标 199/0/0。原产物前后哈希相等。

同一隔离运行另对 network projection 真实 preparing 中 SIGKILL API（Go 验证阶段、尚无 Python child），再用相同 ControlRoot 重启：attempt1 保留 failed/service_restarted；attempt2 重新完整验证后真实 ready（16.807 秒），旧 owner 在新 attempt preparing 时 SQL CAS 更新 0 行，恢复后的完整 network projection 200。它证明准备进程恢复；独立 Python 测试另证明继承 FD 在父关闭后保持协调锁，实际子进程独立 alarm 退出124后才释放。两项均不替代实际分析双 Worker 故障试验。

Focused Go catalog/jobapi 全绿（15.763/5.671 秒），go vet 两包通过。Python 实际 alarm/继承锁测试2项通过（2.23秒）。格式6的小例真实 ready/空库恢复由独立验收记录保存，不能与本次同旧 S100 产物的软件请求复测混为一次容量运行。最后版本6个新 S100 Worker 运行仍待主流程冻结后另外执行。
