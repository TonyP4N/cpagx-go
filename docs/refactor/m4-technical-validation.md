# M4 持久任务技术验证（独立原型）

核验日期：2026-10-24。此变更用于验证方案中的 PostgreSQL 领取与 fencing 机制，**不是 M4 完整验收，也不切换默认任务系统**。已有 Go API、Python/Celery executor 和部署入口未接入本包；回滚只需停用原型，旧服务和旧产物不依赖新表。

## 交付边界

- `internal/jobs`：使用标准 `database/sql` 的独立 repository；生产模块不引入数据库驱动。
- `internal/jobs/migrations/001_jobs.sql`：只创建 `m4_jobs` 与领取索引。无自动启动迁移，不更改既有表。
- `internal/jobs/integration`：独立 Go module，固定 pgx v5.7.6 驱动及 go.sum；必须单独执行，根目录 `go test ./...` 不会替代此数据库验证。
- `deployments/compose.m4-validation.yml`、`scripts/m4/validate-postgres.sh`：专用 compose project、本机端口 55439、临时存储和明确的测试密码；不使用生产凭据。镜像固定为 PostgreSQL 17.6-alpine 的 digest `sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94`。

## 状态语义

`queued → running → succeeded / failed`；可重试错误回到 `queued`，非可重试错误直接 `failed`。重试次数 1–100；失败重试延迟按 attempt 从 1 秒指数增加，上限 256 秒。到期任务仅在 attempt 未耗尽时可再次领取；最终 attempt 到期后，下一次领取扫描将其标为失败。

领取在单条 CTE UPDATE 中通过 `FOR UPDATE SKIP LOCKED` 锁定候选，并增加 attempt。后续心跳、失败与完成必须匹配 id、attempt、worker、running 状态和未到期租约。租约范围 1 秒至 1 小时，比较与延长均以数据库时间为准。

取消 queued 任务直接进入 cancelled；取消 running 任务先进入 cancelling，禁止继续心跳、失败、完成与再次领取。只有持有相同 attempt/worker 的 `AcknowledgeCancel` 才能确认 cancelled。**调用方必须先确认该子进程已退出**；原型没有 worker，不能据此宣称进程终止已验证。重复 Cancel 保持 cancelling/cancelled 及其他终态，不覆盖成功结果。找不到任务返回 ErrStale。

完成只接受 `jobs/{id}/attempt-{n}/{sha256}.json` 的 attempt 独立路径和合法摘要格式，成功后拒绝再次完成。**这只是数据库元数据与身份约束，不验证真实字节、文件持久化或排他创建**。生产发布器仍须先在受控目录排他创建、校验摘要并持久化，再写元数据；崩溃留下的未发布文件需另行回收。

## 已执行

1. 根 module `go test ./internal/jobs`：通过。验证路径逃逸、非法摘要与 attempt 独立路径。
2. 在真实 PostgreSQL 17.6 上运行 integration module 的 `go test -race -count=1 -v ./...`：通过；调用的是实际 Go Repository SQL，不是复制 SQL 的替代测试。
3. 故障场景：人为将数据库 lease 置为过期，模拟失去心跳后的回收；旧 attempt 心跳/完成/失败被拒绝，新 attempt 成功领取。最终 attempt 到期后转失败。
4. 12 个并发 Go 领取者竞争同一任务：恰好一次领取成功。
5. 可重试错误不能在 available_at 之前领取；后续 attempt 受 max_attempts 限制。非可重试错误即使未耗尽 attempt 也直接失败。
6. running 取消保留 cancelling，重复取消幂等；旧 attempt 不能确认取消；当前 attempt 可确认。取消后迟到完成被拒绝。
7. 任意发布路径被拒绝；正确元数据只能完成一次；取消成功任务保持成功状态。

复现：在仓库根目录执行 `./scripts/m4/validate-postgres.sh`。需要 Docker、Go 与已缓存或可下载的固定依赖。脚本建立独立数据库，测试完成或失败均通过 trap 停止并移除该 compose project。测试表会被 TRUNCATE，因此手动执行 integration module 时也只能使用专用可丢弃数据库。

## 尚未验证 / 缺项

- 未实现常驻 Go worker、Python 子进程调用、真实 SIGKILL/超时/process-group 回收、取消时的退出确认、CPU/内存/磁盘限制。租约过期模拟不是杀进程证据。
- 未实现实际不可变产物发布、文件内容摘要校验、manifest 完整性与 DB/文件一致性恢复；不能将元数据测试视为完整发布验证。
- 未进行 PostgreSQL 重启/断电/网络分区、连接中断、磁盘耗尽、多主机时钟、持续压力和长时间运行验证。本次数据库使用 tmpfs，不证明数据库磁盘持久性或备份恢复。
- lease 过期后由下一次 Claim 惰性处理；尚无独立定时回收器、指标或调度宽限 SLO。cancelling 状态需要 worker 或恢复器独立确认退出，不能仅凭 lease 到期擅自宣布进程已结束。
- 无 API/权限/配置/默认切换、运行输入契约与数据集绑定、幂等 enqueue key、任务历史审计、资源清理和运维恢复工具。Enqueue 主键冲突会返回数据库错误，不代表幂等成功。
- 无生产迁移回滚脚本；原型表可在确认没有消费者后单独删除。保留旧系统并不等于已实测整套系统回滚。

结论：领取原子性、租约 fencing 和核心数据库状态变更有真实 PostgreSQL 测试支持。默认切换仍需补齐 worker、真实故障、发布一致性与运维验证。

### 已实现但未完成外部行为验证

- `ArtifactKey` / `Complete` 只实现路径身份与摘要格式校验；真实文件系统字节验证、排他写入与落盘没有实现，不能称为已验证不可变文件发布。
- repository 提供内部 Go 方法；没有内部 HTTP API、Worker 凭据或鉴权实现，相关行为未验证。
- `Cancel` / `AcknowledgeCancel` 的状态与 fencing 已经数据库验证；子进程启动、停止及调用方确认退出的行为没有实现，未验证。
- cancelling 不进入 Claim 的回收范围；这样不会因租约过期重复执行正在取消的任务，但可能停留不退出。恢复器必须先独立核实原进程状态，再确认取消；该恢复流程尚未实现和验证。

集成测试在迁移与清表之前还检查 `current_database() == 'm4_validation'`，其他数据库直接拒绝。此护栏不能替代使用专用可丢弃数据库的要求。
