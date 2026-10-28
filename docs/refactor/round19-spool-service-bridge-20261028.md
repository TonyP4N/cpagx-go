# R19 正式回放存储分支与服务桥接

本阶段接在 `3e7340e` 离线预算/资源阶段之后，旧JSONL产物、默认版本、历史限额及旧回放校验不改。新分支解决显式checkpoint/delta存储的正式执行、验证、查询与恢复接入；不代表目标规模、完整容量边界或参考机性能已经验收。

## 明确选择与绑定

唯一新存储选择是完整profile内的 `replay.history_format="replay-history-checkpoint-delta-2"`。逻辑 `replay.version` 仍为 `dual-source-replay-1`；存储选择从语义配置指纹的transport字段中排除，但保留在完整profile指纹中。不能只改逻辑版本字符串便把旧历史当成新格式。

catalog从不可变配置复制payload `history_format`。Worker产物清单wrapper、core `run_manifest.json`、保留profile和history manifest的格式/上下文与同一run/attempt、输入、完整配置及语义指纹分别绑定；缺失、未知、串格式或跨attempt拒绝。新profile只走 `DualSpoolProfile`、`ReplaySpoolProfile` 和 `ReplaySpoolRunManifest`，不放宽旧schema。

新库存以 `history/manifest.json`、`history/history.sqlite3` 替代 `snapshots.jsonl`、`revisions.jsonl`，其余标准产物、到达记录、指标及保留原件不变。唯一允许目录为sources和history；混入旧JSONL、额外数据库journal、链接、缺失/改字节或不同库存均拒绝。Worker复制、schema校验、退出后发布和恢复重新发布都选择同一显式库存。

没有 `capacity_profile` 时，新存储仍受旧Budget约束：16MiB输出、22000到达、4096快照、8192修订及原输入限制。只有显式 `engineering-capacity-1` 与operator策略绑定才选择新预算；不能借新schema静默放大旧容量。

## Go不解释SQLite，限定CLI核验

Go先复用现有授权、数据库终态/attempt身份、发布manifest摘要、原件与全部产物字节摘要、精确库存检查，再调用固定模块 `cpag_core.replay_spool_cli`。根目录由服务选取，action仅允许verify/metadata/snapshot/revisions/graph/evidence；没有来自URL的路径、SQL、模块名或shell命令。

verify必须成功完整重放原始输入，返回精确验证标记 `source_replayed_storage_and_business_fields_verified`，并返回与Go已读到的core/history manifests及history manifest摘要相同的值。数据库状态只是 `sealed_storage_not_source_verified` 时并不能自行放行。Go另查来源类别、原始输入指纹、完整/语义配置指纹、run/attempt与格式，不能用CLI返回“成功”代替这些绑定。

CLI stdout独立限制8MiB、stderr限制64KiB；writer没有可绕过Write守卫的ReadFrom捷径。超限、非JSON、超时或子进程失败不返回部分响应。Go为每个子进程设置私有TMPDIR，在结束、报错及超时后删除临时重放数据库；进程内最多同时运行一个验证CLI，排队消耗原请求deadline。正式原件和失败运行证据不在临时目录内。

目前查询CLI仍完整重放校验，没有未验证的跳过算法开关。验证子进程受开发180秒/工程600秒上限，查询子进程10秒；这两个子过程加原件/产物散列的完整请求耗时仍需实测，不能把10秒子进程deadline写成大型证据请求已达10秒SLA。

## 查询形状与有界失败

服务保留旧result/snapshot/revisions/evidence路由和原业务字段。最终result从已全部验证的标准analysis/graph/events等产物读取，受冻结资源档字节预算，避免将CLI的8MiB交接界限误当成所有最终产物的上限。历史snapshot和证据经有界CLI返回；单份完整snapshot或完整selection超过8MiB时明确失败，不删字段凑通过。

新存储修订分页最多100条。证据支持ref_offset/ref_limit，默认100、最多100；完整selection和全部引用先验证属于指定到达前缀，再仅解析该页原件与帧字段，返回 `source-reference-page-1` 分页元数据。完整业务selection不因分页删除；超大selection仍可能碰到8MiB门禁，属于待测容量边界。

回放查询仍要求已验证终态。SQLite完整但原件缺失、摘要被改、无权限、attempt过期或恢复后缺证据，均不能提供可信结果。

## 验证与保留失败

- `spool-go-tests-attempt1.log`：既有Go回放回归通过。
- `spool-go-tests-attempt2.log`：真实Python导出到Go/CLI校验、result/snapshot/revisions/evidence、同大小SQLite篡改和缺文件拒绝通过。
- `spool-go-tests-attempt3.log`：完整jobapi/catalog包通过，包含旧回放门禁与历史资源兼容。
- `spool-worker-tests-attempt1.log`：新库存handoff、已移除容器凭据后的恢复、错格式拒绝通过。
- `spool-worker-all-tests.log`：首次全量发现新格式guard过早作用于旧故障样例，改变原生returncode保存顺序，失败保留。guard已限定显式新history格式；`spool-worker-all-tests-attempt2.log`全部30项重新通过。

新增负例还覆盖CLI输出有界复制、私有临时SQLite在截止后清理、新格式不提升无capacity配置预算、错误selector/页大小、Go精确库存输出上限+1和Worker解包前输出上限+1。输出负例使用稀疏文件/声明tar长度检查真实拒绝路径，**不称为真实1GiB正例产物或完整大规模实测**。

正式PG/隔离Worker小例、七任务及空库恢复由独立验收脚本记录。它们与函数级预算测试、真实目标数据密度、大字节正边界和参考环境吞吐分开登记；最终以固定提交/镜像对应的正式验收报告为准。

## 阶段一CI迁移回退修复

stage1 CI `40628284336` 的两个任务均在原 `TestMigrationPreservesPublishedHistory` 报42P01。原CI日志保存于 `migration-stage1-ci-first-failure.log`；`migration-compat-reproduction/`在临时PG中原样复现，未改旧fixture。

原因是011触发器用单个 `policy=enabled AND EXISTS(m4_job_attempts...)` SQL条件。PostgreSQL在判断左侧false前也规划整个表达式；旧迁移测试事务中暂时移除attempt历史表重放004，disabled策略仍因此触发缺表错误。

011改用独立的PL/pgSQL外层IF，再在enabled分支查询历史。disabled时不触碰重建中的旧表；enabled时原退出门禁不降级。`migration-compat-after-fix/`同时通过原迁移保留测试和12并发单任务门禁，数据库导出/清理返回0；不以删除fixture或跳过迁移测试掩盖失败。
