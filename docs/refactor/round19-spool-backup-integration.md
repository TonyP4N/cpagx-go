# R19 磁盘回放历史备份及正式小例衔接

基线为第一阶段提交 `3e7340e`。本页记录显式历史存储格式的备份、评估适配和正式 API
恢复子项；逻辑回放版本仍为 `dual-source-replay-1`，不是目标规模性能或工业适用性验收。
R19 未结项，R20 未启动。

## 版本与库存

只有 `profile.replay.history_format='replay-history-checkpoint-delta-2'` 才选择新格式。
备份核对 profile、payload、发布 wrapper、核心 run manifest 的历史格式一致；省略字段
继续使用旧 JSONL 库存。未知或显式 null 格式拒绝，不能当作旧版省略。

新库存以 `history/manifest.json` 和 `history/history.sqlite3` 替代
`snapshots.jsonl`、`revisions.jsonl`。其余标准产物、原始输入及到达记录仍保留。
备份按版本取精确文件集合，拒绝缺件、额外 WAL 等可变文件及链接；复制后通过
`replay_export.verify_task` 的新分派重放原件核验，不把 SQLite 自身的存储校验状态
误写成已经核验原件或到达前缀。

SQLite 历史 manifest 绑定 run/attempt。不同运行的物理哈希不要求相同；跨运行及
CLI/Worker 对比使用**完整重建快照、修订和其余语义产物**的哈希，不删除业务字段。
每个运行的历史 manifest/数据库物理哈希另存，恢复后逐件比对。

评估适配器按显式格式使用 `iter_verified_snapshots` 逐条重建，仍仅选择经过核验的终态；
首次出现和撤回统计独立保留。新侧包绑定历史格式、历史 manifest 摘要和完整文件哈希。
旧格式的 adapter binding 不增加新字段。测试中，新旧格式的全部事件预测、未标注关系及
过程统计一致；新格式目录复制后原始证据仍可查。

## 初步正式小例结果（总输出预算修复前）

[汇总](validation-round19-followup/spool-formal-preliminary/summary.json)、
[历史检查](validation-round19-followup/spool-formal-preliminary/spool-results.json)、
[完整主链](validation-round19-followup/spool-formal-preliminary/results.json)。

镜像 `cpag-isolated:r19-spool-acceptance`，完整 ID：
`sha256:e8c9982c7e80965e6242a4e50df43086ac51f59d3acda237dc4d59d2f3440e23`。
实际七个隔离 Worker 任务通过，原始与恢复后共十四条完整 API 检查：

- 三次正常任务完整逻辑历史哈希一致；不同运行的物理库存各自绑定运行身份。
- pending、响应时钟过期 unknown、允许迟到、开放窗口和未满足前置条件等原 R18 断言全部保留。
- 历史快照、修订、图谱、操作/变化/触发原件与字段片段、两件新历史文件下载均核验。
- CLI/Worker/API 语义一致；真实 1x/10x 输入具有相同逻辑结果。
- viewer 读取允许、写入拒绝；完整备份恢复到 PostgreSQL 空库及新目录后，全部历史和原件查询相同。

正式小例没有使用最大容量输入。按临时目录创建时间至结果写入时间观察约 287 秒，
这是本机小例完整链耗时的近似值，不是参考硬件性能指标。
原件库存 v2 的正式评估、ACL 和空库恢复证据仍见
[第一阶段说明](round19-reference-inventory-followup.md)；新 spool 终态与该评估适配接口的
衔接另有单元测试，不把两组证据混写成已运行的更大组合场景。

正式小例之后只增加了“显式 null 不得退回旧格式”的备份拒绝守卫；该守卫不改变本次
有效格式路径。最终备份回归 **56 项通过**，其中包括新格式缺件、错格式、额外 WAL、
重新哈希后混入其他运行历史仍拒绝；评估回归 **75 项通过**。
[备份记录](validation-round19-followup/spool-all-backup-tests.log)、
[评估记录](validation-round19-followup/spool-all-evaluation-tests.log)。
公开文件已对本次临时配置中的六个私有值做精确扫描，无命中；私有数据库转储、配置和 session 不上传。

## CI 接入

`.github/workflows/m1-core.yml` 的 `replay-persistent` 新增本脚本。
通过 `--image cpag-isolated:r18-acceptance` 复用该 job 前面从同一 checkout 构建的完整
Worker 镜像，不重复构建；只上传 `round19-spool/public`。
现有 job 的 30 分钟预算暂不调整：新增小例本机约 4.8 分钟，目前没有完整 CI 超时证据。
YAML 解析及无继承 PYTHONPATH 的 CLI 启动检查通过；最终精确提交的完整 CI 仍为独立门禁。

另修复历史评估投影读取：服务资源策略升级后，旧运行仍按其冻结的 8MiB 预算读取，
不会借当前策略放大旧输出。新运行提交/未完成发布的 operator 绑定保持在相应写入边界；
历史读路径只接受受支持的版本。[专用检查](validation-round19-followup/evaluation-historical-resource-tests.log)。

## 总输出预算修复后的最终复验

初步七任务结果独立保留，不能替代修复后的运行。修复稳定后重新构建
`cpag-isolated:spool-final-1`，镜像 ID：
`sha256:5979b0d9e5ad655c2340cfc1aa33148dd83085b153459eb91e34c788f644ab25`。

构建前 **125 件 runtime 源文件**与构建后、所有最终验证结束后的哈希相同；
镜像内 **63 件源码/Schema/entry**逐件匹配构建前清单。
这些 runtime 文件及四件 harness/CI 文件后来与提交
`52711e3497d0d23e4b926941b58b9ffefab9528d` 逐件核对，全相同。
原始 Go 构建身份、初始 dirty 标记和逐件清单原样保留；**初始 dirty HEAD 本身不是固定测量身份**，
本次身份是实际源码哈希和不可变镜像，再通过内容匹配绑定到上述提交。

[最终汇总](validation-round19-followup/spool-formal-final/summary.json)、
[构建前清单](validation-round19-followup/spool-formal-final/before-build-source.json)、
[镜像源码对照](validation-round19-followup/spool-formal-final/image-source-binding.json)、
[527 内容匹配](validation-round19-followup/spool-formal-final/revision-runtime-match.json)。

同一最终镜像先后串行完成：

|最终场景|实际结果|
|---|---|
|七个真实隔离 Worker 任务|PASS；含三次正常一致、响应时钟过期、允许迟到及实际1x/10x|
|空库/新目录完整恢复|PASS；十四条原始/恢复后完整历史、图谱、原件、触发证据检查一致|
|排队取消|cancelled，attempt0，无发布|
|arrival3 实际 pending 前缀后取消|取得容器退出/移除、pid0证据，无半历史发布|
|无效输入有限重试|三次失败，无可信半产物|
|Worker 被杀与真实租约失效|恢复确认旧容器退出|
|新 attempt 从头回放|attempt2 从 snapshot0/arrival0 开始，完整验真成功|
|旧 attempt complete 与成功重复 complete|旧请求409；成功重复请求仍同SHA且仅一个发布锚点|

[七任务结果](validation-round19-followup/spool-formal-final/results.json)、
[十四条历史检查](validation-round19-followup/spool-formal-final/spool-results.json)、
[生命周期八项门禁](validation-round19-followup/spool-lifecycle-final/lifecycle.json)。
测前独立预期见 [生命周期场景](round19-spool-lifecycle-scenarios.md)。
最终七任务与生命周期的首次执行均通过；没有删改失败记录或调大十秒查询预算。

按目录创建至公开结果写入观察，本机完整七任务约 **291.5 秒**，生命周期约 **29.4 秒**，
仅作为本地流程观察值。最终源码上的 **75 项 evaluation**、**56 项 backup** 测试通过，
另有 replay/contracts/inputs 回归由对应记录逐项列证。
[评估记录](validation-round19-followup/evaluation-spool-final-regressions.log)、
[备份记录](validation-round19-followup/backup-spool-final-regressions.log)。

最终两组仅复制公开结果、源码清单及日志：十二件文件对二十三个不同私有值精确扫描无命中；
数据库转储、控制配置、claim token 和 session 不上传。
CI 保留旧 v1 lifecycle，并新增独立显式新格式 lifecycle step；复用已有 checkout 镜像，
不重复构建。新增本机完整流程合计约5.35分钟，仍保留现有30分钟 job预算，
最终精确提交的完整 CI 成功仍是关闭门禁。本结果不证明目标大规模回放或参考硬件性能通过。
