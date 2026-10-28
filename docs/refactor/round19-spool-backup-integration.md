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
