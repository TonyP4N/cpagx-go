# R19 DAG6 核心接口与后续接入边界

本文件描述显式核心实验接口，不宣布容量支持、正式服务可用或R19完成。预登记见round19-core-bottleneck-preregistration-20261028.md。RC1、默认Celery/持久任务入口不切换。

## 版本和完整业务对象

配置显式绑定 `engineering-core-capacity-3` / `shared-observation-dag-6`。回放另绑定 `identity_strategy=merkle-json-dag-1` 和 `prefix_digest_strategy=incremental-prefix-digest-2`。原capacity1、DAG3—5和JSON/历史v2保留原版本路径。生成器新选项为 `r19-density-capacity-4`，只允许核心实验，不能交给尚未适配的正式测量/Worker入口。

最终analysis、标准events/graph、quality、dataset、metrics、全部快照和修订均为数据库中有名称的完整逻辑根。物理文件为run_manifest.json、shared/manifest.json、shared/shared.sqlite3及sources全部原件/版本配置。不再输出重复平铺analysis.json/graph.json。逻辑对象仍完整保留原字段及顺序，数组分块并引用不可变节点；物理整数引用必须经摘要、类型、完整逻辑字节范围和子节点核验，不能将缺节点当空列表。

图容器ID在新格式为完整图（排除自身graph_id）的typed Merkle摘要；snapshot/state/revision容器身份也为typed Merkle。旧canonical JSON摘要不改。业务事件、候选、Claim、证据不因存储主动改写；配置指纹改变引起的业务ID差异必须用同一配置的旧算法对照，不能删除这些字段凑一致。

## 核心读写和信任边界

`cpag_core.shared_export.export_task` 产生未获来源复核许可的产物；`verify_task` 检查物理清单和所有节点，再由保留原件、配置完整重建，逐逻辑根比对。实际耗时和临时重建库计入总成本。runtime_metrics的实际墙钟样本仅绑定物理字节，不要求重建时墙钟相同。

`shared_cli` 提供export、verify、metadata、page、selection/evidence、snapshot和revisions动作。大逻辑根不能无界展开：单次读取8MiB/100项，超过明确报错，需使用path/offset/limit分页。完整逻辑extent是溢出防护，不代表可解码为一个巨大JSON。全量导出/HTTP下载尚需后续服务端流式适配。

本地受信任协调器在完整来源核验成功后，可用仅驻内存的32字节密钥签发 `core-read-approval-1`。新读取进程经继承FD接收密钥/许可；每次重新检查全部物理与原件字节、上下文及许可，随后只解码需要的页。密钥不进入CLI参数、产物或公开日志。这是核心实验的有限读取授权，不是用户角色授权，也不替代Go服务认证、attempt有效性与任务终态检查。无许可路径仍完整来源核验；不能拿调用者提交的SHA作为许可。

## 下一项正式集成必须修改的接口

- Go任务类型/请求契约：明确绑定新容量、存储和历史版本；同步预检历史输入、配置指纹、运行/attempt身份，未知或跨层版本不一致拒绝。
- 隔离Worker：显式新资源/CLI dispatch及物理产物清单；交接前完整校验，不再假设每个逻辑产物是平铺文件。旧attempt发布、取消退出证明和全站活动名额仍由现有持久体系控制。
- 服务读取：实现受服务端保护的来源核验记录及完整文件变更检测；不能直接采纳实验CLI的HMAC密钥。先授权再查证据，限制页数/字节、历史边界和查询时间。
- 评估适配：按索引分页读取最终观察/候选和声明回放口径；不重跑另一算法、不丢反证/未知。绑定运行/attempt和逻辑根身份。
- 终态备份恢复：纳入新物理清单、全部输入和共享库/manifest；恢复空库新目录后执行来源及引用核验。旧备份格式不能默认为理解DAG6。
- UI只通过已授权新服务API消费分页图/历史/原证据，不直接打开SQLite或暴露内部Worker凭据。

上述正式集成均未作为本次核心工作已完成项；已有未提交Go/capacity2/Worker/backup原型保持原状，后续需独立核对。

失败输出保留采用 `compact-failed-attempt-1` 标记：不删除已经写入的诊断字节，目录存在时下一attempt必须另选目录。`FAILED.json`使严格物理清单校验失败，不能查询为可信结果或签发读取许可。磁盘满可能连标记也写不出，此时调用仍明确失败、无许可，宿主执行记录为依据；不得仅看run_manifest文件存在判断成功。
