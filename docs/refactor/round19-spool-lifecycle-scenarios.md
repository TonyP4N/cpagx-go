# R19 新历史格式生命周期独立预期

登记基线 `3e7340e` 及当前显式 spool 集成工作树；固定镜像计划为
`cpag-isolated:spool-final-1`，待总输出预算修复稳定后构建并记录完整 ID。
本文件先于该新格式的故障注入执行。旧 R18 JSONL 生命周期测试保留，由完整 CI 独立运行。

仅选择 `history_format=replay-history-checkpoint-delta-2`，逻辑回放版本仍为1。
复用 `round18_lifecycle.py` 的实际 Go/PG/隔离 Worker 状态机和故障钩子，不改分析算法。
运行取消和 Worker 中断必须发生在实际 arrival 3、`pending_response` 的快照；
未来响应/工艺记录不得提前出现，不能用启动后任意等待代替该前缀证据。

|场景|实施前独立预期|不接受的替代|
|---|---|---|
|排队取消|cancelled，attempt=0，无容器、无发布|先领取再称排队取消|
|运行中取消|先取得实际 pending 前缀，退出检查证明容器已移除且pid=0，再终态 cancelled；无可信半历史|仅发送取消请求或停了宿主线程|
|无效抓包|三次有限 attempt 全部失败，无发布路径和可信历史；错误保留|生成空事件或仅校验SQLite即可成功|
|宿主 Worker 被杀|保留真实 pending 前缀；等待真实租约失效；恢复取得旧容器不可逆退出证据|直接人工改数据库状态|
|中断后新 attempt|attempt=2 从 snapshot_number=0、arrival_seq=0 开始；attempt1不发表半历史，attempt2完整验真成功|冒称从中断位置续算|
|旧 attempt complete|返回409，不替换当前终态的发布锚点|仅比较输出文件名|
|成功 complete 重复请求|相同SHA，唯一内容寻址发布锚点|增加第二套发布或换SHA|
|历史格式绑定|profile/payload/wrapper/core均为显式新fmt；只有history目录两件新库存，不借旧两JSONL|由文件存在猜测格式|

执行顺序：先等待并发的正式容量测量结束，再跑修复后七任务/空库恢复，然后运行本故障矩阵。
所有首次失败和重新运行记录分别保留。源清单、Go构建身份、镜像内源码清单及镜像ID随结果绑定。
只有检查实际通过才推进该限定软件子项；不据此宣称目标规模、参考硬件或真实工业效果通过。

CI 将保留旧 lifecycle step，并另加 `--history-format replay-history-checkpoint-delta-2` 的
独立 step；复用同 job 已构建的镜像，私有控制文件、租约 token、配置和数据库转储不上传。
