# 第十四轮：双源持久任务、取消恢复与成套备份

基线 `23635e90922adcfd0eb2c20e3ca620b31e5d72fb`，分支 `refactor/m1-evidence-core`。本轮是明确声明的合成软件验收，不是工业效果验证。RC1、默认入口、协议及关联算法保持不变。

## 实现和交付边界

- Go API 接受显式 `kind=dual-source`，三份输入先复制为受控内容寻址文件。小数时间参数和字符串按 Python canonical JSON 定义核对配置指纹。每次运行绑定 job/attempt；11 个核心文件包括 DerivedEvent、Claim、规则/配置指纹及 `dual/sources/` 原件。
- 现有 host Worker 与 DockerExecutor 调用同一个 `cpag_core.dual_source_export`；隔离执行只增加该任务需要的有界 `/tmp`，交接、发布和恢复都校验完整目录。没有另写关联算法。
- 现有合成双源页增加显式执行路径选择，默认仍为 Celery。持久桥接的凭证仅留服务端；状态、取消、结果、六项公开 JSON 下载和原始证据查询使用同一持久任务记录。嵌套原件受控查询和备份，不提供任意路径下载。
- 备份限定停写、所有任务终态，包含 PostgreSQL 行及执行历史、输入配置、全部产物原件与一致性清单；恢复创建新的空数据库和新目录。运行中的任务快照、跨主机恢复、整个主机控制目录迁移不在本轮验收范围。

## 可重复验收

先安装仓库现有 Python 测试依赖、Go、Docker、前端依赖及 Playwright Chromium；在仓库根目录执行：

```sh
npm --prefix webui run build
bash scripts/m4/isolated/validate-isolated-dual.sh
CPAG_PYTHON=.venv/bin/python bash scripts/validation/round14_acceptance.sh /tmp/cpag-round14-new
```

目录必须为本次独立验收新建。该命令创建真实 PostgreSQL、RabbitMQ、Redis、Celery prefork、Go API、Docker Worker；先恢复数据库和文件，再进行同输入对照及现有界面普通点击。`public/` 保存无凭证报告和截图。`backup/state.json` 为 0600 的临时测试凭证，不能公开或提交。停止时清理本次服务。

仅显式启用持久页面入口的服务端环境：`CPAG_PERSISTENT_ENABLED=1`、`CPAG_PERSISTENT_API_URL=http://127.0.0.1:<port>`、`CPAG_PERSISTENT_ROOT=<shared root>`、`CPAG_PERSISTENT_TOKEN=<worker credential>`。单机本地 API 范围；未配置时返回明确 503。现有代理转发 v2 子路径，不更换生产默认。

## 验收矩阵

| 门槛 | 实际方法与结果 | 证据 |
|---|---|---|
| 输入与产物契约 | 小数参数、字面转义及 Unicode 配置与 Python 指纹对照；DerivedEvent、嵌套原件、run/attempt 绑定；自改引用并重算哈希仍拒绝 | `internal/jobapi/dual_test.go`、`tests/dual_source/test_dual_source_export.py` |
| 排队取消 | 未启动任务取消后不可领取、无发布 | `validation-round14/isolated-dual-validation.log` |
| 运行取消 | 测试门控在真实双源分析已完成、投影尚未发布时暂停；取消后取容器退出证明才进入 cancelled | 同上；不是以 sleep-only 进程代替分析 |
| 失联与租约 | 同样门控实际分析，杀 Worker，租约到期恢复并启动 attempt 2；attempt 1 发布被拒绝 | 同上及 `isolated-dual-status.json` |
| 重复与重启 | 重复 enqueue 拒绝且不改变已接收任务；重复 complete 保持同一发布；交接后杀 API 并重启，恢复仅发布一次 | 同上 |
| 嵌套损坏 | 交接后损坏嵌套原件，不报告成功；取消保留退出依据 | 同上 |
| 空库成套恢复 | 目标数据库事前不存在；元数据、attempt history、文件清单一致；额外恢复 timeout→attempt 2 成功的双源任务，两次退出回执均绑定身份且字节相同；恢复 API 操作查询四条原始引用、变化查询两条 | `validation-round14/backup-restore-summary.json` |
| 恢复后完整性 | 独立损坏副本：删除数据库引用的受控 PCAP、篡改受控 CSV、删除嵌套分析产物，结果 API 均 409 | 同上 |
| 同输入执行器一致性 | 真实 Celery 与 Docker 持久路径：6 种有效场景完整分析结果及原始证据一致；无效 CSV 均失败；全部嵌套产物哈希一致 | `validation-round14/executor-parity.json` |
| 界面恢复与提交 | 恢复任务→四证据、普通点击图、下载、缺失/篡改清屏；再从界面提交隔离任务 | `validation-round14/browser-results.json`，page_errors=[] |

## 本轮发现及处理

1. 隔离容器只读根目录没有双源核心所需临时目录：实际任务复现后，限 dual-source 加有界 tmpfs，真实 Docker 完整链路复验通过。
2. 指纹字符串全局替换可能把字面反斜杠转义误当 Unicode：改逐字符 JSON 编码，独立 Python 对照覆盖小数、指数、Unicode、控制符和字面转义。
3. 本机 Celery API 两次冷启动在既有 90 秒门槛内未就绪；保留底层导入日志，未把它算作通过，未扩大本轮基础设施修复范围。独立完整导入诊断后，未修改既有90秒门槛第三次通过真实 Celery 全场景，见 celery-live.json；启动慢根因仍未解决。

阶段提交：`13ca980` 契约及执行身份；`4005cb1` 实际取消/失联/重启故障；`ebd1192` 成套空库恢复；`f552a70` 显式界面与端到端工具；`cdcdfd8` 指纹边界和恢复证据。最终 CI 与验收结论补充在末尾，不以中间提交代表最终验收。

## 原方案退出条件影响与待办

| 阶段/工作包 | 状态 | 本轮变化及剩余条件 |
|---|---|---|
| M0 / R01 | 部分完成 | 增加可重复隔离验收；真实历史入口/配置核验仍待历史材料 |
| M1 / R02—R04 | 既定最小范围完成 | 增加双源持久产物绑定与跨语言指纹，不改变原核心骨架结论 |
| M2 / R05—R06 | 部分完成，真实验收受阻 | 不扩解析协议；字段、设备映射和时钟依据仍需授权双源小片段 |
| M3 / R07、R11 | 部分完成 | 同一合成分析结果可通过持久任务及恢复后的界面查询；真实正常/攻击区间、通用大图未完成 |
| M4 / R09—R10 | 部分完成 | 本轮限定双源任务接入 PG/Worker/隔离/取消/恢复/成套备份；完整历史任务兼容、默认切换门槛和原方案全范围故障覆盖仍须分别验收 |
| M5 / R08、R12 | 部分完成 | 无新增正式评估或完整回放；独立标注、保留集及完整回放条件仍未满足 |
| M6 / R13 | 部分完成 | 增加新任务数据库与产物恢复证据；RC1冻结不重打包，本轮不是新的离线发布版 |

未完成软件范围：运行中快照、整机控制证据迁移、完整历史任务迁移兼容、完整回放、通用大图、生产默认迁移。上述不全部归为数据阻塞。首个真实双源样例仍依 [最小接收清单](first-real-dual-source-intake.md) 单列：授权和来源、同期 PCAP/CSV、字段单位、设备/IP/CIP/tag 映射、时区和时钟误差依据；正常/攻击区间、独立标注、保留集另行接收。本轮没有读取并验收新的真实数据，也未将真实数据标为 synthetic。

## 界面及一致性实测补充

现有页面保持默认 Celery，选择“持久 Worker”后，从空库恢复的 `r14-dual-backup` 定位四条引用：请求帧、响应帧及变化前后两条工艺记录。普通点击图节点/候选连线、六项受控下载、嵌套原件缺失/篡改后的409清除旧结果、新上传隔离任务均通过，浏览器 page_errors=[]。截图 `restored-evidence.png`、`new-task-evidence.png`、`tampered.png`；前端使用同提交远端成功 frontend 构建产物。

正常、错误响应、无响应、映射缺失、映射冲突、多操作歧义6种输入，经真实Celery与DockerWorker比较，analysis/events/graph/quality/dataset及完整原始证据对象相同；RunManifest去除有依据的run_id、attempt_id、Python补丁版本后相同，内含全部嵌套文件哈希一致。无效工艺CSV两路径均failed。允许差异实际值保存在executor-parity.json，没有排除分析字段或证据字段。

首次对照发现Go内部原始帧查询为简化视图，缺少完整核心查询的帧元数据；使用入口已改为先由Go核验数据库发布锚点和输入，再调用同一个核心query_task。Go内部证据接口仍是有界简化视图，不能将其与完整界面查询契约混同。复验按完整对象逐项比较通过。

本机最初有两个构建检查先后进入同一构建目录，产生webpack缓存竞争警告；已停止重复构建，使用当前提交远端成功的前端产物完成界面验收。未改变构建门槛或既有页面。此前失败、修复后结果分别保留。

本轮另修复持久状态未返回分析失败原因的问题：状态新增可选last_error，界面优先显示失败原因，恢复原因仍保留；无效CSV对照要求failed且原因非空。桥接本地API地址改为解析主机与端口，拒绝含用户信息的伪本地URL，避免误发服务端凭证。
