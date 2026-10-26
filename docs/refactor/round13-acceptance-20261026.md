# 第十三轮：合成双源 Celery 使用流程验收

基线 `eef8d2e7d18186ca51a3ddc3cfc3ce44fda9430d`，分支 `refactor/m1-evidence-core`。本轮计划与退出条件见[有限计划](round13-plan-20261026.md)。依据原方案第4/5/8/11节，用现有Celery承载第12轮分析核心，不同时更换任务机制或关联算法。

## 实际新增

显式 `POST /api/v2/cpag/dual-source` 接收抓包、工艺CSV、版本配置与synthetic确认，派发命名Celery任务至已有cpag_generation队列。现有status、result/json、artifacts和受控download路径按task_kind分派；旧JSONL合成入口及普通入口保持不变。解析失败保留failed与原因，队列不可用返回503；完成任务重复投递验证原产物，failed不重新变为运行，活动重复投递沿用现有slot保护。

`dual_source_export`仅投影已有结果：标准NetworkEvent、ProcessObservation、DerivedEvent进入events；GraphArtifact包含网络/工艺/变化节点和候选边、原始Claim、规则/配置版本、配置指纹、证据引用与hypothetical状态，不新增推断算法。扩展GraphArtifact的derived_event节点和候选元数据为可选兼容字段。原始dual运行、抓包、CSV及配置一起保留。

新 `/dual-source/` 页面从首页显式链接进入。提交、任务查找、图、双源时间线、支持/反证/歧义/未知详情、原始帧/CSV记录/网络字段及下载联动。请求与响应保留协议语义，界面常驻合成及非因果/非攻击/非物理成功说明。切换任务有异步代际保护；完整性失败清除已有结果，禁止继续展示为可信结果。

## 产物清单、完整性和备份边界

公开下载仅六个根文件：graph.json、events.json、dataset.json、quality.json、analysis.json、run_manifest.json。完整core目录共11文件：上述六文件及dual/内分析/清单/三份输入。RunManifest列出除自身外10文件的哈希/长度；服务manifest绑定RunManifest SHA256并保留三份上传输入记录。内部路径不作为任意文件下载入口。

完成前检查所有导出副本和输入一致性。结果、清单、下载、证据查询重新验证服务副本、core原始文件、所有哈希、来源、完整性清单及重算图投影；缺文件/篡改返回409。状态接口保留记录的终态，409说明出版物不再可信，不伪造任务重新执行。只提供受信任本地清单内的完整性证明，不提供外部签名真实性证明。

新增 `backup_task(core_dir,bundle_dir)` / `restore_task(bundle_dir,new_core_dir)` 支持已完成**产物树**备份恢复，恢复后能重新查询双方证据，负例覆盖缺文件和篡改；不会覆盖已存在目录。既有 `scripts/backup/bundle.py` 的 PostgreSQL任务/attempt备份只支持原任务和packet类型及原文件集合，尚未识别synthetic_dual_source、DerivedEvent及嵌套dual证据；不得将本轮文件恢复视为Celery/Redis/数据库元数据成套恢复。新任务的完整元数据备份/恢复和后续PG执行器接入是尚未完成的软件工作，不是等待真实数据。

本轮沿用既有Celery行为，未增加取消/中断自动恢复承诺、跨主机、生产鉴权或新部署隔离。界面与API应在受控单机验证环境使用；生产多用户授权/运维和原方案完整任务生命周期继续单列。

## 复现步骤

Python3.11、现有服务/分析测试依赖、Docker Compose及前端依赖可用。在仓库根目录：

```sh
python scripts/validation/round13_celery.py --output /tmp/cpag-r13-check
```

此命令建立独立RabbitMQ/Redis、真实prefork Worker及HTTP API，执行正常、错误、无响应、映射缺失/冲突、歧义、无效输入、全部下载、缺文件和篡改拒绝，保存输入、输出、API/Worker日志及results.json，结束清理自己的服务。输出目录必须不存在。没有eager任务替代，也没有HTTP响应mock。

浏览器操作：先在webui运行 `npm run build`，再执行：

```sh
python scripts/validation/round13_celery.py --output /tmp/cpag-r13-ui --serve --ui-port 18300
```

打开 `http://127.0.0.1:18300/dual-source/`，选择该输出目录inputs/success中的三个文件，勾选合成确认并提交。完成后点击图的操作节点或候选连线，证据区应显示4条原始引用；双源时间线可联动操作/变化查询。results.json里的其他任务ID可直接读取检查异常状态。停止验收进程后清理隔离服务。测试代理仅承载静态站点和v2同源请求，不修改默认路由。

可选自动浏览器复验（安装Playwright及Chromium后，或PLAYWRIGHT_MODULE指向本机已有模块）：

```sh
node scripts/validation/round13_browser.cjs /tmp/cpag-r13-ui output/playwright/round13
```

浏览器脚本实际操作页面，验证三文件确认上传、图/时间线点击、四引用、下载、各异常场景、无效输入、缺失/篡改后清屏、非法任务ID及窄屏布局；对隔离输出目录短暂注入损坏并在finally还原，不能对生产目录运行。

## 本轮问题与已保存证据

- 首次本机API在90秒内未启动，原失败见 `validation-round13/startup-first-failure.json`；独立导入诊断用了约269秒，栈停留旧api/__init__→v1间接导入的pandas/InfluxDB等模块文件读取，日志 `startup-import-diagnostic.log`。完成导入后，不改90秒门槛复验API正常，全部真实队列场景通过；未确定宿主文件读取慢的根因，也未宣称已修复既有启动问题。新增验证工具保留底层stdout/stderr及导入日志。
- 本机首次前端编译/类型通过，但既有未修改/graph静态收集两次60秒超时，未产出站点；同源码第二次本机构建通过（frontend-build.log），独立Linux CI前端也通过。未提高时限，未改旧graph；保留环境/构建耗时观察，不把失败抹除。
- 首次远端CI旧isolated-executor在镜像拉取阶段，因远端in-toto内容描述符not found失败，未进入隔离测试；原日志及CI快照为ci-first-failure.log、ci-first.json。其余13项（含新增真实双源Celery）首次通过；只对失败作业复验，后续结果单列。
- 浏览器首次发现候选连线被响应节点遮挡，导致正常click超时；browser-first-failure.json及graph-overlap-before.png保存复现，修复与回归结果在最终记录补齐。
- 首次主任务调用core测试漏设PYTHONPATH，导入失败而非软件回归；按既有CI方式设置后12项通过，调用错误和最终日志均保留。

## 原方案进度的具体影响

| 阶段/工作包 | 当前状态 | 本轮影响与剩余退出条件 |
|---|---|---|
| M0 / R01 | 部分完成 | 增加可复现实际使用步骤；完整真实历史入口/配置核验仍缺 |
| M1 / R02—R04 | 既定骨架/最小范围已完成 | 标准图契约兼容扩展、同纯核心被队列调用；不改变原最小验收结论 |
| M2 / R05—R06 | 部分完成，真实验收受阻 | 复用已有协议/CSV/配置，不增加协议覆盖；真实字段、映射和时间依据待小片段 |
| M3 / R07、R11 | 部分完成 | 合成候选标准图、图/时间线/双方证据界面接通；正常及攻击真实区间独立复核仍未通过，通用界面能力未全量实现 |
| M4 / R09—R10 | 部分完成 | 新核心经现有Celery实际执行，保留旧入口；新类型PG/取消恢复/完整备份及历史任务兼容尚未完成，不切默认 |
| M5 / R08、R12 | 部分完成 | 沿用独立预期，不新增正式评估/完整回放；真实标签/保留集与研究目标继续独立验收 |
| M6 / R13 | 部分完成 | 增加操作和接收文档；RC1不重打包，不因新合成链路视为正式发布 |

真实材料清单单独见[首个真实双源样例最小接收清单](first-real-dual-source-intake.md)。首批小片段用于字段/设备/时间核验；正常/攻击、独立标注/保留集分开列明。上述未完成软件功能可以独立继续，不全部归入等待真实数据。

冻结标签仍为 `49e998545b9b7b47f2b1dc9b19e6d8562f780765`；RC1包SHA256仍为 `c199dd417e1c59c55563c5535e32d26197b164c95ae17c0ef3bb621f7228b49e`。旧默认入口、协议/关联算法、完整回放与正式发布均不改。既有未受影响验收引用第7—12轮，不将本轮贯通等同于真实工业验证或整体重构完成。

## 有限验收矩阵与结果

| 门槛 | 方法与结果 |
|---|---|
| U1 实际队列 | 独立RabbitMQ/Redis、真实Celery prefork、HTTP：6种有效场景completed，无效CSV failed，6类产物下载一致；celery-live.json及API/Worker原始日志 |
| U2 图契约 | 18项dual-source测试通过（含15个独立预登记场景、标准图、完整性及文件恢复）；Python契约、Go契约和既有核心12项通过 |
| U3 用户联动 | 实际浏览器从上传新任务开始，图/时间线→原始证据、4条引用、异常状态、下载、窄屏通过；图遮挡缺陷修复后按相同普通click回归 |
| U4 完整性 | 服务测试19项含旧synthetic回归、复制损坏不得成功、终态重复保护；真实HTTP缺失/篡改4类读取均409，浏览器不保留可信结果；产物树恢复查询通过，数据库元数据恢复明确未支持 |
| U5 CI/交付 | 实现提交39ef9fd的14项最终通过，isolated-executor仅在镜像拉取失败后重跑一次；最终修复/报告提交CI待另附链接 |
| U6 接收清单 | 首个小片段的授权、双源原件、版本/哈希、字段、设备、时间/精度依据逐项给出用途/缺失影响/具备状态；正常/攻击及独立评估材料分列 |

图点击修复将响应和工艺原始节点移至候选连接下方，保留全部GraphArtifact节点；普通鼠标点击可查询，不用测试强制点击。证据区增加端点→目标、操作、响应语义、映射及工艺前后值摘要，原始内容和字段仍可展开查看。最终浏览器及CI结果记录随本轮提交保留。M3有限合成使用闭环达成本轮退出条件，但M2/M3真实退出条件、M4全任务生命周期/备份、M5完整回放及整体目标均未完成。
