# 第九轮：真实 Celery 合成链路与旧入口兼容验收

基线 `f859a8bdeb07a5a4d067566f23eb5fa035ab362f`；分支 `refactor/m1-evidence-core`。范围与退出条件先登记于 [有限计划](round9-plan-20261026.md)。本报告为本轮实际证据的索引；最终状态需与真实执行JSON及CI一致。

## 代码变更与缺陷复现

已有 `/cpag/synthetic` 桥接采用真实Celery task，无需另写算法。新增独立测试编排：真实RabbitMQ broker、Redis backend、独立uvicorn进程、Celery prefork Worker，只消费 `cpag_generation`，不启用beat。临时数据根和端口均独立，不接触默认服务。

复现：已完成任务的 `graph.json` 被改为另一个有效JSON后，旧合成查询/下载仍返回200；缺文件还可能由旧result回退到其他JSON或抛未处理异常。新回归在修复前为7个断言失败、1个错误（`validation-round9/pre-fix-service.log`）。

修复：仅对manifest明确 `synthetic` 的分支，在artifacts、result、result/json、download读取前调用既有 `verify_completed`。完成清单、产物和保留输入校验失败返回409；未完成合成结果不提供成功下载。保留原始任务终态，不将读取时完整性异常改写为一次新的任务失败。非synthetic历史文件读取分支保留，新增小型格式夹具证明旧result/download行为不变。该夹具不是实际旧工业任务。

修复不回写 `cpag-engineering-synthetic-rc1` 镜像或离线包；当前分支承载后续代码。无协议、界面或回放扩展，无默认入口切换。

## 验收证据

- 服务回归13项通过；core12项、legacy5项通过；Go api/contracts通过。对应 `service-tests.log`、`core-tests.log`、`legacy-tests.log`、`go-tests.log`。
- 真实链路记录：`validation-round9/celery-live.json`；详细命令、实际运行环境和C1—C6结果见 [真实队列说明](round9-celery.md)。此证据必须为真实broker/backend/Worker，不以服务单测中的mock队列替代。
- 新增独立远端 `celery-live-compatibility` CI作业，原有十项作业保留。真实失败输入、测试任务失败和请求错误日志属于验收预期，最终以断言结果和检查表判断。
- 冻结标签与包校验值、默认路由/配置、纯核心、M4 Worker保持不变，见 `validation-round9/freeze-invariants.json`。

## 兼容结论的边界

已验证的兼容范围由真实链路结果限定：显式v2合成提交通过Celery执行现有纯核心，使用旧v2状态、结果和下载URL读取产物，并核对原始证据；可以据此补齐上一轮S01的真实队列证据。它不等价于旧v1/v2 `generate_cpag` 的工业PCAP算法与所有数据库副作用兼容，也不替代Neo4j历史图核查。

本轮不承诺计算中强杀后的自动恢复、Redis槽位/状态丢失后的重建、所有失败任务的安全重投、取消迁移、多主机执行或在线历史迁移。重复已完成任务的幂等性与Worker正常重启后的接单分别验收，不用它们推断中断窗口已经闭合。

## 原方案状态和待材料

M0/R01补充真实队列启动记录；M1/R02—R04维持原骨架验收；M4/R09—R10与R13补充有限Celery链路和CI证据，仍为部分完成。M2真实解析/对齐、M3双源关联、M5正式评估继续受真实材料限制；R11/R12界面和回放不扩展，M6冻结工程候选保持原范围，整体重构未完成。

真实历史材料仍需：具体旧任务的输入、当时版本与配置、任务元数据及原产物；要验证旧图需对应Neo4j只读导出与版本；真实工业效果需授权同批次抓包/工艺数据、字段/设备映射、时钟依据、正常与攻击区间、独立标注及保留集。无需提供生产凭据或把受限原始数据写入Git。

实现提交与远端 CI 记录见本文末尾；本地通过不代替 Linux 远端执行。

## 测试环境问题（不混同产品缺陷）

macOS初次prefork使用SpawnPoolWorker，实际收消息后在Celery fast_trace_task中报本地初始化错误，未完成任务。测试脚本仅在自身进程中显式设置billiard fork，保留真实prefork子进程；产品启动方式未改变，不能据此声称未经设置的macOS默认Worker已修复。Linux CI使用正常Celery启动命令。

真实broker恢复过程中，测试脚本原先以“旧队列管理URL必须存在”作为RabbitMQ就绪判据，停止后该URL返回404。改为broker自身健康/overview检查，再实际提交任务验证新队列声明与执行。此测试在停broker前已完成任务，不证明持久化待处理消息在broker重启中不丢失。前次失败证据单独保留，最终成功结果才作为验收。


## 本地完整链路验收矩阵

| 条件 | 实际验证 | 结果 |
|---|---|---|
| C1 无 Worker 提交 | HTTP 202/queued 与 RabbitMQ ready 消息 | 通过 |
| C2 真实队列至旧 URL | prefork 消费、Redis SUCCESS、五个产物下载/哈希、状态/列表/结果、事件及图引用解析 | 通过 |
| C3 同核心一致性 | dataset/events/graph/quality 字节一致；run_manifest 仅 run_id 不同 | 通过 |
| C4 混合输入与重复投递 | 损坏/仅表头分别 FAILURE 且无产物；后续正常成功；第二次真实消费完成任务后文件哈希不变 | 通过 |
| C5 正常重启及 broker 故障 | Worker 正常退出码 0 后接单；broker 不可用提交 503/failed；恢复后新任务成功 | 通过，有限范围 |
| C6 缺失/篡改/恢复 | 四个读取 URL 均 409；恢复原文件后下载 200 | 通过 |

C5 恢复时 Docker 临时端口可能重新分配，测试刷新 broker 地址并重启独立 API/Worker 后提交新任务；这不是原进程透明重连或未处理消息持久性验证。缺失/篡改检测为合成任务产物的读取校验，不能据此推断所有历史任务具有同样保障。
