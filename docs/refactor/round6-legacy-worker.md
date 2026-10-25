# 兼容Worker稳定性范围排查

基线 `2f08784`，保留兼容入口，仅修已有执行的重复调用与模糊完成响应。

## 已复现并修复

1. 同attempt控制目录已存在时，旧代码把FileExistsError当任务失败并调用`/fail`。真实目录+FakeAPI复现见`validation-round6/legacy-before.jsonl`。现在返回`reconciliation_required`，不改现有目录、不发送终态请求。回归验证已有退出文件字节不变。
2. `/complete`可能已经提交但响应丢失时，旧代码又发送`/fail`并报告failed。使用真实核心计算和注入响应丢失复现。现在网络/响应解码/5xx返回`publication_pending`，409返回`lost_lease`，保留产物、不发fail。数据库终态仍以API为准，兼容Worker不自行推断成功。

3. 兼容CLI的`--once`在领取API不可用时原先无诊断并退出0。新增精确模拟复现已归档同一before文件；现在输出无凭据的结构化依赖故障，退出75提示重试；持续模式保持周期重试。

`validation-round6/worker-regression.log`为14项Worker最终回归，包含真实子进程退出、父进程被杀、API失联、CPU/文件限制和以上两项。FakeAPI用于精确模拟响应丢失，不冒充真实网络中断；实际API/PostgreSQL矩阵由独立集成覆盖。

## 范围说明

兼容Worker的pending返回值用于显式诊断，不新增默认路径的自动交接机制。隔离执行器承担本轮持久交接与恢复验收；跨执行器完整能力一致性仍是默认切换前条件。代码审查不能证明没有其他问题，进程/机器断电、宿主root篡改不在这些回归的证明范围。
