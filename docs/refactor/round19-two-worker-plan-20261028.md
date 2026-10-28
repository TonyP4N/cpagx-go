# R19 第四阶段：真实双 Worker 竞争与故障预登记

登记于执行前；本文件不登记任何通过结果。测试使用新隔离 PG、新 shared/control 根和两个真实 `cpag_worker.service` 守护进程，不连接生产 DB、不改保留 S100 原件。全站活动 attempt 政策仍显式 `engineering-capacity-1`；计算资源仍显式 `r19-dev-s100-1`（2 CPU/2 GiB/512 MiB 输出），不提升旧默认，不修改 pipeline。使用原始 S100 offline PCAP/CSV 的真实分析命令，无 pacing、sleep 替身、旧 JSONL benchmark 或假容器计算。

运行前冻结源清单、宿主 Go binary SHA、host Worker 源清单、Docker 镜像不可变 ID、原始输入/profile SHA、环境、命令和本脚本 SHA。固定后仍只说明这组软件的开发机生命周期行为；不能代替最后配置的 6 个新 S100 分析、M/L、字节边界、参考 Ubuntu 主机或真实工业数据。

## 预登记场景

1. **真实竞争与排队取消**：先由 A 启动一个实际分析容器并观察真实 analysis 子进程，再启动 B。两个服务同时存活时提交第二任务；至少三次连续采样显示首任务容器活动、第二任务 attempt=0，并保留完整 Docker start/die 事件流。取消排队任务，必须 attempt=0、无计算容器；首任务真正成功并通过服务产物校验。
2. **运行取消**：两个 Worker 同时存活下提交任务，观察实际 analysis 子进程，再排队另一任务。取消正在运行任务；只有 Docker 实际退出/独立退出凭据后才允许下一次 start。第二任务若开始也观察真实容器后取消，两个任务最终 cancelled，均保留完整 attempt/退出/发布历史。取消任务不能有 published 结果。
3. **失联、自然租约过期与 fencing**：任务开始真实计算后暂停另一 Worker（显式实验控制）、SIGKILL 当前 owner 守护进程，保留其 Docker 容器。等待实际 15 秒租约自然过期，不直接改 DB 时间或手造 exit。观察旧容器仍存活、lease_valid=false、exited_at 为空、排队任务仍 attempt=0。旧 token 心跳必须被拒绝。排队任务取消后恢复第二 Worker，由其独立查 Docker 并终止/确认旧容器、写退出凭据、重新领取源任务；新 attempt 必须真实计算并成功，旧 attempt 不得发表。两种 worker ID 均须至少一次实际启动计算。

PID1 在实际子进程完成后会有限保留 tmpfs 用于交接。因此失联时观察到 `container running` 不能自动写成 `CPU still computing`；保留 `/runtime/result.json` 是否已存在及 Docker top，准确区分计算进程、等待交接、容器退出和已核验 DB exit。若首次容器/子进程太短而未捕获，场景证据不足，不自动通过或补造采样。

## 证据与拒绝条件

Docker daemon 的全量 start/die 事件是活动区间主证据，采样只作补充。事件必须覆盖所有本隔离 scope 的容器；任意区间重叠、缺 start/die、无法核对 worker/job/attempt 标签、未解析事件或采样命令失败都保留并明确失败/不足，不能把未知作 0。跨来源时钟差异不能凭时间戳猜测；实际 exit 凭据和后续 start 的因果检查另记。

记录两个 Worker PID/退出码、API job 状态、明确字段的 DB attempt 快照、Docker inspect/top/stats 原始输出、资源预算、镜像 ID、Docker 退出事件、原始输入/产物 hash、失败和清理结果。API/Worker credentials、attempt token、完整私有 config/DB dump 留在 0700 私有目录，公开收据只复制所需字段。

默认每个场景受整体 600 秒脚本 deadline 约束；所有调用另有短超时。异常时先停止两个守护进程，再只清理本次随机 scope 的容器并保存最后状态、日志与 DB dump。禁止清理别的运行。失败目录不覆盖，后续尝试必须新目录。硬预算/权限/环境拒绝同样保留，不将重试视作原尝试成功。

脚本和限定负例单测完成后，等待主代理的固定镜像/CPU窗口再实际运行。此处的 DB snapshot 或单元 interval 测试自身不构成上述真实双 Worker 验收。
