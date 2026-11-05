# R21 EU Kubernetes 定向修复（2026-11-05）

本次以 `94badfa693190e2b56eaa3a4b647a2ff5e8af6ac` 为代码基线，只修复独立验收发现的 Kubernetes 回放、取消/失败收尾、成套备份恢复三项缺口。冻结 RC1、旧默认入口、历史结果及未提交的 R19 工作保持原状。原 [R21 验收](round21-acceptance.md) 的历史证据仍按其环境解释；本次 EU 结果见 [精简证据](validation-round21/eu-kubernetes-fixes-20261105.json)。

## 修复行为

- Worker 从任务状态接口读取取消状态，心跳只用于续租。执行登记、激活、退出证明和发布边界有持久记录；失败输入可以结算，不再永久占用活动记录。运行中取消先终止计算、保存实际退出证明，再确认取消。Pod 的退出证据 finalizer 在确认前保留。未激活的挂起 Job 采用绑定 UID 的未启动证明；已启动 Job 无证明地丢失仍保留未知，不伪造退出或成功。
- `dual-source-replay` 走原 DAG6 核心和原资源限额，贯通正式 Kubernetes Worker、Go 来源复核、历史快照、四条原始证据和受控下载。
- 新运维入口通过明确的 context、namespace/deployment UID、PostgreSQL Pod UID 操作原 format7 成套备份；兼容已部署的 sidecar v1 回执，新 v2 回执另绑定完整核验 nonce。恢复必须使用新库、新目录，撤销旧会话，保留原件和失败目标，启动新服务后重新核验来源。
- 恢复显式区分宿主 PV 目录与容器内 `/state/shared`，完整控制库存校验通过后才重定位容量账本；不放宽原件摘要、退出证明、目录边界和维护锁。

## 实测范围

| 检查 | 本次结果与范围 |
|---|---|
| 定向回归 | Worker 22 项；backup 125 项（含工作区既有原型测试）；Go jobs/jobapi 通过。新增 Worker 7 项、backup 6 项另在 EU Linux 镜像通过。正式 CI 以本提交对应运行结果为准。 |
| 公网回放 | 普通浏览器创建 `16c291e141eccb2c39198643669513c2`，attempt 1 成功；16 快照/11 修订，快照 0 不含未来操作，快照 15 原件可查，重新登录和下载通过；macOS Chromium，系统 TLS 信任，零页面错误。复用了已有上传和预检，报告继承的泛用 `ordinary_offline_single_submission` 字段不代表离线模式。 |
| 运行中取消 | 先从真实 Pod 看到容器 Running，再取消 `9751192a1ff0bac38711cd01ec7128f3`；实际退出后 cancelled/fenced。随后小回放 `0938c4aefd3048d7f22f9df1e5482d11` 成功，证明 Worker 可继续接任务。 |
| 备份 | 在线未停服务时明确拒绝；显式停止 API/Worker 后成功备份 format7，117 件业务文件、42 件控制文件，随后自动恢复原服务。 |
| 独立恢复 | 空库 `cpag_r21_restore_20261105_b`、新目录恢复；文件和重定位前控制库存一致，撤销 8 个旧会话。独立服务只读核验结果写入精简证据。该副本不接公网、不启动 Worker，不覆盖原数据。 |

公网运行镜像为 `docker.io/library/cpag-eu-suite@sha256:7185ad3d8c44270530ac988a9387455320740c94cbdd786cfbaf1e822a849217`，Go 二进制 SHA-256 为 `4ce1af0adadf5dfaee344c2fd2ed88afaed3fb600915a0c437dba89b135364d4`。后续仅备份路径映射更新，独立运维镜像为 `sha256:f47eef40d9d542eba3277e5ea59bb9310757341b4366fcd2b277ba6627c463fc`；不能用公网运行镜像内的旧备份脚本冒充该修复。运维工具以本提交及精简证据中的逐文件 SHA 为准。

失败记录保留：初始镜像内测试导入了旧 Worker 副本，修正双路径复制后通过；初始运维容器挂载了 k3s 启动包装器，因只读根无法解包而在停服前失败，改用已展开的 kubectl 二进制；首次恢复因容器/宿主路径不同失败，保留原恢复库和目录，修复后复用同一备份另建新目标；临时恢复 Pod 最初使用 Never 重启策略，在网络策略生效前连接数据库失败，改用与服务一致的重试策略。以上失败不计入成功次数，也不反复重跑已通过业务矩阵。

## k3s 运维入口

在授权 Linux 主机使用 `scripts/backup/kubernetes_ops.py`，Python 能导入同版本 `services/analysis/src`，且 kubectl 可访问明确集群。配置必须为当前操作者持有的 0600 普通文件；备份根、恢复根为 root:root 0700，四个持久根路径互不重叠。配置精确包含以下字段（值从目标部署读取，不能照抄其他集群 UID）：

```text
context, namespace, namespace_uid, app_deployment, app_uid,
postgres_pod, postgres_uid, postgres_container,
source_database, restore_database,
shared_root, control_root, backup_root, restore_root, runtime_shared_root
```

`shared_root/control_root` 是宿主机实际卷路径；`runtime_shared_root` 是恢复服务挂载后的路径（本次 `/state/shared`）。`restore_database` 必须不同于源库且尚不存在。容器化运维要按相同绝对路径挂载指定卷；k3s 主机应挂载已展开的实际二进制为 kubectl，不挂载需要自解包的启动包装器。

```sh
sudo env PYTHONPATH=/opt/cpag/services/analysis/src python3 /opt/cpag/scripts/backup/kubernetes_ops.py \
  --config /etc/cpag/kubernetes-operator.json backup --name NEW_BUNDLE --stop-services
sudo env PYTHONPATH=/opt/cpag/services/analysis/src python3 /opt/cpag/scripts/backup/kubernetes_ops.py \
  --config /etc/cpag/kubernetes-operator.json restore --name NEW_BUNDLE --target NEW_TARGET
```

这是终态维护备份；有未退出执行或活跃核验时必须拒绝。一次失败后不要覆盖同名回执、库或目录，保留失败证据并使用新名称。恢复入口不自动更换生产连接或启用 Worker。另建隔离服务、轮换内部凭据、挂载新目录，确认重新登录、来源复核、原件和下载后，才按部署流程切换。共享卷或已有 Job 被管理者强制删除且无退出证明的情况仍需人工调查，不能当作已取消。

独立 Windows Edge/Chrome 实际客户端、目标现场尚未覆盖的故障/稳定性检查继续待验；社区 M/L、指定参考环境、真实工业数据分别保留。此次限定缺口的修复不等于 R21 整体收口，未进入 R22。
