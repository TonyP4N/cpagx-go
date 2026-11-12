# 第十轮：Linux 隔离探针稳定性验收

基线 `ee0cefa5a2a4907198ec6d158fdbac366760a00a`，分支 `refactor/m1-evidence-core`。有限条件见 [计划](round10-plan-20261026.md)。本轮只改合成验证器及其夹具，业务 Worker、guardian、隔离入口 init.py、默认路由与冻结包均未修改。

## 复现与修复

上一轮 CI 的具体调度无法精确重放，本轮对相同失败机制做确定性注入：旧验证器在启动 timeout 容器后延迟10秒再读PID。容器已有 `reason=timeout, group_exited=true, returncode=-15` 回执，但旧验证器仍要求 `docker exec` 成功，进而断言失败。记录见 `validation-round10/pre-fix.log`、`pre-fix/results.json` 和实际执行脚本 `pre-fix/executed-reproducer.py`。该脚本记录当次绝对路径，重放应使用基线checkout及其原始probe，不能混用新夹具。

修复将就绪与退出分开：

- 合成core完成启动后原子写入 child/guardian/worker/escaped 快照。双杀必须先读取完整快照，再核对实际父子关系及所杀身份；无就绪证明不执行双杀。
- timeout验证不再与2秒超时竞争 `docker exec`。Worker结束后输出结构化原始退出回执及启动快照，宿主待容器退出后读取Docker日志，严格核验attempt身份、超时原因、负退出码、group_exited与PID关联；同时核验容器停止、宿主Pid=0及退出码。未就绪超时单独记录startup=null，不伪造启动成功。
- 计算超时仍2秒、容器总时限仍20秒、CPU仍0.25核，其余资源限制不放宽。双杀就绪等待12秒；Docker命令默认45秒有界，取就绪快照命令还受剩余就绪期限约束。缺证、坏证、错误退出与OOM不能被判成正常超时。
- 每个容器唯一命名，失败保留状态/日志且清理；单个探针失败后仍运行后续独立探针，整轮最终非零退出，不用后续成功掩盖失败。

## 验收矩阵

| 条件 | 验证与证据 | 状态 |
|---|---|---|
| I1 旧竞态 | 原2秒超时＋宿主延迟10秒，已退出却取证失败 | 已复现 |
| I2 正常超时 | 完整启动快照与退出回执一致，容器确已退出 | 通过；实际逐轮JSON留档 |
| I2 启动超时 | core启动延迟4秒，guardian仍2秒超时，startup=null且退出证明完整 | 通过；实际逐轮JSON留档 |
| I2 延迟观察 | 先docker wait确认容器停止，再读取日志；无需容器内exec | 通过；实际逐轮JSON留档 |
| I3 双重崩溃 | 获取完整身份并核对后双杀，容器137退出/Pid=0 | 通过；实际逐轮JSON留档 |
| I4 资源回归 | memory/disk/output/pids/cpu原断言保留；四种时序各重复3轮 | 通过；实际逐轮JSON留档 |
| I4 回执反例 | 缺失、坏JSON、重复、错身份、假退出、OOM、错PID、超界耗时均拒绝 | 8项单测通过（包含多个反例） |

实际Docker证据 `validation-round10/linux-results.json` 与 `linux-run.log`；单测 `unit-tests.log`。本地及远端完整结果见本文末尾汇总，不以本表预期代替执行结果。

## 保持不变和剩余事项

冻结标签 `cpag-engineering-synthetic-rc1` 仍指向 `49e998545b9b7b47f2b1dc9b19e6d8562f780765`；离线包SHA256仍为 `c199dd417e1c59c55563c5535e32d26197b164c95ae17c0ef3bb621f7228b49e`。默认入口与业务执行代码无diff。

本轮证据仅覆盖单机Linux合成隔离探针。重复通过不是任意负载/任意故障下无缺陷证明；Docker整体不可用时只能明确失败，不能制造退出依据。没有增加跨主机或生产保证。M4/R09—R10/R13补充测试稳定性证据，仍部分完成；M0—M6及R01—R13其余状态沿用第九轮/第八轮，不由本轮测试数量改变阶段判断。

真实历史材料缺口仍为旧任务输入、版本配置、任务记录与原产物、Neo4j只读导出；工业效果另需授权同批次双源数据、设备/字段映射、时钟依据、独立标注和保留集。M2/M3/M5相关真实验收及整体重构未完成。


## 本地最终结果

17个真实容器探针全部通过并清理：5项资源探针各1次，正常超时、退出后观察、延迟启动超时和双杀各3次。最终严格回执检查重新应用于全部9个timeout记录通过；8项单测通过。没有借助重跑覆盖失败结果，本轮首次完整新验证器执行即通过。

## 远端补充复现：双杀命令也随容器结束

首个实现提交 `c93b6c08d0b19b918a492ca1e02d31a8fffb54b3` 的 CI 40267640697：前16个容器探针通过，第3次doublekill失败。`ci-first-results.json` 显示已获取就绪身份，注入docker exec返回137；Docker最终状态也为137、非OOM、Running=false、Pid=0。旧检查假定发起双杀的exec必须返回0，未考虑PID 1退出会同时杀掉该exec。此次失败没有通过重跑掩盖。

追加修复：先核对core的父进程身份，发送guardian SIGKILL后立即flush结构化回执，再发送worker SIGKILL；注入后有意等待2秒，使注入进程被容器结束一起杀掉的路径可稳定覆盖。必须同时满足回执身份匹配、已发送guardian信号、injector退出0或137，以及Docker非OOM的137退出/Pid=0；缺回执、其他退出码、OOM或仍在运行一律失败。信号发送回执本身不是退出证明，退出依据仍为Docker最终状态。新增相应负例，单测总计9项。实际三轮回归见 `doublekill-final.json`，其余14项未改动，由最终CI再次完整执行。


## 最终远端验收

修复提交 `fbaf36992637b7de631ce1d0e4c8cb69dbd95a88` 的 [CI 40268136264](https://github.com/TonyP4N/cpagx-go/actions/runs/40268136264) 11项全部通过，未对该提交重跑失败项。Linux隔离专项重新完整执行17个真实容器探针，全部通过并清理；9项负例/回执单测通过。归档 `ci-implementation.json` 与 `linux-ci-results.json`。最终实现包含初始timeout观察修复与随后远端捕获的doublekill注入进程退出修复，不能只引用第一次本地通过代替此最终结果。

本轮有限退出条件I1—I5满足。保留首次失败资料；没有证据声称任意极端负载下均无问题。冻结版本和默认入口不变，原真实材料待办和阶段未完成结论不变。
