# R19 原56 S offline 函数CPU诊断归因（partial）

只读整理 `outputs/cpag-r19-function-profile-attempt1` 和 `attempt2` 已有材料；没有重跑核心或修改原始pstats/数据库。公开的[完整脱敏函数JSON](validation-round19-dev4-cost-attribution/S-offline-functions-public.json)包含 **全部571个pstats函数与caller边**，其中196个core函数逐值核对原 `result/profile.json`，另375个stdlib/builtin/generated函数一并保留，不是top-N摘录。全部原始普通文件的SHA256与大小、两份custody核验及镜像/代码/脚本身份也在JSON留存。源路径改为仓库或stdlib逻辑位置，host挂载源目录和1个函数标签内存地址已脱敏，原始记录未改。

## 两次尝试及计量边界

attempt1将诊断复制为 `profile.py`，遮蔽Python标准库同名模块；`import cProfile`阶段报 `AttributeError: module 'profile' has no attribute 'run'`，核心分析未开始。保留这次失败及其SHA，不能当作运行成功或零成本；该次计算耗时和容器终态没有记录，均为null。

attempt2改用 `round19_core_profile.py`，脚本内容SHA相同。固定原runtime `56e106b2a44d88a0c67280d5d9e6a1e13aa79a75`、镜像 `eb80e205…615f8c`，没有因诊断修改业务算法。脚本以 `cProfile.Profile(timer=time.process_time)`包围S offline `export_task`，记录状态是 **`exported_not_source_verified`**：导出完成，但没有完整来源重算核验或查询。

| 项目 | 实测值 | 范围 |
| --- | ---: | --- |
| 诊断wall | 98.011587 s | 脚本计时边界，包含插桩；core导入在起表前 |
| 诊断进程CPU | 97.501817 s | 含探针开销，非无探针CPU成绩 |
| pstats全部self time之和 | 97.263765 s | profiler开启区间的函数归属，与脚本边界不同 |
| 进程RSS累计高水位 | 54,345,728 B | 非逐函数内存或阶段增量 |
| cgroup内存峰值 | 54,562,816 B | 容器记账，与RSS口径不同 |
| cgroup CPU usage | 97.840882 s | 容器累计，user52.029706 / system45.811175 s |
| cgroup nr_throttled / throttled_usec | 0 / 0 | 当前诊断容器的报告值 |

容器退出码0、`OOMKilled=false`。host记录额度仍4 CPU、8 GiB内存、4 GiB `/tmp`，网络关闭、只读rootfs；脚本deadline1800秒。但这98秒是 **process-time timer+cProfile插桩诊断**，不能拿来替代无探针S容量样本、计算与旧样本的加速/减速比，或外推M/L。较高system CPU不单独证明磁盘瓶颈；没有探针开销的配对测量。dump_stats和结果表构造等部分工作位于profiler关闭后、脚本wall/CPU截点前，两套总数应分别保留。

## 函数层已观察到的成本

下表为选摘，全部571行见JSON。self是函数自身CPU，inclusive包含子调用；**父子和递归行互相重叠，不得相加、堆叠或称为互斥阶段**。

| 函数（原始行号） | total calls | self CPU s | inclusive CPU s |
| --- | ---: | ---: | ---: |
| shared_export.export_task:155 | 1 | 0.004295 | 97.495917 |
| shared_export._build_business_roots:118 | 1 | 0.000331 | 82.304147 |
| shared_artifact_store_compact._encode:111 | 1,560,343 | 3.835086 | 42.565024 |
| dual_source._analyze_prepared:126 | 1 | 0.126840 | 31.379904 |
| dual_source.collect_refs:158 | 10,384 | 0.009896 | 17.157515 |
| dual_source.references:58 | 10,384 | 0.049641 | 17.147619 |
| dual_source.references内部visit:60 | 1,650,018 | 7.439589 | 16.993071 |
| contracts.validate:35 | 5,999 | 0.009549 | 17.459004 |
| contracts._validate:40 | 999,747 | 5.480649 | 17.420254 |
| compact_projection.store_standard_projection:14 | 1 | 0.000009 | 16.034646 |
| dual_source_export.event_graph:28 | 1 | 0.001543 | 15.624641 |
| shared_artifact_store_compact.verify:407 | 1 | 0.153732 | 15.124462 |
| pipeline.canonical:14 | 1,930,426 | 2.360907 | 12.771107 |

原始caller边明确 `_analyze_prepared → collect_refs → references → visit`。因此references的17.147619秒是31.379904秒关联合并段里的嵌套工作，不能再相加为48.5秒；visit的165万total calls包含递归，primitive calls是10,384。该证据支持继续审查重复引用遍历、验证和序列化调用，但**没有**测得独立规则判断/独立证据组织wall时间，也没有证明缓存改动的收益或正确性。

同样，`_encode → _array/chunks`、`add/intern`等存储行存在嵌套，不能相加得出“存储总耗时”。标准graph的identity callback包含存储工作，投影和存储也非独立。`Reader.verify`这15.124462秒是导出期间的节点完整性核验，**不是** `verify_task` 的完整来源重建；不得据此声称新来源策略已跑完。本次没有相应的全来源核验、冷/热查询、全链或逐函数内存结果，JSON均明确未测。

## 可复核性与结论边界

完整JSON保留函数原call/self/inclusive数值及caller原始pstats tuple（不擅自重标其顺序），所有公共function ID与caller ID引用闭合；196行core投影与生产诊断JSON逐值一致。全部self之和与原pstats total_tt一致。两个attempt的原始普通文件在生成补充前后SHA一致，custody声明全部匹配；没有发布原二进制pstats或带本机目录的host配置作为脱敏材料。

这是一份原56、小规模、合成输入的函数诊断。它补充了此前合并阶段计量中不可见的内部调用线索，不能关闭M/L容量、回放增量成本、完整六格、参考环境或真实工业数据门槛。
