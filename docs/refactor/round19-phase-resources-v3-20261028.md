# 显式 phase-resources-3 与生成器6

本项只增加新的计量策略及新生成器选项，不改变已运行任务的环境选择，不修改既有phase-resources-2模块，不改判断缓存实现、Go/Worker或harness选择。下一镜像是否选择3由统一核心runner决定，当前phase2运行不能被追溯改写为phase3测量。

## 进度契约

显式环境 `CPAG_PHASE_STRATEGY=phase-resources-3`、`CPAG_PHASE_METRICS=/runtime/phases.jsonl`：JSONL仍保留前256条sample，最多64个阶段累计所有已经结束的调用（returned和failed），正常解释器退出追加恰好一个terminal_measurement_summary；该汇总不证明计算成功或容器退出。

新增同目录固定 `progress.json`。第一次进入被装饰函数前先发布0结束call，首个结束call即时发布；单一daemon按单调时钟配置5秒周期原子替换，结束call也会补写已经到期的进度。使用同目录0600临时文件、完整JSON编码/flush/fsync、os.replace；替换失败保留上一个完整文档，临时文件清理。进度只有一份被覆盖，不追加数百份JSON；强杀写入中最多留下一个有界临时文件。

这是有界周期机制，不是操作系统调度/阻塞IO的硬实时5秒保证。外层1800秒强杀界仍来自核心runner。只有新策略启用此thread，不为旧2启动thread或写progress。

进度字段：

- `version=phase-resources-3`、`kind=progress_measurement_summary`。
- `measurement_state=in_progress`、`terminal=false`、`completed_calls_only=true`、`compute_success=null`。
- `all_observed_calls/raw_rows_retained/raw_rows_not_retained/phases` 与v2累计形状相同；每phase有calls/returned/failed、累计wall/CPU及进程RSS高水。
- `metrics_file`仅basename，`progress_interval_seconds=5`、`elapsed_monotonic_seconds`、`progress_write_failures/last_progress_error_type`。

当前尚未结束的外层调用不计入任何阶段，也不按经过时间估计；阶段缺席不能补为0或当作没成本。嵌套wall/CPU重叠，不能相加作整链时长；RSS是进程累计高水，不能叫阶段内存分配。后台写失败有计数和安全异常类型，下一次写仍重试；终态JSONL另给progress_writes/progress_last_snapshot_calls。progress本身始终非终态，正常退出后也不改成成功；没有JSONL终态时只能报告计量不完整。样本、进度和终态都不替代原始输入/业务产物验证。

新增有界约束：1个operator target、64phase、ASCII阶段名1..128字符、前256raw、每份progress/summary编码不超过128KiB、安全整数调用计数、有限非负计时和RSS；累计溢出在变更计数前拒绝。target不得与progress.json撞名。原子替换失败不会生成半个成功JSON，也不抹除先前进度。

## 已保留首次失败与修复

第一轮实际子进程测试结束300个函数后进入未结束长函数，强杀前进度却只有261。原因是沿用旧CPU相减顺序 `after.user+after.system-before.user-before.system`，极短函数两个计数均未变时浮点消去可能产生负微数，record拒绝部分调用。随后加固定rusage(.1/.01、前后相同)的先失败测试，原异常记录完整保留。

仅版本3改为两项各自相减后相加；相同计数准确得到0，不把缺失计量补零。旧2代码与选择行为保持原样。修复后v2/v3共12项测试通过（5.253秒），包括实际SIGKILL：最近progress完整保留300已结束calls/其中1failed，未结束phase未计数，JSONL只有256samples且无terminal。其它测试覆盖假时钟到5秒才更新、异常传播、并发400calls不丢、原子replace失败旧完整JSON保留、128KiB/phase/target/数值边界及正常退出只写一次终态。

原始失败/成功日志先存0700 controlled `outputs/cpag-r19-phase3-generator6-evidence-20261028`；公开 `validation-round19-phase3-generator6/` 仅替换个人文件路径前缀并列原/公开SHA。测试证明计量机制，不表示任何S/M/L完整运行通过。

## 生成器6

新增显式 `r19-density-capacity-6`：在5基础上**只在replay新增** `judgement_strategy=prepared-prefix-cache-1`。offline profile字节与5完全相同；storage_budget2、standard-graph-events-1、全部raw/window/sequence/预算保持。旧5目录和省略判断策略的dev1语义不改，6→5/4降级拒绝。判断缓存内容及失效策略由独立核心实现/回归负责，生成器不借此宣称判断或性能已通过。

已从5升级生成 controlled `outputs/cpag-r19-core-cached-generator-{S,M,L}6-attempt1`。每目录含offline/replay-profile、6份case、preflight、matrix和fixture；仍为core_only/integration_ready=false/operator=null，不能由formal Go/Worker路径误执行。原始网络/CSV SHA与固定S/M/L完全一致。精确路径与逐件SHA在公开receipt。

静态生成器全部16项回归通过：包含旧版本1—5、新6跨S/M/L仅该字段变化、原目录不变、offline原字节不变、拒绝降级。没有由本项启动新的分析、回放、服务、Worker或M/L重负载。下一次实际运行必须冻结完整新image源码、选择6与phase3并记录配额和全部失败，不能把旧5/phase2结果改名使用。
