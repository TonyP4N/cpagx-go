# 原56核心六格资源记录

由 `dev4-final-matrix-v2.json` 的保留终态事实生成；不重新运行分析。原生83件始终绑定56e106b与同一immutable镜像。S/M原验收器，L离线为7cc覆盖验收器，L回放第二次为2fbc限定采样修复；第一次采样器故障另列。

限额：4CPU、容器配置8GiB、临时4GiB、完整输出1GiB、整链1800秒。每请求10秒/8MiB/100项。VM实际MemTotal8,217,448,448字节，小于容器请求；本机开发测量不是参考环境或工业验收。

## 计数、时间与完整存储

计数顺序为网络观测/工艺观测/操作/变化/候选。回放未完成的末态计数为null；已发布中间snapshot不冒充末态。L有过期时全部原件admit/ever-observed另须独立覆盖审计，不能仅用末态live+frozen计数证明完整。

|格|期望固定计数与候选界|实际末态计数|controller/driver秒|实际目录/产物字节|产物状态；整链结论|
|---|---|---|---:|---:|---|
|S/offline|200/100/100/99/[2594,2596]|200/100/100/99/2596|36.739/36.845|8116055/7611037|exported; passed|
|S/replay|200/100/100/99/[2594,2596]|null|1801.151/1801.296|86484618/85817016|exported; failed|
|M/offline|2000/1000/1000/999/[31751,31813]|2000/1000/1000/999/31801|551.103/551.314|101520402/100668118|exported; passed|
|M/replay|2000/1000/1000/999/[31751,31813]|null|1800.945/1801.090|85701139/84640132|failed_marked; failed|
|L/offline|20000/10000/10000/9999/[317500,318125]|null|1802.076/1802.178|5795055/2658755|failed_marked; failed|
|L/replay|20000/10000/10000/9999/[317500,318125]（末态观测/变化允许过期；覆盖审计必需）|null|1801.935/1802.110|95728630/89558423|failed_marked; failed|

实际目录包含最终handoff-inventory；其字节和whole-driver另作严格资源接受门槛。未达到完整导出的partial字节不是容量成功。输出副本与保留scratch分别计数，交接/query时scratch另作为临时占用；没有把1GiB输出门槛减半。

## 分阶段成本

各阶段独立进程，wall含义分别保留；RSS和kernel cgroup peak不是同一指标。tmp是观测采样峰而非kernel精确高水位。null表示未到达/未记录；不能以较早阶段RSS或进度填补。CPU不从嵌套decorator累计求和。

|格/phase|controller/native wall秒|native CPU秒|RSS/cgroup峰MiB|cgroup CPU秒|tmp/保留scratch+tmp采样峰MiB|
|---|---:|---:|---:|---:|---:|
|S/offline/export|15.885/15.304|14.839|52.359/56.617|15.242|0.000/0.000|
|S/offline/verify|13.749/12.498|12.462|60.059/59.469|12.798|0.000/0.000|
|S/offline/query|3.264/3.040|2.998|61.848/60.707|3.066|0.000/0.000|
|S/offline/query-after-handoff|3.280/3.047|2.978|62.461/60.352|3.046|0.000/7.569|
|S/replay/export|1103.273/1101.302|953.224|104.652/183.598|984.644|0.000/0.000|
|S/replay/verify|697.420/696.578|695.754|148.711/230.023|715.444|0.000/0.000|
|S/replay/query|null/null|null|null/null|null|null/null|
|S/replay/query-after-handoff|null/null|null|null/null|null|null/null|
|M/offline/export|300.758/299.762|279.987|279.949/393.492|288.598|0.000/0.000|
|M/offline/verify|239.924/239.725|239.080|365.680/462.656|245.911|0.000/0.000|
|M/offline/query|4.786/4.572|4.229|67.184/154.266|4.364|0.000/0.000|
|M/offline/query-after-handoff|4.726/4.510|4.136|67.133/154.246|4.271|0.000/96.646|
|M/replay/export|1800.578/1799.930|1555.353|87.711/185.270|1606.877|0.000/0.000|
|M/replay/verify|null/null|null|null/null|null|null/null|
|M/replay/query|null/null|null|null/null|null|null/null|
|M/replay/query-after-handoff|null/null|null|null/null|null|null/null|
|L/offline/export|1801.527/null|null|null/null|null|0.000/0.000|
|L/offline/verify|null/null|null|null/null|null|null/null|
|L/offline/query|null/null|null|null/null|null|null/null|
|L/offline/query-after-handoff|null/null|null|null/null|null|null/null|
|L/replay/export|1801.272/1801.078|1552.340|114.543/216.910|1603.454|0.000/0.000|
|L/replay/verify|null/null|null|null/null|null|null/null|
|L/replay/query|null/null|null|null/null|null|null/null|
|L/replay/query-after-handoff|null/null|null|null/null|null|null/null|

完整JSON还保留kernel CPU原始usec、实际quota、嵌套phase和原始packet SHA。association_and_evidence在本矩阵为合并阶段；没有分别测量两者。L离线终态decorator中关联1711.234秒返回、首次store22.880秒失败；它们不替代缺失的最终native RSS/cgroup。

## 交互查询

cold是新进程、持当次完整来源验证私有capability的冷reader，不是新的全sourceverify；repeat为同进程重新打开reader，OS/解码缓存状态未独立证明，不能称持续reader热缓存。成本为每次请求wall，不是所有分页总和；每phase CPU/RSS见上表。

|格|首次cold/重复reader/剩余页秒|交接后cold/重复reader/剩余页秒|最大响应字节|
|---|---:|---:|---:|
|S/offline|1.134/0.858/1.014|1.126/0.854/1.035|2837137|
|S/replay|null/null/null|null/null/null|null|
|M/offline|1.548/1.258/1.546|1.509/1.278/1.508|2851032|
|M/replay|null/null/null|null/null/null|null|
|L/offline|null/null/null|null/null/null|null|
|L/replay|null/null/null|null/null/null|null|

首/中/末历史metadata、graph/events页面、修订与历史操作引用的实际样本保存在完整JSON；本次回放格未进入查询，均null。完整历史逻辑根核验与这些有限交互样本是不同门槛。

## 首次失败与边界

- S/replay：RuntimeError / `verify:ValueError:shared_store_deadline_exceeded`；whole-driver 1801.296秒，原report SHA `72e712852d64ecf2a5c0500561e3ead3ddf37be443d12bc7144b69b5d4b9d652`。
- M/replay：RuntimeError / `export:ValueError:shared_store_deadline_exceeded`；whole-driver 1801.090秒，原report SHA `95e4695f87ab4ff210a2f6faef74a81cc80f29d7f071b79ea0e6114bd783a9e3`。
- L/offline：TimeoutError / `core_chain_1800_seconds`；whole-driver 1802.178秒，原report SHA `c2cc4b5964c34cc435abff340e0d25ec62bc3c65bbac7cd16de7546533daeaba`。
- L/replay：RuntimeError / `export:ValueError:shared_store_deadline_exceeded`；whole-driver 1802.110秒，原report SHA `f149b467d2254b4d60dcd8a0e811d84f3ffe8ba29aa741f037e95bb1b4ecaa9f`。

L回放attempt1另列为instrumentation failure：controller 857.260秒，driver 857.428秒，原report SHA `d7e626861d2a0336587717436e6fac4b09d1541dde8fd07626f01f8aa074dc28`；SQLite journal删除竞态中断了采样器，不计核心性能失败，也不替代attempt2。原目录、完整交接及失败复现保留。

原56外层manifest逻辑长度512GiB护栏与budget2内部4PiB不贯通的问题，后来的5d契约修复未包含在本矩阵；高extent整链不宣称通过。独立小例及修复后S链路/旧M兼容核验另有身份记录，不拼入原56六格。
