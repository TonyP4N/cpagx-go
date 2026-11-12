# R19 核心独立证据（六格测量终态，未整体通过）

`custody.json`的35件衍生记录列明受控原始SHA与公开衍生SHA。只替换私人workspace/user-home/scratch路径，保留其他值及标量类型；没有发布数据库原件、PCAP、CSV、secret或approval。三个早期progress摘要直接生成于公共目录，未找到单独脱敏前原件，故仅在 `preserved_public_only_snapshots` 登记自身SHA及该限制，原样保留、不作为最终run原件。原始失败、完整产物、逐件交接清单、完整harness字节及镜像均单独保留。

dev3历史测量版本为 `39b8b3610431c574bb5c0631eb000174e7f0274b`，镜像 `sha256:f162027639d8ccf2696b298e696076a0b9f2864e559ac05119f46b6176133d5c`。实际镜像81件core/schema与该签名版本、build前冻结源码逐件一致。独立复核随后发现旧verifier未绑定 `run_manifest.synthetic` 和回放 `final_snapshot_number/id`；因此dev3结果只保留为历史测量，不能计最终严格六格。修复后approval版本升级2，须重新完整来源核验，不接受旧临时permit。当时等待的新dev4随后已冻结，本次实际结果见下方“原56镜像六格”。

六格使用新生成器6、同一原件SHA、4CPU/8GiB/4GiB临时/1GiB完整输出/1800秒总预算。终态为S/M离线2格通过，S/M回放及L两模式4格未通过。此为本机开发核心测量，不是正式Worker/服务接入、Ubuntu参考环境、工业数据验收或R19关闭。完整事实见 `dev4-final-matrix-v2.json`，简短逐格、逐phase资源表见 `dev4-final-resources.md`；早期progress公共快照仍保留，不覆盖。

实际开发环境另见 `dev4-development-environment.json`：Docker29.1.3、Linuxkit6.12.54/aarch64，VM有10CPU，MemTotal8,217,448,448字节，低于容器请求的8,589,934,592字节。8GiB是容器配置上限，不能表述为VM实际可用8GiB；SSD未独立核验。原冻结quota保持不变，不把本机开发测量称为参考环境验收。

## 原56镜像六格（终态）

本次固定原生运行时为 `56e106b2a44d88a0c67280d5d9e6a1e13aa79a75`，83件core/schema与实际镜像 `sha256:eb80e205306c0463eede21e546b8a4fb1be4fa9e51deb8bd7652cdee6e615f8c` 全等。S/M使用原冻结harness；L离线及首次回放使用签名 `7cc85eed856c453c505e986c6a9c81f60b624e97` 的专用覆盖验收器，原生83件不变。L回放首次遇验收器采样竞态，第二次使用签名 `2fbcf00dbbb477830797debae545b6d182da0d50` 的限定采样修复。两次均从各自只读原56源码视图运行，避免后来workspace契约修复混入本次身份记录。

|六格|controller整链秒|结论|
|---|---:|---|
|S离线|36.739|通过；最终实际目录及完整driver时限另经v2摘要核对|
|S回放|1801.151|失败；独立来源重建达到时限，未查询|
|M离线|551.103|通过；完整验证、引用分页及交接后查询通过|
|M回放|1800.945|失败；导出达到时限，未形成完整新产物|
|L离线|1802.076|失败；关联/证据组织1711.234秒已返回，首次分析写入22.880秒失败；未完成导出|
|L回放attempt2|1801.935|失败；导出达到原时限；未来源核验、覆盖审计或查询|

这些超限值包含停止/收尾；未扩展原1800秒成功门槛。真实最终目录（包括handoff-inventory）须≤1GiB，whole-driver须≤1800；v2摘要保留原controller状态并单列外部资源接受结论，不回写原report。缺测指标为null，阶段累计RSS不冒充最终进程或kernel峰值，嵌套阶段耗时不相加。

L回放首次857.260秒终止于验收器 `is_file/stat` 对 SQLite rollback journal 删除的竞态，不能计核心性能失败或完成的L测量。该原始失败、完整交接和独立竞态复现均保留（`dev4-L-replay-instrumentation-failure.json`、`live-sampler-race-before.json`）。新 `matrix-live-file-sampler-2` 仅在运行中对这一确切临时文件记录不完整样本；固定原件/产物、权限及终态库存仍严格拒绝。5项限定测试及29项相关回归通过，日志另存。第二次回放的完整83件核心及93件只读视图清单见 `dev4-L-replay-attempt2-frozen-view.json`，终态后逐件仍只读且未变。实际遇到1次journal消失并记录为不完整样本，未中断。

第二次回放whole-driver为1802.110秒；native export为1801.078秒、CPU1552.340秒、最终进程RSS120,107,008字节、kernel cgroup峰227,446,784字节。history374次调用中373返回、1失败，不能充当完整历史。最终保留目录95,728,630字节，partial failed-marked产物89,558,423字节；它们低于1GiB不构成容量成功。全部原始bytes及交接清单保留，没有重试核心deadline失败。

本次原56镜像外层manifest仍有512GiB逻辑长度上限与内部budget2的4PiB护栏不贯通问题。后来的契约修复不在本矩阵镜像；高extent整链未通过，不能据单元测试宣称已支持。只读已保留manifest声明审计见 `dev4-original56-outer-extent-audit.json`：S离线、S回放、M离线已形成外层manifest的最大logical root均低于512GiB，其余没有完整外层manifest；这只是声明读取，不替代sourceverify。association_and_evidence仍为合并阶段，没有在矩阵中分别测量两者；后续函数诊断不得替代本矩阵。

|dev3历史测量（不计最终严格六格）|当前状态|
|---|---|
|S100离线|测量通过39.263秒；含当时verifier、全部引用分页、逐件交接和交接后新进程query；上述binding缺口使严格接受待重验|
|S100回放|整链失败1800.626秒；export1166.037秒，sourceverify634.131秒到原总限拒绝，未签发approval、未查询|
|M1000离线/回放|未在dev3执行|
|L10000离线/回放|未在dev3执行|

旧版记录不拼入最终六格：dev1回放因原1800秒总限失败，且标准历史缺graph/events；dev2首次bind路径拒绝发现只有ctime漂移、原件SHA不变，未放松核验，也未证明具体云同步实现是原因；dev2本机暂存S离线通过，但store/投影变慢；dev2回放因父代理要求先查该回归被行政中断。后者的原始report可能记录强杀后的JSON解析失败，须结合controller-interruption记录阅读，不能当核心性能失败。dev3首次S启动为人工误抄image ID的准备错误，未执行core，原始记录保留。tag短暂库存拒绝也只算环境准备失败；后续全部从已核验绑定JSON直接取immutable ID。

`dev3-independent-small.json`为11个独立手写小例：新旧完整业务对象、全部历史snapshot/revision及身份双射、完整raw引用、反证、迟到、重复/冲突、未来前缀不变和完整性负例。源码before/after摘要一致。它不能替代六格容量测量。各阶段嵌套时长重叠，不求和；progress仅统计已结束调用，未终态不推算通过。

`dev3-manifest-binding-before.json`以冻结旧image独立复现4种manifest篡改，经issue_approval/open_reader共8次错误接受，未保留任何token。`manifest-binding-fixed-independent.json`为修复源码上的独立11小例，源码before/after完全一致；33个完整性拒绝全部通过，新增synthetic两模式及回放final number/id共12次，分别覆盖verify_task/issue_approval/open_reader。该小例补门槛通过不代表最终dev4六格已完成。

`dev3-S-replay-final-phases.json`记录旧版完整终态。不同于dev1被强杀，dev3本次由native显式拒绝 `shared_store_deadline_exceeded`，export及verify均留下完整terminal summary；verify只有285个结束history调用，不能冒充310条完整来源重建。失败受控副本86,357,510字节，与原scratch全部普通文件清单完全一致。最终验证策略将使用完整来源Merkle重建，避免重复保存第二份SQLite，原artifact仍完整核节点及字节；策略门槛、正反例与新固定镜像六格必须另外确认。
