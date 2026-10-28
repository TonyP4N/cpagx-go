# R19 本轮核心独立预期与测量合同

在调用新 DAG6 核心前登记。父预登记 `round19-core-bottleneck-preregistration-20261028.md` / `9384fbd` 为配额及退出标准；本轮不启动服务，不修改 Go、Worker、备份或既有默认入口。

## 手写小例预期

原件由既有手工 PCAP/CSV fixture 构造，不读取分析、预测或标签后选择答案。以下预期先于新核心输出固定：

|小例|原件与独立预期|
|---|---|
|正常离线|1请求+1成功响应、5条工艺数据（另表头）、0→1一次变化；1操作、1变化、1候选，候选仍是假设，协议success不证明物理/攻击/因果|
|无响应|1请求无响应保留；响应状态missing；回放请求已到、响应/变化未到的prefix为pending_response且候选为空，不能利用未来原件补齐|
|错误响应|保留错误响应原帧与错误状态，不得改成成功、丢弃原件或把反证删去|
|两请求同变化|2请求+2响应、同一0→1变化；2操作、1变化、2候选，两方原件和歧义均保留，不任意选赢家|
|同前缀改未来|请求及此前CSV不变，只改未来响应/后续值；已保存prefix的完整analysis/trigger/事件/关系/原件引用和修订不变；分段未来帧不提前出现|
|重复/冲突声明|重复同一原始记录不增加事实；未知/错误digest声明不能覆盖原件；duplicate/conflict计量和原因必须保留|
|迟到|12秒原始样本13秒到达在2秒允许量内，有late痕迹且可产生候选；关闭之后19秒到达为too_late，不静默改写已关闭操作或历史|
|完整性负例|改原件、删shared对象、坏整数引用、缺历史index/记录、未知版本及篡改上下文均必须拒绝；重算外层自报hash不能代替正确Merkle引用/完整历史/源核验|

CSV定位按逻辑记录处理并保留真实字节边界；PCAP独立扫描全局头/逐帧记录头，核对frame、record及file SHA、raw_hex、offset/length和原时间，不借核心解析器决定“原件是什么”。引用分页最多100，不能以截断后非空替代完整分页/可继续状态。

## 新旧完整对象比较

小例以同一原始数据和同一**判断语义**配置运行旧核心与新保存/读取路径。逐JSON Pointer比较全部字段、数组顺序和标量类型；bool/int/float不混同。不能先删除analysis、未知、反证、候选、引用再比较。允许的差异必须逐叶路径登记 old/new精确值与理由，新增元数据也要明确；整对象/数组不可作允许差异。

snapshot/state/revision的容器身份用显式双射及全链引用映射，不能复用一个新ID吞并多个旧ID。业务 operation/change/candidate/claim ID不默认重写。当前旧candidate ID依赖identity_config，capacity/transport差异须由core owner明确semantic identity规则；规则未锁时对应比较标为等待，不自动忽略不一致。

## 六格测量

顺序 S100离线→S100回放→M1000离线→M1000回放→L10000离线→L10000回放，每格至少一个**新输出目录**和一次完整运行，root分配串行CPU窗口。输入须匹配旧生成器冻结 PCAP/CSV SHA，保留全部请求/响应/数据/窗口/缓冲/迟到；profile、quota、image id及harness/core源码摘要在启动前固定。失败/强杀/不完整产物原样保留，不覆盖旧目录。

固定 Docker4CPU、8GiB内存、4GiB tmp、1GiB完整物理输出；分析/完整验证/查询及验证准备总1800秒。export之后用新进程完整source verify；query用另一新进程做冷reader/热reader两次，每完整响应10秒/8MiB/100项。OS cache不作清除声明。本地无硬配额路径只用于小单元，不计六格成功。最终物理库存、数据库/临时采样、CPU/RSS/cgroup不同定义分别记账，未实际施加的配额明确false/null。

本地受控 query capability 经父批准：每格随机32字节secret只经私有IPC/继承FD，完整verify后签发HMAC绑定manifest/完整physical-input inventory及logical root；query验证签名并重核当前所有bytes与访问节点。secret、approval不写artifact、不进入参数/ENV/日志；默认无capability路径仍完整verify。该测量称“新进程冷reader”，不冒充冷sourceverify或外部独立性证明。

shared_export API 尚未落地时报告 waiting_for_core_interface，不创建假通过。六格缺整体新输出reader/完整核验/查询任何一步均不是成功；M/L失败先按实际软件/配置/实证资源原因记录，不统称环境问题。本轮不替代最终三次、Ubuntu参考环境或工业数据验收，不结束R19或进入R20。

## 已落实的比较路径与版本补充

旧参考采用原 `ReplayCore`、原未缓存 `ReplayInputs`、相同完整业务profile；只将schema校验名显式分派至新profile schema。旧参考不设置compact开关，不调用新缓存判断器。业务operation/change/candidate/claim ID全部原样比较；只有graph/state/snapshot/revision容器身份逐叶列明且检查双射及全链引用。

标准历史投影显式为 `standard-graph-events-1`；初版dev1缺省历史不含graph/events，已判定不能通过完整旧历史内容验收。后续新配置使用 `shared-storage-budget-2` 扩大共享逻辑长度算术护栏，1GiB完整物理输出、8MiB/100查询和8GiB内存不变。prepared-prefix缓存只在显式 `prepared-prefix-cache-1` 下使用。固定生成器6准入须重算全部原件、profile、arrival schedule及preflight；5秒关联窗、300秒buffer、2秒允许迟到不变，不把旧5/4配置自动改名。

测量脚本第二次查询实际会重新创建reader，故标签为 `same_process_repeat_new_reader`，并明确OS/decoder缓存状态未验证。每页独立计10秒、8MiB、100项；选中操作的全部引用通过连续、不重复、total稳定且终点完整的分页检查。全部页与完整历史查询共同消耗原1800秒。各attempt保存执行harness完整字节与摘要，后续脚本修改不能影响正在运行的attempt。

## 已观察结果（尚非六格完成）

独立小例脚本 `scripts/validation/round19_core_small.py` 已以显式prepared-prefix策略运行11小例：4个离线和7个回放，全部逐字段比较通过。正常回放16个完整snapshot和11个revision；关闭后迟到小例17个snapshot和11个revision。改变未来响应及CSV数据后，前5个snapshot及4个revision完整相等，无任何身份差异豁免。缺原件、同大小原件篡改、重算外层hash后的整数child引用破坏、缺历史根均拒绝。首次迟到测试错误地重排CSV物理记录，旧参考先拒绝 `source_record_not_next`，该失败保留；第二次仅修正手写到达顺序后通过。上述为本地语义/完整性小例，未充当配额或服务验收。

dev1镜像为 `sha256:f810c8163b2e69df3e8b51f28c86c785ba15d367df4000a83fedeac3ae6b1c8a`，81件运行时源码/schema与 `a3d2a92f0c2f5dd71b69e050803fc1f7e1ba3cf2` 完全匹配。S离线初测整链38.626秒，但不计新配置完整六格。S回放导出1320.040秒，完整验证在原1800秒总限被停止，整链失败；最终测得1802.006秒含停止和清理约2秒，容器exit137但 `OOMKilled=false`，未签发approval、未查询。物理attempt85,152,944字节。原report的verify状态残留running是首版runner终态记录缺陷，整体failed及容器exited记录明确；原记录保留，第二版修正失败phase终态。

dev1回放导出完整terminal summary记录关联判断587次/555.802秒、历史生成310次/644.752秒、store写入1558次/620.608秒、节点验证38.474秒、网络解析1.710秒、CSV解析0.010秒。嵌套时长重叠，不求和；验证被强杀后仅有256条受限原始phase行，没有完整summary，不能据此估计全验证成本。dev1还存在已知标准历史缺口，因此即使时间通过也不能接受。dev1完整harness字节和初始摘要单独冻结，原始镜像、成功/失败目录与原始日志均保留。下一版须在新镜像和生成器6上重新按六格顺序测量；当前M/L未完成，不能宣布容量通过。

## dev2拒绝及本机暂存对照

dev2为 `sha256:9084aaa0b4bc4dfbd7f241ba472422846fce275a70fb1ff162f2832d1c734446`，81件core/schema与签名版本 `864a999be93b360a8703ccd407f8ada493104c3b` 完全一致。首次S离线在FYP bind输出路径导出约4.3秒时，严格 `EvidenceIndex.verify` 拒绝 `evidence file changed`。独立诊断保持原验证代码不变，记录到CSV只有ctime从1793197466797392860变为1793197469871011712；dev/ino/size/mtime完全相同，初始及verify前后字节SHA都为 `9d933fd88020df0172cbd12fd58ac1ee63f71b83ebfb901f5ea500c42c856c55`。只能证明元数据漂移，未证明由iCloud或virtiofs中哪一层引起，未删除ctime核验。

父代理随后明确授权开发测量位置 `core-local-scratch-1`：每格在 `/private/tmp` 下新建0700目录，沿用原镜像、原件、配置和严格签名/SHA核验。整链结束把所有原始输出、完整harness、测量及日志复制至新受控目录，逐文件SHA及库存集合核对，再使用仍只在内存中的当次approval/key运行交接后新进程query。暂存及受控副本都保留。原完整输出预算仍1GiB，分别记账；交接后暂存副本计入4GiB临时占用，并与查询/tmp实测采样合计核对，不把同一产物两份复制合计作为1GiB准入门槛。复制、核验和交接后query均计入原1800秒。该位置对照不是正式Worker或服务交接验收。

本机暂存第一次尝试在core启动前遇到短暂tag库存拒绝，目录和错误原样保留；随后只读检查确认相同immutable ID仍存在、context为desktop-linux，改用已核实SHA，不重建镜像。第二个本机暂存新attempt完成S离线整链56.066秒：export23.250秒、完整sourceverify21.292秒、原位置query4.264秒、交接后query4.282秒；165/165原件引用完整分页，最终所有普通文件（含最终report）逐件清单与受控副本一致。受控完整目录8,096,459字节。此为单次开发核心测量，不能替代剩余五格或正式环境复验。

dev2离线导出native完整阶段为21.475秒，其中判断3.937秒、store写入11.429秒、标准投影2.885秒、节点核验3.020秒。dev1对应判断3.998秒、store8.074秒、投影1.605秒，观察到store/投影回归，不能报告整体提速。dev2回放在父代理要求先核查该回归时受控中断，完整partial及 `controller-interruption.json` 保留；不将行政中断当性能失败。后续优化若改变runtime，须再次固定新镜像，所有版本结果均保留，不拼接不同镜像的六格为一次完成。

## 2026-10-29 原56六格终态补充

上述dev1/dev2段落为当时历史记录。最终83件core/schema绑定签名 `56e106b2a44d88a0c67280d5d9e6a1e13aa79a75` 和同一immutable镜像，固定生成器6原件及原配额，已逐格实际运行。S离线36.739秒、M离线551.103秒通过完整输出、独立来源核验、全部选中引用分页及交接后查询。S回放在独立来源核验阶段到时限；M回放、L离线、L回放均未完成导出。四格不通过，六格不整体通过。

L回放首次因验收器采样SQLite临时journal删除竞态在857.260秒中断，独立复现、失败及完整partial保留，不计核心性能失败。限定修复只允许live sampler对这一确切临时路径记录vanished/incomplete，终态库存、原件/固定产物、权限仍严格；5项针对测试及29项相关回归通过。第二次仅用签名2fbcf00修复harness，原56核心不变，controller1801.935秒、driver1802.110秒，以原生 `shared_store_deadline_exceeded` 明确失败，没有再重试。L完整原件admit/ever-observed覆盖审计未到达，不能宣布大规模覆盖通过。

完整公开衍生事实、原件/衍生SHA与逐phase资源表见 `validation-round19-core-independent/dev4-final-matrix-v2.json`、`dev4-final-resources.md`、`custody.json`。缺测指标为null；最终目录包括交接库存，whole-driver独立核时限。parent另行执行的原56函数插桩诊断及后来契约修复的S链路/旧M兼容核验不拼入本矩阵。此轮仍不构成正式服务、Worker、参考环境、工业数据或R19关闭。
