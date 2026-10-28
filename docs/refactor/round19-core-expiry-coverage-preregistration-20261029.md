# R19 L 专用验收器 v4：原件准入与历史观测覆盖

本登记在 L 实跑及覆盖审计输出之前固定。核心83件文件、镜像、生成器6原件/profile、300秒buffer、5秒窗口、2秒允许迟到、4CPU/容器配置8GiB、4GiB临时、1GiB完整输出与1800秒总额均不变。S/M继续原私有冻结harness；仅L采用新版本入口并保存完整字节/SHA。不回写历史原件或既有测量目录。

## 已证实的口径差异

`ReplayCore` 的末态为live观察加已冻结决策引用的观察。未被引用的观察正常过期后可以只保留在历史中。独立6条CSV数据小例中，原引擎和新引擎末态process均为2，全部9个原始单元（2帧、6数据行、1表头）已准入、8个已过期，完整历史及来源核验仍通过。因此不能强令L末态process/changes等于全部原始数量，也不能改变buffer或算法凑数。

## 独立完整覆盖审计

审计版本为 `core-ever-observed-coverage-1`，验收器版本为 `r19-core-l-expiry-coverage-4`。它是完整验证审计，成本计入原1800秒；不冒充10秒交互查询，不代替完整source Merkle重建。原首/中/末历史交互请求仍逐个执行10秒/8MiB/100项门槛。

1. 用独立PCAP记录头扫描、CSV逻辑记录边界扫描构造每个原始单元的 `(source_slot, ordinal, record_sha256)`，绑定完整文件SHA及固定arrival sequence。CSV表头须准入，但明确不是工艺数据观测；PCAP全局头由完整文件SHA绑定，不伪造为观测。
2. 经当次完整来源核验产生的私有能力打开只读、当前字节及节点认证的reader。最终 `analysis.replay.available_record_refs` 必须与上述全部单元集合完全相等，不以accepted总数替代。
3. 读取真实路径 `metrics.json / event_latency / samples`。当前固定生成器每帧一个协议事件、每CSV数据行一个工艺事件，因此要求每个数据原件一一对应、event_id唯一；额外、缺失、重复或SHA错误均拒绝。非本固定fixture不套用此一对一前提。
4. 按历史顺序访问snapshot元数据与完整 `events` 数组的已认证共享节点，按array子树digest去重，避免逐快照展开大数组。只提取目标事件的event_id/source_ref和首次实际出现的snapshot时间/arrival_seq。每个原件的事件必须在真实历史中出现，事件source_ref须与原件匹配；首次出现时间须等于latency记录，且不得早于独立arrival sequence。不能只把metrics或source重建自身当独立答案。
5. 审计只调用节点认证读取，不绕过节点校验或直接相信SQLite行；不展开大snapshot/analysis/graph。完整历史其他字段仍由全部root的source重建比对，原首/中/末实际reader抽样保留。

审计ledger保守记账上限128MiB，访问去重节点最多8,000,000，深度最多64；超限明确失败，不截断后判通过。临时解码单个小记录不超过8MiB，扫描以有限批次记录进度，整个审计受同一绝对deadline约束。报告审计墙钟/CPU、ledger峰值、访问节点数、原件/准入/历史观测数量、缺失和多余数量；原生RSS与kernel cgroup峰值仍分别记录。完成后再次核当前库存及能力绑定，发现字节变化拒绝。

## 通过条件

离线L保持原始观察数量门槛。回放L始终要求操作N、独立候选几何界、全部原件准入、每个数据原件真实历史观测覆盖、首次时间及前缀一致、完整来源重建和原交互查询门槛。无过期仍要求原末态N一致；有过期时末态live+frozen量独列，不伪称全部原始观察都仍在末态。任一完整覆盖条件无法实现、超时、超内存或缺证，都明确未通过/验证缺口，不放宽为accepted计数通过。

新增独立expiry小例须原引擎/新引擎全部业务和历史路径逐字段一致（只有既登记容器身份双射允许差异）；负例至少覆盖漏准入、漏历史观测、错误原件SHA、未来引用、latency时间错、重复event/source身份及ledger上限。S/M原记录不重新解释。
