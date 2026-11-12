# DAG6 完整来源核验策略：typed-Merkle source sink

策略名称为 `dag6-full-source-merkle-sink-1`，只用于新核心DAG6完整来源核验。旧格式读取器和artifact bytes不变；原完整SQLite重导出核验策略 `source-sqlite-reexport-1` 保留为独立对照。新增策略不是批准缓存，也不是直接接受产物给出的根。

## 计算和接口

`cpag_core.source_merkle_sink.TypedMerkleSourceSink(context=None, version=STRATEGY_VERSION, **writer_options(...))` 实现现writer的intern/add/compose/sequence/alias/descriptor接口。它接收完整来源执行生成的值，复用相同typed hash、类型、顺序、extent/height与数组分块；compose/sequence只能引用本sink已经独立计算的节点。传入原artifact根或猜测摘要不能绕过来源重算。

共享 `_build_business_roots` 仍执行全部原件解析、ReplayCore业务、每个到达步骤、全部snapshot/revision、完整analysis与graph/events、全部deterministic metrics和索引。新策略只取消第二份SQLite的物理编码、插入和文件写出。原artifact仍必须完整核验库存、profile/schema、全部物理文件/原件SHA、全部节点与根，并在来源重建后再次确认字节与清单未变；清单classification/终态字段的独立绑定修复由主任务负责。

返回descriptor与物理writer同shape：digest/logical_bytes/items/kind，named root另有name。`report()`返回策略名、exact unique node/root count、roots-index SHA、索引/flat cache内存计数、原limits与 `physical_artifacts_created=0`。`seal()`只提供source根审计报告，绝不是物理发布manifest或source approval。`close()`释放索引与缓存。HMAC批准仍只能由完整核验流程成功后签发，sink本身不签发批准。

## 预算及失败

node/depth/array/dict/node-byte/logical-root/named-root预算与原DAG6保持。完整唯一节点索引使用32-byte SHA→14-byte packed extent/type/height，受max_nodes（当前最高8M）和额外内部2GiB索引上限约束。2GiB是该精确审计索引的拒绝阈值，不是新增容器内存配额；flat complete-value cache仍16MiB，进程整体仍在原8GiB配额内。索引报告只统计自身Python对象拥有字节，不冒充进程RSS/cgroup峰值。

原物理产物总额仍1GiB、单次查询仍8MiB/100项、完整链路仍1800秒。由于新sink不创建物理产物，原库存的物理限额由外层完整库存校验判定，不能用“未写第二份DB”绕过原库大小限制。node、extent、内存、deadline等失败不seal、不批准；cgroup/OOM与全链路失败也必须保留。

## 独立测试与边界

首轮5项独立测试PASS，0.703秒，原/public日志SHA与模块SHA记录在 `validation-round19-source-merkle-sink/`：

1. 手写确定性完整值（类型、signed zero、顺序、未知、claims/反证、多个历史状态、完整metrics及固定runtime样本）：每个descriptor、exact unique node count及roots-index SHA与真实SQLite writer完全一致。
2. 相同共享来源流程的offline/replay小例，在禁止sqlite3.connect时仍完成全部根/summary；完整analysis/graph、metrics及全部history roots一致。唯一不作确定性重现比较的是实际 `runtime_metrics.json` 墙钟样本；原样本仍在原artifact字节/全部节点认证内，不能将新运行时刻伪称原测量。
3. 未计算的原root/猜测ref拒绝，反证字节变化得到不同完整根。
4. node/root/depth/item/node-byte/logical/deadline/内部索引内存阈值失败不能seal；未知策略版本拒绝。
5. 两种完整策略都拒绝重算全部外层SHA的自洽伪造analysis，并拒签read approval。

这些测试证明小例格式/来源流程等价与拒绝行为；不证明S/M/L时间或物理空间已通过。旧S replay dev3 export1166秒及其未完成/超时验证必须保留。新策略仍可能受完整业务判断、graph投影、typed哈希或原库读取成本限制；冷读取不再写第二份DB，但仍重算全部来源判断。性能结论以新固定镜像、相同配额的完整矩阵测量为准，不能把其他同步软件变更的收益全部归因于此sink。
