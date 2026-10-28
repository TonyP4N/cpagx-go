# R19 dev4 已完成记录的成本归因（partial）

范围仅为开发环境中的核心导出、完整来源核验及读取，读取既有S offline、S replay和M offline attempt1记录；未重跑程序、未改原始矩阵目录。固定镜像为`eb80e205…615f8c`，限额4 CPU、8 GiB内存、4 GiB临时空间、完整输出1 GiB、全链1800秒、查询10秒/8 MiB/100项。单次结果不等于完整矩阵、参考环境或真实工业数据验收；本轮瓶颈仍未全解。

## 三组结果与时钟

下表单位为秒；查询列是首个原件页的新进程冷读/同进程新reader重复调用。OS/解码缓存状态未验证，不能把“冷”解释为已清空系统文件缓存。

| dev4记录 | 导出 controller / native | 核验 controller / native | controller全链 | 冷读 / 重复 | 结果 |
| --- | ---: | ---: | ---: | ---: | --- |
| S offline | 15.885 / 15.304 | 13.749 / 12.498 | 36.739 | 1.134 / 0.858 | 通过本格 |
| S replay | 1103.273 / 1101.302 | 697.420 / 696.578 | 1801.151 | null / null | 核验deadline失败 |
| M offline | 300.758 / 299.762 | 239.924 / 239.725 | 551.103 | 1.548 / 1.258 | 通过本格 |

controller包含容器生命周期与控制器收件等范围；native从模块首段、依赖导入和参数处理前开始，包含core导入、原件哈希及私有IPC读取，排除解释器执行首段代码前启动；最终协议序列化/退出另有边界。二者不能混作函数耗时，差值也没有被独立归因为I/O。query整包还包含metadata、后续原件分页及独立原件比对，不等于上述单个API调用时间。交接后新进程查询另列于结构化表。

S replay失败阶段的controller report没有内嵌完整result，但独立`verify-result.json`仍有native耗时696.578秒、CPU **695.754秒**、RSS与cgroup信息，应补入而不能记作未测。该核验消耗的是导出后剩余全链预算，并非再获1800秒；来源重建未完成、未进入query，查询和最终审计索引值为null。

## 能够归因的阶段与不能相加的范围

所有下列数值都是嵌套调用累计值，**不是互斥分解，不得相加或用于堆叠占比**。

- S offline导出：`association_and_evidence` 3.747秒，`compact_store_write` 7.367秒，`standard_projection` 2.058秒，节点验证2.934秒；核验的完整来源重建9.192秒，节点验证2.981秒。
- M offline导出：相应合并关联段54.518秒、存储131.705秒、投影89.750秒、节点验证40.227秒；核验来源重建198.305秒、节点验证40.735秒。native核验CPU为239.080秒，接近239.725秒墙钟，取消副库没有取消完整业务/根重算。
- S replay导出：合并关联段258.225秒/305次，history generation 738.117秒/310次，其内外重叠的存储累计635.604秒、投影193.684秒，节点验证35.634秒。原件前缀snapshot累计9.275秒；网络/CSV解析累计1.561/0.0068秒。在本记录中，不能把当前成本主要归给原始解析。
- S replay失败核验：来源重建660.880秒（returned=0、failed=1），其中历史生成379.137秒、合并关联段238.030秒、typed根调用296.643秒相互嵌套；原库节点验证35.097秒。native CPU接近墙钟，显示仍有大量CPU重算，不能把无第二份SQLite等同于瓶颈已解决。

`association_and_evidence`覆盖共享关联/判断与证据处理函数，是**合并阶段**。判断本体、证据组织、schema处理等尚无独立计时；结构表中“仅证据组织”和“仅规则判断”均为null，不能把整个合并段称为纯算法成本或纯证据成本。

## 内存与空间

native进程CPU（导出/核验）分别为S offline 14.839/12.462秒、S replay 953.224/695.754秒、M offline 279.987/239.080秒。cgroup CPU包含整个容器及采样exec，不能与native进程CPU混用。记录中`nr_throttled=0`，不能据此推断参考环境已达标，也不能保证4个核被程序有效并行使用。

RSS是进程累计高水，不是某阶段新增分配；cgroup peak覆盖容器整体计费内存和采样进程等，采样/共享页计费范围亦不同，数值不能相减作为“缓存占用”。导出/核验的RSS为S offline 54902784/62976000字节、S replay 109735936/155934720字节、M offline 293548032/383442944字节；相应cgroup peak为59367424/62357504、192516096/241197056、412606464/485130240字节。失败核验的峰值仍是截至失败的实测，不是完成核验峰值。

M旧平铺 **1795907870字节（约1.80 GB）只是独立数学下界**，不是实际完成的旧平铺产物。新M完整artifact由6个实体文件实际合计 **100668118字节**，其中SQLite100397056字节；两种性质不同，不能标成两次实测压缩率。S offline/S replay产物分别为7611037/85817016字节；S replay这里只证明producer写出了产物，不能代替完整来源核验通过。成功offline核验报告均为`physical_artifacts_created=0`，但仍读取原库并重新执行完整来源计算；失败replay只留下in_progress报告，不能补造其最终索引峰值。没有从这些数值外推L。

## dev3同模式历史对照的边界

dev3 S offline attempt2的controller导出/核验为16.232/15.900秒，dev4为15.885/13.749秒；dev3 S replay导出1166.037秒、dev4为1103.273秒，两次replay全链都失败。dev3核验使用SQLite完整重导出，dev4使用typed-Merkle source sink，且镜像/存储投影实现和完整性约束有同步变化，不能将整体差异全部归于某一个优化。dev3旧核验器的已知清单绑定缺口也不能忽略，其记录仅作历史资源对照。

尤其dev3 S replay `standard_projection` 为148.334秒，dev4为193.684秒：dev4 `event_graph`的identity callback已在该计时段内执行sink/writer的intern/compose，另有外层`stored_graph_composition_1` 211.476秒，二者重叠。**148→193不是等定义的纯算法计时，不能据此称算法变慢。** 同名compact_store_write调用数也由2178变4044，操作拆分不同，不能直接比较每次调用性能。

完整数值、来源SHA、缺测原因和dev3同模式原始摘录见[JSON](validation-round19-dev4-cost-attribution/cost-attribution.json)、[控制器/native表](validation-round19-dev4-cost-attribution/stage-costs.csv)、[嵌套阶段表](validation-round19-dev4-cost-attribution/nested-phase-costs.csv)。缺测为null；所有派生文件独立保存，原始报告和adapter公共矩阵未修改。
