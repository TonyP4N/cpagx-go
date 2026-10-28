# DAG6 外层清单逻辑范围契约修复

本修复晚于六格冻结运行 `56e106b2a44d88a0c67280d5d9e6a1e13aa79a75`。该运行和镜像不包含本修复，不改其来源身份、不替换实跑结果、不重新解释失败。本记录仅证明外层清单的有限数值校验；不代表大历史实际导出、核验、查询或容量通过。

## 首次实际失败与独立预期

只读复核发现：`shared-storage-budget-2` 的底层writer/reader与声明允许4PiB，但 `CompactStoreRunManifest.logical_artifacts[].logical_bytes` 仍固定512GiB。发布器在shared_export.py的export_task中seal后校验此schema，读取/核验入口_bound也先校验，故大逻辑根不能穿过外清单。

手写完整外层manifest（五个逻辑根，其中history/snapshots逻辑范围549755813889字节）在旧runtime实际执行validate，得到 `ContractError: CompactStoreRunManifest.logical_artifacts[3].logical_bytes: above maximum`。这里没有生成/展开549755813889字节内容。手定独立边界为budget1最高549755813888、budget2最高4503599627370496；并要求两者物理1GiB、页8MiB/100项不变。旧schema/contracts源码、完整输入、摘要和首次失败均已留存。

首次专属测试9项，修前11个失败断言和3个错误：除外清单拒绝合法budget2范围外，还确认runtime原本忽略allOf/if/then/else，不能只修改标准JSON Schema而以独立jsonschema通过冒充runtime修复。最初只读探针另有一次漏配PYTHONPATH的ModuleNotFoundError，已在receipt列为调用配置错误，不作项目容量失败。

受控原始输出：FYP工作区 `outputs/cpag-r19-manifest-extent-contract-attempt1`。公开原始SHA、路径脱敏日志、完整手写外清单及修前/修后摘要见 [validation-round19-outer-extent-contract](validation-round19-outer-extent-contract/)。未修改任何六格私有运行目录。

## 有限修复

只修改外层schema与contracts条件子集：

- `logical_artifacts[].logical_bytes` 总上界为4PiB；allOf中的if/then/else仅在明确budget2时允许对应声明。budget1与其它分支仍限制512GiB，版本/声明范围不匹配拒绝；原全局required/enum继续拒绝缺版本及未知版本。
- stdlib runtime增加allOf及if/then/else执行：只将ContractError视为条件不匹配，文件/引用错误不吞掉。其它原有验证规则与未使用条件的schema行为不改。修前检查既有schemas未使用这四个关键字。
- 新专属测试覆盖完整manifest两个精确上界、各上界+1、budget2跨旧界、版本/范围混配、缺失/未知版本；与独立Draft202012Validator交叉校验。另测条件匹配/不匹配/缺失、缺then或else、分支拒绝、allOf逐分支和校验会话内嵌套修改失效。

没有改变物理存储、节点编码、业务规则、输入密度、时序、ID、配置选择、页或资源预算；除contracts运行时条件校验外，没有改发布器/读取器/Go/Worker/备份或其他计算模块。大逻辑extent仍是计数护栏，不授予巨大JSON展开权限。

## 回归结果

|范围|实际结果|
|全部contracts（含10项新专项）|17项PASS，0.356秒|
|原DAG/压缩/compact物理存储|21项PASS，5.301秒|
|DAG6实际小例发布、源核验、查询、恢复、篡改拒绝|6项PASS，0.739秒|
|source sink与物理writer完整根对照|5项PASS，0.703秒|
|原/新逻辑预算与巨大共享extent底层读取拒绝|3项PASS，2.289秒|

这些是无Docker的小单元/组件检查。当前修复须独立提交、冻结并执行受影响复验；56版本矩阵结果保持原样。尤其不能把schema边界PASS写成4PiB历史整链已测、S/M/L通过、参考环境通过或正式产品接入完成。

## 同次只读接口复核的剩余项

1. CLI page只消费数组子路径；Python reader.get可以读取对象/标量子路径，CLI目前没有通用get/path动作。graph和snapshot整对象超过8MiB会拒绝。需要补CLI/正式服务通用路径消费和流式下载，不能声称现CLI已逐字段暴露所有逻辑根。
2. 底层open_reader仅保证库存、物理节点与外声明绑定；无许可的metadata_task/query_task和CLI读动作会额外做完整来源verify。直接调用open_reader不能当作source approval。集成方必须明确这两层。
3. run_manifest.tool_versions是生产者声明；现source比对重建业务根与终态，未独立认证历史Python生产环境。冻结代码/镜像receipt是本轮运行来源依据，不能仅凭可重写的tool_versions证明来源。
4. 正式Go任务/Worker分派、服务授权与attempt有效性、受控持久核验凭据、DAG6评估统计/适配、成套备份恢复及UI/API分页仍是软件工作。完整增量关联也尚未实现；新前缀仍重算。它们不能以缺真实工业材料解释或标为完成。
