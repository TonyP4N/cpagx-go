# R19 独立评估操作与边界（实施中）

本轮未关闭。参考环境容量验收按用户回复保留待办；真实材料另列。以下 CLI 不改变默认入口或 RC1。

## 统计与隔离

`cpag_core.evaluation_artifacts`只适配已校验的最终产物；现有验证器允许重新计算作完整性检查，但预测选择只读保留的产物，不接收标注。网络操作与工艺变化分开统计；候选为未标注关系，非攻击预测。回放终态只计稳定ID一次，首次出现与撤回另列。

`cpag_core.single_source_export`是真正单源CLI：network只读取抓包，process只读取CSV，复用原R17解析/判断。缺失另一源明确标注，不能把缺源当成完整双源成功。`evaluation_artifacts --projection network/process`对双源产物仅是投影视图，不等于重新做单源实验。

现有详细评估器上限仍为每侧500事件；大于上限明确拒绝。容量升级尚未完成，不能把适配器保留全部事件理解成评估已支持10000条。

## CLI

仓库根目录设置 `PYTHONPATH=services/analysis/src`，使用 `.venv/bin/python`。所有输出目录必须不存在。

```sh
PYTHONPATH=services/analysis/src .venv/bin/python -m cpag_core.single_source_export \
  --source-mode network --source examples/round18-replay/network.pcap \
  --source examples/round18-replay/response.pcap \
  --profile examples/round19-evaluation/profile.json --output /tmp/cpag-network-only

PYTHONPATH=services/analysis/src .venv/bin/python -m cpag_core.single_source_export \
  --source-mode process --source examples/round18-replay/process.csv \
  --profile examples/round19-evaluation/profile.json --output /tmp/cpag-process-only
```

适配命令：`python -m cpag_core.evaluation_artifacts --artifact ARTIFACT --projection network|process|dual --batch BATCH --sample-sha256 REGISTERED_DIGEST`。来源、划分与参考答案须由独立材料决定；不得从适配结果生成gold。

评估分两步：

```sh
python -m cpag_core.evaluation_bundle freeze --artifact ARTIFACT \
  --split SPLIT.json --registration REGISTRATION.json --batch BATCH \
  --sample-sha256 REGISTERED_DIGEST --projection dual --output FROZEN
python -m cpag_core.evaluation_bundle evaluate --frozen FROZEN --artifact ARTIFACT \
  --annotations ANNOTATIONS.json --references REFERENCES.json --output EVALUATION
python -m cpag_core.evaluation_bundle verify --bundle EVALUATION --artifact ARTIFACT
python -m cpag_core.evaluation_bundle query --bundle EVALUATION --artifact ARTIFACT --id PREDICTION_ID
python -m cpag_core.evaluation_bundle query --bundle EVALUATION --artifact ARTIFACT --id GOLD_ID --reference
```

`freeze`必须在声明的解封时间之前实际完成，`evaluate`等待该时间；两次系统观察时间都保留。冻结绑定完整适配结果、运行/attempt、分析/回放/规则/配置/匹配版本和划分，冻结后变更拒绝。它是本机文件工具，不能证明可信时间、保管链或审核独立性。

每个gold要求`references`索引，字段`source_ref`、`record`、`sha256`。漏检查询返回独立参考定位；尚不自动获取外部参考文件，其原件校验状态明确为声明而非已验证。预测查询复用现有原始帧/CSV证据校验。

## 服务和备份

新增服务端评估输入、评估导入/查询的路由和实际验收结果以本轮报告及OpenAPI为准。评估标注保存在控制侧数据库，不加入分析任务payload或计算容器输入。目录复制测试不等同数据库恢复。

新备份格式5包含`v3_evaluations`，当前源数据库须先完成迁移010；格式4历史包继续按原表集合恢复验证，不伪造旧包的评估数据。新表保存精确JSON文本和SHA，同时保存JSONB投影；读取/恢复检查两者一致及原分析产物。热备份和任意生产数据库仍不支持。
