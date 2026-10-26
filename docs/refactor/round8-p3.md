# P3 独立评估契约与泄漏防护验收

范围：仅合成软件计算与分析输入隔离；不新增检测/关联算法，不修改旧默认分析入口，不宣称真实工业效果。

## 交付与使用

新增四份严格 JSON Schema：EvaluationAnnotations、EvaluationPredictions、EvaluationSplit、EvaluationRegistration。评估输出复用既有 EvaluationRecord；原10份契约不变。新对象由本地 Python 评估工具使用，并通过 Go/Python 合同验证；尚不作为 Go API 接收对象，不声称新增服务接口已验收。

```sh
PYTHONPATH=services/analysis/src python -m cpag_core.evaluation \
  --predictions fixtures/evaluation/predictions.json \
  --annotations fixtures/evaluation/annotations.json \
  --split fixtures/evaluation/split.json \
  --registration fixtures/evaluation/registration.json
```

CLI 向标准输出写 JSON，不写预测、原始文件或标注。合同/来源/划分不一致返回2。每侧最多500个合成事件，超限拒绝；大规模研究评估不是本轮支持范围。

数据目录分 raw、profiles、annotations。`python -m cpag_core.evaluation_analysis --root DATA --network raw/network.jsonl --process raw/process.csv --profile profiles/profile.json --output NEW_OUTPUT` 仅接受 raw 和 profiles，拒绝 annotations 路径、越界、符号链接、硬链接、已存在输出、标注列/字段和未知配置键。只将允许的两份数据及内存配置传入纯核心。此为可信本地工具的输入约束，不是阻止恶意用户重命名/伪造数据的 OS 沙箱；不会据此宣称所有旧入口都具有相同隔离保障。

P1 的 `input_fingerprint` 按文件角色、内容哈希和大小形成；单 network/process 时与核心相同。P1 `intake_config_fingerprint` 标识接收声明，P3 `config_fingerprint` 标识实际分析 profile；两者不可混用。注册还绑定 split 摘要，预测必须匹配输入与分析配置指纹。

## 验收

| 条件 | 结果与证据 |
|---|---|
| 标注隔离 | 修改 annotations 后同一分析输出和指纹保持一致；传入标注路径、越界/链接、标注字段拒绝。`test_isolation.py` |
| 划分防泄漏 | 连续块重叠、跨块重复样本哈希、隔离小于最大规则窗口、未声明窗口拒绝；事件绑定所在保留块的样本哈希。`test_evaluation.py` |
| 预登记 | 登记时间必须早于解封声明；修改划分或预测配置/输入指纹拒绝。时间与独立来源是受审核的声明，不是密码学保管证明 |
| 手算指标 | 合成例 TP=1、FP=1、FN=1，precision=recall=0.5；单独正常时段1小时，误报/小时=1。缺分母及空集合输出null，匹配一对一且有边界容差测试 |
| 正常时段一致性 | 审查发现初版夹具将阳性标签放在normal区间；实现改为明确拒绝，夹具分离正常区间。避免将攻击时段计入正常分母；负例已回归 |
| 未标注与争议 | 争议时段预测及标签从指标中排除，正常时长扣除重叠争议；未标注关联单列数量，无路径gold输出path_accuracy=null |
| 真实状态 | 任一输入声明非合成时，正式指标均null、status=not_evaluated；不会将软件手算成绩作为真实评估结果 |
| 严格契约 | runtime与独立jsonschema验证；未知字段拒绝。已有EvaluationRecord复用 |

`validation-round8/evaluation-tests.log` 是实际测试记录；`evaluation-result.json` 为CLI实际输出。

## 旧评估审计

`tests/evaluation_final.py:390` 的 derive_gold_units 接收 cpag_units 并选取其中单元作为 gold。`scripts/validation/round8_evaluation_audit.py` 只提取该函数，以同一空攻击说明测试：无预测时gold为空；加入一个合成预测后gold随之增加。实际结果在 `legacy-evaluation-audit.json`。因此该函数输出不能作为本轮独立参考。保留旧文件作为历史实现，不重写旧算法。

该函数复现不等于所有旧评估脚本都存在同一缺陷。其他 evaluation_* 脚本未获独立来源认证，本轮工具不调用它们；将来要用其结果，必须先审查来源、划分和标注独立性。

## 剩余条件

事件类型/资产/批次及样本归属仍需真实来源核查；输入隔离不能识别任意伪装标签或证明人从未看过保留集。正式验收还需授权原始样本、独立标签/争议审阅、可信正常时段、划分及解封审计、预先约定指标目标。本轮不提供边/路径效果评分，不解除 M5/R08 的真实数据阻塞。
