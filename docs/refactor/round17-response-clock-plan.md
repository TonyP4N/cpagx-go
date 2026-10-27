# R17 响应时间补修预登记

基线 `288ffc068c0196d0725478c3404bdca0a2aaf26e`，分支 `refactor/m1-evidence-core`，开始核对无后续修改且工作区干净。只修本轮时间质量与版本兼容，不进入R18。冻结RC1和默认入口不变。

先原样运行用户 `outputs/cpag-r17-review-20261027/reproduce_response_clock.py`：单文件及双文件的响应过期均产生1个supported_candidate，违反预期0；正常与请求过期对照符合预期。预期、失败结果及一份完整历史导出分别保存在 `validation-round17-response/` 与 `tests/fixtures/r17-response-clock-v1/`，不得改答案或重写旧导出。

## 预期（实现前）

每项独立构造固定请求10秒/响应11秒、CSV0→1；均测试单文件和跨文件。

| 条件 | 操作时间质量与候选/图预期 |
|---|---|
| 正常完整依据 | 请求/响应有效，1 supported_candidate和1图连线；只属假设 |
| 有效期从10.5秒开始：请求单独失效 | 保留2网络及全部工艺观测，传播request clock_validity_outside，0候选/连线 |
| 有效期截止10.5秒：响应单独失效 | 保留成功响应协议事实，传播response clock_validity_outside，操作unknown，0候选/连线 |
| 有效期闭边界恰好请求10/响应11 | 原始时刻在闭区间内，合法正常候选；刚越界明确unknown并0候选 |
| 网络basis、drift_basis、precision_basis缺失 | CLI核心保留观测及具体缺失原因，不生成候选；正式入口材料门禁仍拒绝不完整配置 |
| 请求/响应可能时间区间相交或接触 | 不可确定严格先后，明确response_order_uncertain，0候选/连线；不篡改协议状态 |
| 响应确定早于请求 | response_precedes_request，0候选/连线 |
| 无响应 | 保留原既定缺响应事实与未知语义，不推断响应成功；不将本修复扩大为协议支持变更 |

## 版本和验收

新R17执行发布 `bounded-dual-source-2`，原 `bounded-dual-source-1` 仅按固定历史版本语义读取/验证，显示已知响应时间限制并建议显式重分析，不改文件及历史结果。旧 synthetic-dual-source-1 不变。未知版本拒绝；manifest/analysis版本不一致拒绝；新执行不能借历史版本绕过修正。

在真实PG、正常Go入口及隔离Worker验证响应过期：0候选/图边，未知原因可查，操作查询2条网络原证据、变化查询2条工艺原记录，总计4条。CLI相同版本输出一致；终态备份空库/新目录恢复后结果与证据仍一致。普通点击页面断言未知原因、无候选和证据，而非只检查page_errors。

正常例三次规范化哈希及CLI/Worker一致性继续通过；版本字段变化造成的跨版本分析哈希差异须明示，不能删字段伪造一致。R16顺序预检、门禁、备份恢复回归保持。新增回归接入完整CI，最终SHA全部成功后提交补验收结论，等待用户复核。真实材料与R18—R22软件剩余项分别保留。
