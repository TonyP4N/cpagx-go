# R17 响应时钟补验：服务版本预登记

基线 288ffc0。先固定答案，再实施版本兼容；不改旧分析、旧 manifest、旧哈希或任务状态，不增加协议/关联算法。

1. 新 bounded 分析必须发布 `bounded-dual-source-2`。首次发布 v1 拒绝；已经完成的 v1 幂等完成与历史读取仍能核对既有哈希。
2. 已保留的 bounded v1、v2 只有 core run manifest 绑定的产物哈希有效、dual manifest 与 analysis 版本完全一致且原件、配置、产物、结果哈希均有效时才允许读取。未知版本及混合版本必须拒绝。
3. 旧 synthetic scalar 使用 `synthetic-dual-source-1`，不因补验改变其既有身份与只读行为。
4. 历史 bounded v1 的结果、图和证据响应提供独立 compatibility 元数据：analysis_version=bounded-dual-source-1、status=historical_semantics、known_limitations 包含 response_clock_quality_not_enforced、reanalysis_required=true；不改写 retained normalized data 或把旧结果当新语义重新通过。
5. bounded v2 采用根任务修复后的响应时钟语义。Go 只核验版本及证据一致性，Python 历史重算必须显式按已保留版本分派，未知版本不得回退。

验证包含：旧 scalar、实际生成 v2、按显式历史 verifier 生成/保留 v1、未知和混合版本拒绝、历史响应提示、首次发布 v1 拒绝及历史已完成幂等允许。最终真实数据库/隔离 Worker 与页面补验由主任务留证。
