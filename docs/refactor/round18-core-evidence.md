# R18 增量核心验收证据

基线为 `25b2f1c8985fe7b68323cfea224e785c124679f2`，实施前预登记为 `cc2db77` 的 [round18-plan-scenarios.md](round18-plan-scenarios.md)。本记录只验增量解析与核心规则机制；不替代正式 PG/隔离 Worker、实际节奏、页面、恢复和最终 CI 验收，更不代表真实工业数据适用性。

核心调用只接收 `ReplayInputs.snapshot()` 中已经到达的记录，通过共享 `_analyze_prepared` 执行 R17 v2 时间、映射及规则判断。未修改旧 `ReplayWindow`。新模式引用为 `source_slot + record_sha256 + 原帧/CSV物理逻辑记录号 + column/raw_time`，不把记录哈希冒充完整文件哈希。完整文件身份仅由外层原件完整性绑定保存。

## 预登记答案与实际核对

以下方法均在 `tests/replay/test_replay_core.py`；原始字节读取与生产适配器的独立测试另见 `tests/replay_inputs/test_arrived_inputs.py`。

| 预登记项 | 固定预期与实际结果 | 独立测试方法 |
| --- | --- | --- |
| P01 | 请求已到时只有 1 个网络事件、`pending_response`，没有变化、候选或未来响应引用；通过。 | `test_pending_then_response_wait_then_change_preserves_historical_versions` |
| P02 | 固定前四次到达，修改响应后缀、追加 CSV、改变合法未来到达序列/结束时刻及 1x/10x 配置，当前快照、全部已存快照、修订字节相同；通过。 | `test_future_bytes_and_future_schedule_and_speed_do_not_change_prefix`；适配器 Guard 拒绝任何后缀读取，并以旧全量解析触发 Guard 作为负对照。 |
| P03 | 正常请求10/响应11/变化12形成 1 个 `supported_candidate`，仍是 hypothetical；终态按具名身份适配与 offline 的每一个业务字段相同；通过。 | `test_terminal_offline_equivalence_preserves_every_business_field` |
| P04 | 响应11已到但变化未到时为 `wait_process`；变化12到达后为 normal，修订连到可查询旧、新快照，旧对象不变；通过。 | pending/wait/change 测试与 old/new snapshot number、ID、fingerprint 交叉断言。 |
| P05 | 无响应、协议错误、无变化、缺测、孤立变化均不能成为物理效果结论或 supported 因果关系；通过。无响应到关闭后明确 missing，错误保留 error，完整覆盖的无变化只报告未观察到预期变化。 | `test_no_response_error_no_change_missing_and_orphan_outcomes_are_not_effect_claims`；`test_eof_does_not_satisfy_response_or_process_and_unknown_time_uses_arrival_timeout` |
| P06 | 开放窗口内，原时间12的变化在13到达，记录 late、产生带 available_at=13 的修订，旧等待快照保留；通过。 | `test_allowed_late_revision_and_closed_too_late_freeze` |
| P07 | 即使没有显式 advance，19秒到达前也先关闭期限17的旧窗口；19到达的旧变化只记 too_late，不能补造候选。17的等号仍可接收。关闭修订不引用当前到达的新原件；通过。 | `test_arrival_clock_automatically_closes_before_late_record_without_explicit_advance`；过早 finish 明确 incomplete。 |
| P08 | 重复同一记录不增加事件或语义修订；错误的声明哈希仅为 unverified reference rejection，不伪称第二份原件。真实 TCP 重叠冲突有两份可 resolve 的原记录，并撤回当前请求/候选，历史版本保留；通过。 | `test_duplicate_and_unverified_reference_claim_do_not_rewrite_facts`；`test_accepted_tcp_conflict_retracts_previous_current_operation_not_its_history`；真实同时间不同 CSV 值由适配器保留两侧证据。 |
| P09 | 请求/响应分别过期、缺依据、时间区间重叠/接触，均继承 R17 具体原因，保持成功响应协议事实而禁止相应候选。映射多义保持 unknown；通过。R17 更完整的精确闭边界、drift、precision 和历史版本回归仍保留。 | `test_r17_clock_validity_basis_precision_order_and_mapping_ambiguity_are_shared`，以及原 R17 时间测试。 |
| P10 | 跨文件乱序分段未到齐前没有完整 PDU；补齐后只出现一个请求，重传不改事件 ID，只补原帧；缺口 EOF 明确 unsupported；FIN 半关闭保留合法配对，RST 禁止跨边界配对；通过。 | `test_cross_file_segments_retransmission_emit_no_pdu_before_arrived_bytes`；`test_gap_finalization_is_explicit_unsupported_without_inventing_request`；`test_fin_half_close_preserves_matching_but_reset_prevents_cross_boundary_pair`。其他解析器缓存/连接硬限由原测试和适配器测试覆盖，不声称容量验收。 |
| P11 | 缺测与零分开、重复时间不选一个值；被 admission filter 去掉的真实 CSV 记录不能压缩序号后暗中连接前后值，也不能伪造完整负观察；通过。 | `test_filtered_csv_ordinal_gap_cannot_invent_adjacent_transition_or_negative_coverage`；缺测/映射测试；适配器多行、BOM、CRLF、重复值测试。 |
| P12 | buffer-record、snapshot、revision、output 先触限即 `ReplayIncomplete`。无关旧缓存可过期并继续接收；仍开放操作或未完成 TCP 必需上下文若到缓冲时限，明确 `buffer_time_limit`，不能静默忘记。冻结候选的 network/process 依赖在100秒终结时仍完整；通过。 | `test_incomplete_limits_and_active_buffer_expiry`；`test_expiring_open_operation_context_is_incomplete_not_silently_forgotten`；`test_closed_final_graph_dependencies_survive_buffer_expiry` |
| P13 | 相同原始到达序列与参数三次执行，snapshot/history/final/semantic-metrics 四种规范化哈希均相同。墙钟样本独立，不进入这些哈希；通过。 | `test_deterministic_three_runs_metrics_complete_and_runtime_separate` |
| P14 | 核心层验证 transport 参数不进入语义身份。外层在最终 metrics 字段后补充实际 pacing：1x runtime 10.0645秒，10x 1.1108秒；analysis/events/graph/snapshots/revisions/metrics 六类哈希两次完全相同，保留全部墙钟样本。只是小型机制样本；通过，不代表吞吐验收。 | prefix/metrics/backlog 测试；外层实际记录 [pacing-metrics-final-samples.json](validation-round18-core/pacing-metrics-final-samples.json)。核心单元测试本身不冒充节奏实测。 |

## 时间、修订和指标口径

每次到达先用旧的 admitted prefix 处理已超过期限的关闭与缓存过期，再考虑新记录。由此产生的 `clock_before_arrival` 修订只含 clock trigger，没有当前新记录引用。关闭采用校正请求区间上界+关联窗口+允许迟到，严格超过才关闭；未知时间采用首次可见到达超时并保留 `arrival_timeout_unknown`。EOF 不是效果证据。finish 仍有开放窗口时明确失败，不发布 finished。

snapshot/revision 含 synthetic、版本、available_at、semantic config fingerprint、旧新 snapshot number/ID/state fingerprint 及 trigger/refs。snapshot ID 对核心 snapshot 全字段求哈希；导出器附加的 graph/events 是可重建投影，不属于该 ID 输入。state fingerprint 覆盖完整 analysis。sequence、finish_at、speed、realtime/realtime_pacing 只由外层完整配置绑定，不进入当前语义身份。

事件延迟的分母是曾经至少可见一次的唯一 network/process event ID（包括以后被撤回的事实版本），未知时间另列不可计算数；延迟为模拟到达减校正区间，单位秒。候选确认延迟是软件候选首次可发表时刻减请求区间，样本保留 candidate_state，不表示因果确认。backlog 分别列 `unparsed_records`、`prerequisite_waiting_operations`、`open_window_operations`；`waiting_operations` 明确为前置等待的兼容别名。已发表但仍 provisional 的正常操作仍计入 open window。每条到达尝试另留分类，control 和 record 分开，late 可与 accepted/too_late 重叠计数；实际 wall monotonic 样本单列。当前 `counts.conflict` 指记录身份或未验证 digest 声明冲突，不冒充所有 TCP/工艺语义冲突总数；后者的两侧原件与撤回理由保存在质量报告和历史版本。

## offline 对照的身份转换与合法差异

`offline_identity_projection` 是仅用于该终态测试的具名适配器：按最终完整性绑定，把回放 slot/record hash 位置转换为 offline 原文件哈希位置；CSV header 是回放逻辑记录1，故数据记录号转换为 offline 行号时减1；然后重建 network/process/correlation/derived/candidate 的模式特定身份，声明转换 input/config fingerprint。请求/响应状态、原始 ticks、校正区间、数值、单位、映射、规则版本/参数、支持、反证、未知原因等所有 offline 业务字段继续逐字节比较，不移除难以匹配的业务字段。R18 额外 TCP-PDU 起始序号在独立夹具中断言为100，生命周期断言关闭且非 provisional，pending-parser 断言为空，再进行旧模式字段对照。

对照只用于全部输入已到、没有迟到丢弃、截断、冲突且时间规则等价的正常例。合法差异包括：开放回放没有响应时抑制候选并显示 pending，而历史 offline 可以保留缺响应 hypothetical；尚未到齐的帧/工艺没有对应事实；late policy、关闭冻结、buffer expiration、回放证据身份、版本及生命周期会造成明确差异，不应删字段伪造一致。旧 offline 重算语义未改：独立加载基线 `25b2f1c` 原 dual_source，对15个旧注册场景及4个R17真实/合成、有限规则变体核对，19份规范化结果字节一致。

## 日志与剩余验收

- [自动关闭与过早结束首次失败](validation-round18-core/automatic-window-first-failure.log)：修复前实际 late≠预期 too_late，且过早 finish 未失败。
- [窗口积压指标首次失败](validation-round18-core/backlog-window-first-failure.log)：修复前缺少完整窗口计数；保留固定预期与实际缺字段。
- [speed 参数类型首次失败](validation-round18-core/speed-type-first-failure.log)：修复前布尔 true 被当作枚举数字1；现在拒绝布尔/字符串，同时接受 JSON 数字1/1.0/10/10.0，有效语义不变。
- [最终核心回归](validation-round18-core/core-fixed-regression.log)：23项独立核心测试通过。
- [旧 offline 字节兼容](validation-round18-core/offline-byte-compatibility.log)：19份结果一致。

正式任务生命周期、实际1x/10x完整链路、CLI/Worker、历史查询和下载、PG空库恢复、普通点击、R16/R17全回归以及最终准确提交 SHA 的完整 CI 由总验收记录另行汇总。真实授权材料、工业时钟/设备依据和效果验证仍未取得；R19容量与性能目标未在此验收。
