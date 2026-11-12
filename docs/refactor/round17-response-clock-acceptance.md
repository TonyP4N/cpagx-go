# R17 响应时间质量补验收

基线 `288ffc068c0196d0725478c3404bdca0a2aaf26e`，分支 `refactor/m1-evidence-core`。实现提交 `b4fafa465bddd824011a5b6394ca9ac7b92b005f`。本记录限定合成软件与工程链路，等待本项复核后才讨论 R18；冻结 RC1、默认入口及已有产物不变。最终报告提交与准确对应的完整 CI 在交付信息绑定，不能用旧 CI 绿灯代替。

## 缺陷、独立预期与修复

按复核目录的原 `reproduce_response_clock.py` 原样运行，单文件和跨文件响应过期均得到一个 supported_candidate，操作未知原因为空；请求过期和正常对照符合预期。原独立答案和失败结果保留在 [expected-before.json](validation-round17-response/expected-before.json)、[before.json](validation-round17-response/before.json)。完整历史错误产物保留在 `tests/fixtures/r17-response-clock-v1`，未用新算法生成或重写。

根因是操作只检查请求时间，响应自身的时钟质量未传到操作和候选门禁；因此标准投影、Worker 和恢复一致地传播了错误。新 `bounded-dual-source-2` 检查请求、响应的时间状态、区间及严格先后，按侧别保留原因，例如 `response_clock_validity_outside`。对应操作仍保留协议 success，但判断 unknown，禁止该操作的跨源候选和图边。请求、响应、工艺采样和变化均保留，未知不伪造协议错误。

独立代码复查还发现质量报告遗漏操作时间原因，已在 v2 增加 `quality.operation_time_issues`，按 operation_id 记录，避免把一个操作的问题写入全局门禁而阻断其他正常操作。对应混合双操作回归通过。

预登记见 [补修计划](round17-response-clock-plan.md)，以下实际均通过：

| 场景（均独立构造） | 预期 / 实际 |
|---|---|
| 单文件、跨文件正常 | 2网络、5工艺、1变化、1支持候选；正常对照保持 |
| 请求有效期外 / 响应有效期外 | 对应 request_/response_clock_validity_outside；0候选、0边；观测和响应事实保留 |
| 闭边界恰好10/11秒 / 截止10.999999秒 | 闭边界正常；刚越界未知并拒绝候选 |
| 缺basis、drift_basis、precision_basis | 核心/CLI保留具体未知、无候选；正式材料门禁仍拒绝不完整配置 |
| 请求响应区间重叠 / 接触 | response_order_uncertain，0候选/边，不以近似时间确定先后 |
| 响应明确早于请求 | response_precedes_request，0候选/边 |
| 状态unknown却仍有数值区间 | 不允许绕过时间门禁；测试显式注入这一不一致状态 |
| 两操作中一个正常、一个响应过期 | 正常操作仍保留候选，过期操作单独阻断；质量原因按操作区分 |
| 无响应 | 保留既有缺响应与未知语义，不引入协议扩展或成功推断 |
| 旧v1、新v2、未知/混合版本 | 旧v1可重算核验且字节不变；新执行v2；未知/混合拒绝；新发布v1拒绝 |

原脚本修复后六个场景均匹配原答案，见 [after.json](validation-round17-response/after.json)。完整双源41项（含独立schema验证）、备份47项均通过；新增正式验收oracle3项和服务版本检查通过，见本目录日志及 [服务补验](round17-response-clock-service-acceptance.md)。测试数量仅用于定位日志，不作为关闭标准。

## 正式链路、证据及恢复

[响应过期正式记录](validation-round17-response/response-worker-restore.json)：正常 Go 服务、真实 PostgreSQL、隔离 Worker 三次独立执行，均为 2网络、5工艺、1变化、0候选、0图边，响应仍 success，操作 unknown。API质量、产物质量和操作原因一致。CLI/API结果语义相同。

操作查询两条网络原帧（10秒请求、11秒响应）；独立变化查询两条CSV原记录（第2/3逻辑记录，10.5秒为0、12秒为1），总计四条。核验具体原文件哈希、帧号/记录号与原始时间，不只比对解析器自身输出。没有候选时不把工艺证据伪挂到操作上。

停写终态快照包含数据库、attempt历史、输入、配置、产物和嵌套原件；恢复至空数据库、新目录后再次经 API 查询三次任务，结果、引用、下载哈希、catalog及attempt历史一致。不是仅恢复目录或重启容器。

[普通点击浏览器记录](validation-round17-response/response-browser.json)在源服务与恢复服务均通过：明确看到未知原因和无候选，点击操作/变化分别查看原始内容及字段，下载内容匹配。`page_errors=[]`是附加检查，不是唯一断言。截图：[未知原因](validation-round17-response/source-unknown-no-candidate.png)、[恢复后未知](validation-round17-response/restored-unknown-no-candidate.png)、[请求响应原件](validation-round17-response/source-operation-original-network.png)、[恢复后CSV原件](validation-round17-response/restored-change-original-process.png)。

## 正常重复性与历史兼容

[正常三次 Worker 与 CLI](validation-round17-response/normal-worker-restore.json)完全一致：

| 文件 | 三次与CLI一致的规范化SHA-256 |
|---|---|
| events.json | bf8be4c1e612fad72c87f9b84fe7e682491a7e34f2d089cac56fc8445caac146 |
| graph.json | d550e591c8fcc5ec3947a6267e82dcfe69c58420bebc248b8616857454e07079 |
| analysis.json | ea91e0ad7b437e2cefafd82020267d9bd0ad79ab796313d9425b40d9310ac683 |

前两项与基线相同。analysis因版本字段及新增操作质量列表改变，明确作为版本变化记录，不删字段伪造跨版本哈希相同。执行身份、attempt及运行时间在运行清单另存，未参与三份语义文件哈希。[正常浏览器](validation-round17-response/normal-browser.json)及缺失/篡改、real来源生成接口分支、第五抓包拒绝等原R17检查通过。

读取旧v1产物时，仅由已校验保留manifest选择历史语义，继续完整原件/配置/投影/哈希核验。旧结果不会静默改变或被误报篡改。API和证据查询附 `compatibility`，页面展示历史响应时间限制与显式重新分析提示；只有新运行使用v2。旧 synthetic-dual-source-1 保持不变。新发布门禁不接受v1，已完成同身份同哈希的幂等请求保留。历史固定夹具的文件逐字节核验和服务端历史提示有测试；本轮浏览器真实任务验收覆盖新v2及恢复结果，未声称另建旧v1任务完成浏览器演练。

R16完整顺序回归重新执行成功：PCAP单源预检→补传CSV→再次预检→配置追加→旧快照保持→停写备份→空库新目录恢复；材料/批次/映射/时间/过期预检门禁、审计、无任务副作用、权限和篡改拒绝仍通过。见 [20项顺序检查](validation-round17-response/r16-sequence.json)、[普通点击门禁](validation-round17-response/r16-sequence-browser.json)、[恢复浏览器](validation-round17-response/r16-restored-browser.json)、[边界](validation-round17-response/r16-boundaries.json)。

## 可重复执行

从仓库根目录（可用Docker、Go、Python依赖和Playwright浏览器；前端先构建）：

```sh
python -m pip install -r services/analysis/requirements-test.txt
python -m unittest discover -s tests/dual_source -v
python -m unittest discover -s tests/validation -p test_round17_response_acceptance.py -v
bash scripts/validation/round17_response_acceptance.sh /tmp/cpag-r17-response-fresh
bash scripts/validation/round17_acceptance.sh /tmp/cpag-r17-normal-fresh
bash scripts/validation/round16_acceptance.sh /tmp/cpag-r16-regression-fresh
```

输出目录须为新目录。`CPAG_PYTHON`可指定安装依赖的解释器；`PLAYWRIGHT_MODULE`指定Playwright安装路径。补验脚本可选`CPAG_STATIC_ROOT`指向同源码新构建的静态目录，缺省仍使用仓库webui/out。完整CI已接入补验脚本和独立oracle，不用手工脚本绿灯代替CI。

本机发生iCloud占位读取等待，保留原件并重新下载；GitHub精确基线下载恢复文件前核对Git blob一致。为不覆盖用户部署，部分验收在精确288ffc0临时clone叠加本轮源码并逐文件校验后运行，新前端与隔离镜像均用相同源码构建。见 [输入代码哈希清单](validation-round17-response/validation-overlay.json)。下载阻塞、初次截图位置调整不计软件验收通过，不作为性能结果；最终真实链路与普通点击另行运行通过。

## 本轮状态及剩余事项

本项响应时间软件修复、预登记场景、版本兼容和合成完整链路已通过本地补验。最终完整CI必须绑定最终提交全部成功，交付后等待用户复核，不自动进入R18。

M2/R05—R06补齐支持子集的时间质量传播；M3/R07/R11补齐候选/图/质量一致性；M4/R09—R10和M6/R13新增错误边界经正式Worker和空库恢复证据。只更新这些限定子项，不把M2、M4或整体重构标完成。M0/M1既有成果保留。

软件剩余项仍为原路线图R18回放、R19评估/容量性能、R20综合交互、R21运维/历史格式、R22发布验收；本轮不启动。真实材料缺口：授权同期PCAP/CSV、批次/采集点、设备字段单位映射、时区/偏移/漂移依据、独立标注和保留集。真实历史实例缺口：约定旧版本数据库、输入、配置和产物。生成数据的real来源分支仍只是接口验证，不是已收到真实样本，也不证明工业效果。
