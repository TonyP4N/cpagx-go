# R20 首版分析工作台验收

基线 `912eb7b1a877b0d15083d832ef90577daa9cea8a`，本地与远端核对一致。依据原方案 §8、R11 和收尾路线图第二十轮。正式 Go 服务继续提供页面、会话与数据权限。新入口 `/workbench/`，现有 `/workspace/` 提供入口链接。

| 操作断点 | 复用与补齐 | 新验证 / 复用证据 |
|---|---|---|
| 接收、配置与运行在同一长表单，离开数据集后难辨当前运行 | 复用接收、原件、版本、历史预检表单；分工作区展示，以 URL 保持数据集、运行及页签。提交仍走服务端预检门禁 | 新跑正式小型离线、回放，检查用户权限、切换、刷新、返回；复用 R16/R19 门禁与恢复 |
| 成功运行随后跳到分离页面，图、证据、历史和评估上下文零散 | 复用已核验分页查询、原件与评估定位器；突出当前操作、工艺变化、候选及相反依据 | 新跑普通点击、首中末历史中的选定时刻、评估错误定位、超限/撤信、窄屏和键盘；复用已归档恢复任务、S100 数据 |
| 任务只有取消，失败后无显式受控重试 | 在同一运行内使用既有 claim 的下一次 attempt；校验终态、前次退出、剩余次数、权限、请求绑定并审计 | 新跑定向拒绝与正式重试；引用 R19 隔离/稳定性固定版本 |
| 图形列表缺乏可判断的显示边界 | 图页面限定读取与绘制，保留分页和原始证据链接 | 合成 1000 节点/3000 边仅用于浏览器预算，正式服务小例单独验收 |

采用本地 taste-redesign 的层级、可读文本与响应式检查。web-design-guidelines 按 [2026-11-02 获取的官方规则](https://raw.githubusercontent.com/vercel-labs/web-interface-guidelines/main/command.md) 检查语义导航、标签、键盘焦点、异步通告、长标识及返回状态。基线页面、实际服务流程和审查发现随本页更新。已有未提交原型保持独立。

## 图形测量预登记


Registered before implementation and measurement on 2026-11-02. Baseline 912eb7b.

Scope: Next workspace analysis only. Synthetic bounded browser fixture, not backend capacity, Ubuntu reference-environment, or real-industrial-data acceptance.

- Fetch bounded verified pages, never eagerly expand all DAG6 observations/history. Maximum loaded graph 1000 nodes / 3000 edges; separate analysis rows at most 1000 per kind. Backend refusal remains visible; never treat clipped results as complete.
- Default drawing at most 200 nodes / 600 edges; explicit detail setting permits all 1000 / 3000. Stable O(N+E) layout, no force simulation. Canvas draw; semantic paged selections provide keyboard access.
- Lists <=25 visible rows. Full raw evidence remains server-verified and paged. Run, snapshot, integrity, auth, and query changes clear affected stale selections. No unauthenticated fallback.
- Fixed browser fixture: 1000 graph nodes and 3000 edges, 500 operations + 500 changes, 1000 candidates, pagination over same-origin authenticated API-shaped responses. This test measures frontend only; report it explicitly as injected synthetic fixture.
- Browser acceptance budgets, evaluated without build/start time: loaded view ready <=5000ms; full 1000/3000 draw <=1000ms; filter/select <=1000ms; no browser page errors or unbounded DOM growth (>2500 total nodes). Record elapsed, loaded/drawn counts, DOM, response behavior, and screenshot.
- Functional checks: graph node -> timeline/candidate/evidence selection; candidate -> operation/change linkage; time/type/state/text filters and aggregation; clipping disclosure; keyboard selection; stale async result race; 403/409 clears trusted display; empty and responsive state.
- Capture raw pass/fail measurements. A budget failure stays a failure until changed implementation is remeasured; do not silently relax thresholds.
- Memory preregistration before measurement: Chromium browser via Playwright/CDP `Runtime.getHeapUsage`; post-GC JS heap total <=192 MiB and <=128 MiB above empty-page baseline. Report browser/version/platform/viewport; do not claim OS RSS or renderer process memory from JS heap.

## Frozen final-candidate measurement conditions (registered after diagnostic run2, before final measurement)

- Browser: Google Chrome 156.0.8078.76 (actual diagnostic browser.version), Chromium controlled by local Playwright runtime; headless, deviceScaleFactor default 1, reducedMotion=reduce. macOS Darwin arm64; exact OS build captured in the companion environment file before final measurement.
- Fixed desktop viewport: 1440 × 1000 CSS pixels. Responsive check: 390 × 844 CSS pixels. No CPU/network throttling; same-origin API responses are intercepted by an explicit injected synthetic fixture, with per-page bound <=100. Browser backend/source verification acceptance is outside this measurement.
- First-ready timer: Node monotonic performance.now immediately before page.goto(fixed local /workbench/ deep link), stops after analysis graph DOM is visible. Includes HTML/JS load, login session lookup and context restoration, injected analysis page requests, React rendering; excludes browser launch and prior test-account login. This is a warm local static asset measurement; the browser context is fresh.
- Expand-ready timer: immediately before click on “扩展视图 1000 / 3000”, stops when graph DOM data-edges=3000. Full draw timer is component performance.now around canvas backing-store allocation, edge/node draw loop, before setDrawMs; it measures JS drawing submission, not compositor/GPU presentation. Both values are retained.
- Selection timer: immediately before focused native graph-node button Enter, stops when 25/30 verified-evidence-shaped fixture entries are visibly reported. Filter timer: immediately before Apply button click, stops when graph data-node count is below 1000. These are frontend-only synthetic response timings.
- JS heap: CDP Runtime.getHeapUsage usedSize, after HeapProfiler.collectGarbage on fresh about:blank for baseline and after full 1000/3000 ready for measured view. OS RSS is not inferred. Budget remains <=192MiB total used JS heap / <=128MiB incremental heap, <=2500 DOM elements, first-ready <=5000ms, full draw <=1000ms, selection/filter <=1000ms.
- Prior diagnostic run2 retained at output/playwright/r20-analysis-run2/analysis-browser-measurement.json; it is not the final candidate measurement and its already-observed results do not change thresholds.
- Exact fixed OS: macOS 27.2, build 26B123, arm64. Node runner v25.2.1. Final probe will record static JS bundle URLs/hash for candidate identity along with the above environment.

## 实测记录

| 操作与预期 | 已取得的证据 |
|---|---|
| 正式入口分别提交离线、回放，首次执行完成并能读四条证据 | 两个新运行均在 attempt 1 成功。从时间线点开请求、响应及工艺变化前后记录。 |
| 运行中取消后按同一绑定重试 | 首次执行退出后显示已取消。同一运行第二次执行成功，历史保留两次登记、两次退出。排队取消要求二次确认。 |
| 图规模固定为 1000 节点、3000 边，检查交互、内存和裁剪 | 最终候选固定导出，首屏 343 ms，展开 202 ms，提交 Canvas 绘制 0.6 ms，选择 33 ms，筛选 133 ms。460 个 DOM 元素，GC 后 JS 堆 5,217,040 字节，比空页增加 4,643,008 字节。390 像素窄屏无横向溢出。该项使用明确标注的前端合成图。 |
| 老结果兼容 | 通过原格式 7 恢复的任务再次打开离线证据；复用 R19 已验的恢复、来源核验和固定 S100 三组正式计算。 |

正式界面沿用 Next 静态导出，Go 路由新增同运行受控重试，运行详情补入实际执行登记、退出及核验阶段，评估详情从已核验包投影划分与冻结信息。隔离计算没有上报逐帧计数，界面显示已知阶段及执行次数。规则、存储格式和图中原始证据绑定沿用基线。筛选、分页和图裁剪只作用于显示。

首次图筛选留下了同端点的另一条候选边，现按候选身份区分，定向数据和真实浏览器均验证了仅命中一条。最初浏览器定位把导航链接当作按钮，运行详情缺少区域语义，测试期间覆盖构建目录还会混用脚本；已修正相应控件和观察器、冻结每个候选的静态文件。Go 测试桩已补齐阶段查询，旧任务的空绑定回归继续通过。

工作站为 macOS 27.2（26B123）、Apple M2 Pro，浏览器为 Chromium 156.0.8078.76。未做 Windows 实测。R19 基线为 912eb7b，原 [完整 CI](https://github.com/TonyP4N/cpagx-go/actions/runs/41395084572) 为 17/17。计算与恢复沿用该基线的有效证据。M/L 社区容量未完成、不承诺支持。Ubuntu 指定参考环境、授权同期原件与时钟映射、独立真实标注和历史实例分别待验。R21 运维与 R22 发布保留。

正式 S100 浏览复用 R19 的留存回放，重新来源核验后使用当前服务读取。默认就绪 4.36 秒，当前 200 个端点组成的局部图有 0 条可见边，页上提示裁剪。显式展开实际 399 节点、2596 边用时 28.01 秒（含服务分页），Canvas 绘制 0.9 ms，选中证据 938 ms。展开后 JS 堆 74,536,132 字节，DOM 472。已翻到第二页候选并查其工艺原件。最终合成规模图的 202 ms 与真实服务的 28.01 秒分开记录；扩大范围的主要等待发生在分页读取。

| 其余交互 | 实际结果 |
|---|---|
| 返回、刷新、请求乱序 | 暂扣真实 A 证据响应，切 B 并查询，再放行 A，B 内容不变；返回及刷新显示 A 原上下文。 |
| 回放与评估 | 恢复后的回放第 0 快照无未来事实，末快照可查修订、支持和原始证据。独立评估可见冻结版本、分母及错误实例，可查参考原件并下载已核验包。 |
| 权限变化 | 管理员建用户、授权；分析员可写授权数据的配置；只读者可读授权证据、无导入入口。对无权任务直接下载和匿名下载均由服务拒绝。 |
| 解释与拒绝 | 两个候选的歧义、错误响应反证、缺失响应原因分别使用正式合成任务点击检查；无变化时有空态。缺输入、回放超限任务显示失败，尝试超过执行上限的重试得到 409。 |

### 复现入口

正式启动及完整操作路径见[操作说明](round16-operations-20261027.md)。开发检查从仓库根执行：

```sh
go test ./internal/catalog ./internal/jobapi
npm --prefix webui ci
node scripts/validation/round20_analysis_model.cjs
node webui/scripts/check-history-model.cjs
npm --prefix webui run build
```

有受控 R19 小型备份时，在独立目录运行 `scripts/validation/round20_environment.py --source <原验收目录> --output <新目录>` 保持正式应用运行。用 `round20_prepare_cases.py --state <新目录>/state.json --output <新夹具目录>` 准备合成边界用例。指定 Playwright 模块后，通过 `node scripts/validation/round20_browser.cjs <新目录>/state.json <新报告目录> submissions` 运行两次普通网页提交。运行身份、数据库 dump 和登录资料保存在私有目录。机器可读结果及代表性截图见 [证据索引](validation-round20/index.json)。

多设备用例中，泵和阀在同一时刻各有一项变化，分别点击能得到该资产的对应 CSV 列和两条变化记录。初次用 ISO 字符串断言页面格式时失败，修正为页面使用的 UTC 文字格式后通过，原始时间保留。评估用例的冻结答案为 TP/FP/FN 各 1，精确率、召回率均 1/2，正常时长为 0，按小时指标显示不可用及原因。

实际 FP/FN 行只包含 `event_id`，匹配行包含 `prediction_id/reference_id`。最初页面仅识别嵌套事件，正确指标旁的错误原件按钮缺失；候选 3 的点击超时保留，读取实现已兼容两类原始形状。另修正了来源核验结束后遗留在父工作区的待核验提示。成功回包需与当前选择的代次匹配才会清理提示。

真实占槽复查补出了来源核验的错误分类问题。计算占满唯一名额时，历史结果首次读取原来会把暂时无法启动核验缓存为失败。现仅对持久名额忙采用有冷却的待核验响应，全量核验完成后才可读取。来源不一致、未知错误及无法证明容器清理的情况继续拒绝。使用新提交的小型运行实际占槽，历史查询保持 409 pending；释放后，同一 Go 实例查询变为 200，历史 attempt 和原件字节未变。此前一次多设备结果的 409 未留存内部错误类别，不能据此单独断定其根因。

最终候选中的误报点回两条预测原件，漏检点回独立参考 CSV 的第 4 条逻辑记录，状态为 `reference_original_csv_record_verified`。首次观察器误用了较早参考版本中的 12 秒，按本包原件第 4 条记录重新核对为 14 秒。第 0 快照恢复成功后再检查工作区，旧 pending 提示已清除。前台显示的合成统计不用于评价工业准确性。

最后在独立恢复副本中同大小改写工艺原件，经正式页面重新核验后得到拒绝，原可信图和证据记录已清除，测试随后还原原字节。局部图与大结果读取限额、正式服务各阶段核验和服务端 ACL 持续生效。受影响的 catalog、jobapi、jobs 测试，Go race 定向检查、前端模型测试、静态导出与上述浏览器检查在开发环境通过。最终提交的远端完整 CI 独立核对，链接随交付提供。限定范围只覆盖首版应用的合成软件工作流。
