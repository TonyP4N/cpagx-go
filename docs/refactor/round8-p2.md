# Round 8 P2：旧能力盘点与限定兼容验收

日期：2026-10-26。入口清单在 P2 测试前固定于 `round8-p2-inventory.md`，逐项保留代码位置、分类与既定测试/阻塞，不按结果增删清单。P2 未改默认入口、任务归属、冻结标签或旧服务组件。

Go 的 `/api/health`、`/api/ping` 和根页面位于 `api/routes.go:64-79`，v1/v2 的 `/health` 分别位于 `api/v1/app.py:159`、`api/v2/app.py:58`；这些是控制/健康入口，不生成或读取任务产物，本轮只作静态位置核对，未纳入结果等价范围。

## 执行结果与清单归因

| ID | 本轮实际结果；未覆盖处的具体条件 |
|---|---|
| G01、G02、G03 | 总集成环境执行 `go test ./api ./internal/jobapi ./internal/contracts` 通过，证据见 `validation-round8/go-compatibility.log`。代码位置与旧代理归属已盘点；版本切换、实际 Python 上游和真实历史下载仍需受控部署与实例。 |
| G04 | Neo4j 图任务查询/删除/健康/浏览器路由已盘点；无可授权的真实历史图实例及 Neo4j 运行环境，本轮未执行删除或判定兼容通过。旧路由保留。 |
| L01、L02 | `tests/legacy/test_no_fabricated_pcap.py` **5 passed**，只确认失败 PCAP 不被伪造成成功图；未覆盖旧 v1/v2 完整生成、结果读取或数据库持久化。需具体旧任务的 PCAP、CSV、配置与依赖。 |
| L03 | Celery v1/v2 生成与 v2 指标/清理任务已按源码盘点。真实 broker、结果后端及历史任务实例缺失；未声称旧 Celery 队列执行与 M4 一致。 |
| S01 | `round7-consistency.py` 的三次本轮执行覆盖 legacy-v1 **process Worker** 与 isolated-v2 Worker 共用核心；非 Celery 运行时等价。本机起初因 iCloud 按需依赖文件导入阻塞，取回原版本文件后 `tests/service` 11项通过（`validation-round8/service.log`）。这覆盖服务测试的模拟队列/内联任务路径，真实 Celery broker 执行仍待受控服务环境核查。 |
| C01 | M1 CLI `tests/integration/test_m1_cli.py` **2 passed**。三次比较中共同 events/graph/quality 逐字节一致。 |
| C02 | `tests/packets/test_packet_job.py` **3 passed**；packet 属新版独有独立契约，不要求旧版输出同一结果。 |
| M01 | `go test ./internal/jobapi` 与 `./internal/contracts` 在总集成环境通过，证据见 `validation-round8/go-compatibility.log`；`tests/worker/test_worker.py` **14 passed**。三次 Worker 比较按 Round 7 的字段级规则通过；任务数据库中真实历史实例仍待材料核查。 |
| H01、H02 | 新的只读历史检查 `scripts/validation/round8_compatibility.py` 限定规范化五件与 packet 六件合成产物。`tests/compatibility/test_history_readonly.py` **6 passed**：源文件、manifest、文件集合、hash/size、输入/结果指纹、schema、规范化事件及节点证据回查、packet 原抓包重解码均核对。即使重新计算图及 manifest 哈希，节点引用指向其他有效事件也会拒绝。缺件、未知版本、篡改、符号链接拒绝；检查前后文件哈希不变。真实历史实例未提供，保留待核查。 |

三轮真实 M4 执行结果在 `validation-round8/p2/three-run-summary.json`：`valid=true`、`synthetic_only=true`。每轮两执行器的 `events.json`、`graph.json`、`quality.json` SHA256 均逐件相同；三轮间这些 SHA256 也相同。原记录回查摘要每轮同为 `071276dc4a02798caeeb04fbbfe4d0df2c10ca8c07f15f5874957aa381856537`。具体允许差异继续沿用 Round 7 的逐字段规则，详情在最终 `final-run1`—`final-run3` 各轮 `consistency-exact-differences.json` 与 `consistency-result.json`；没有广泛忽略时间、ID、hash 或证据字段。

只读 CLI 示例：

```sh
PYTHONPATH=services/analysis/src .venv/bin/python scripts/validation/round8_compatibility.py \
  --kind normalized --artifacts /path/to/core-artifacts \
  --network /path/to/source.jsonl --process /path/to/source.csv
```

packet 将 `--kind` 改为 `packet`，提供原 `.pcap` 与当次 process 占位源。未知版本、缺文件或缺原始源会拒绝，且不会修改历史文件。现有数据库、Celery 产物、Neo4j 图、任意旧中间文件与真实工业材料均不在此限定格式的只读通过范围。

## 阶段状态与材料差异

已实现并验证：固定有限清单；规范化/packet 合成历史只读核查；Go API/jobapi/contracts、M1 CLI、packet 契约、M4 worker 有限回归；三轮同核心 Worker 一致性。本地代理环境曾因缓存权限及离线依赖缺失无法启动 Go API 测试，随后总集成环境的上述通过结果取代该尝试。实现但待材料验证：真实历史任务格式、授权和结果、旧 v1/v2 生成与图服务、Celery 队列及 HTTP 上游运行。未开始/受阻：真实历史实例不存在，故 M4“旧任务能力无未解释回退”仍未完成。
