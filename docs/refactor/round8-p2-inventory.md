# Round 8 P2 预先固定的有限入口清单

固定日期：2026-10-26。先按当前源码列出能力与验证入口，再执行 P2 检查；以下分类是代码边界，不是通过结论。真实历史任务、部署凭据、Neo4j/Redis/Celery 等外部环境缺失时保留具体待核查项。`共享核心` 仅指 round7 已限定的 normalized JSONL + process CSV 合成路径。

| ID | 入口、代码位置 | 分类 | 本轮检查或明确阻塞 |
|---|---|---|---|
| G01 | Go `/api/version/*`，`api/routes.go:14`；版本代理 `api/proxy.go` | 旧版独有 | `go test ./api` 现有路由/代理单测；实际切换版本会改变默认归属，本轮不执行，记录待部署核查 |
| G02 | Go `/api/v1/*`、`/api/v2/*` 与默认 `/api/cpag/*`，`api/routes.go:31` | 旧版独有 | `go test ./api`；实际 Python 上游联通和默认代理行为待受控部署核查 |
| G03 | Go `/api/tasks/*` 列表、状态、下载、队列，`api/routes.go:22`、`api/proxy.go` | 旧版独有 | `go test ./api` 覆盖代理的有限路径；真实历史任务下载待实例与服务核查 |
| G04 | Go `/api/graph/*` 查询、删除、健康、浏览器，`api/routes.go:54`、`api/handler.go:344` | 旧版独有 | 图读写依赖 Neo4j 与历史图实例；本轮无真实实例。删除路径不执行 |
| L01 | Python v1 `/cpag/generate`、状态、结果、列表、下载、队列，`services/python-cpag-generator/api/v1/app.py:170` | 旧版独有 | `tests/legacy/test_no_fabricated_pcap.py` 只覆盖不伪造 PCAP 的静态/有限行为；完整旧任务需 PCAP、配置及服务依赖 |
| L02 | Python v2 旧 `/cpag/generate`、状态、结果、JSON、列表、下载、队列，`services/python-cpag-generator/api/v2/app.py:62` | 旧版独有 | `tests/legacy/test_no_fabricated_pcap.py`；完整 v2 处理与 Neo4j/InfluxDB 行为需旧任务材料和依赖 |
| L03 | Celery v1/v2 生成任务及 v2 指标/健康/清理，`api/v1/tasks.py:27`、`api/v2/tasks.py:80,408`、`infrastructure/celery_app.py:12` | 旧版独有 | 源码盘点；真实队列、结果与周期任务需 broker、数据库及旧任务实例，不用合成新核心结果冒充 |
| S01 | 显式 v2 合成 HTTP/worker `/cpag/synthetic` 与产物，`api/v2/synthetic.py:89,160` | 共享核心 | `tests/service/test_synthetic_http.py` 对请求、队列与产物做有限测试；与 M4 的逐字段一致性由 round7 脚本执行 |
| C01 | M1 CLI `python -m cpag_core`，`services/analysis/src/cpag_core/__main__.py:6` | 共享核心 | `tests/integration/test_m1_cli.py`；round7 脚本做三次逐字段比较 |
| C02 | 显式 packet CLI/证据查询，`cpag_core/packet_job.py:124,95`、`evidence_web.py:56` | 新版独有 | `tests/packets/test_packet_job.py` 的独立 packet 契约；旧版无需产生相同结果 |
| M01 | M4 opt-in `/v1/jobs` 提交、领取、状态、attempts、取消/完成，`internal/jobapi/server.go:246` | 共享核心（normalized）；packet 为新版独有 | `go test ./internal/jobapi/...`、`tests/worker/test_worker.py`；round7 逐字段一致性；真实旧任务材料待核查 |
| H01 | 规范化产物读取 `dataset/events/graph/quality/run_manifest`，`cpag_core/pipeline.py:87`、`api/v2/synthetic.py:60` | 共享核心 | P2 历史只读检查仅接收版本 1.0.0 与原始 network/process 文件，复用 schema、hash、evidence；真实历史实例缺失保留待核查 |
| H02 | packet 六件产物读取及原抓包重核，`cpag_core/packet_job.py:55,95`、`evidence_web.py:32` | 新版独有 | P2 历史只读检查复用 `verify_artifacts`；真实 packet 历史实例缺失保留待核查 |

`G04` 删除属于当前旧路由，但不进入只读历史检查；它仍由旧入口保留。P2 不迁移旧数据库或中间文件，不切换默认路由。
