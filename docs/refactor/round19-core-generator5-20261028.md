# R19 密度生成器版本5：显式逻辑护栏与完整快照投影

依据核心瓶颈预登记新增记录，本次只修改 `round19_scale_fixture.py` 与限定测试，不改其它runtime。版本5为 `r19-density-capacity-5`，仍属于 COMPACT3/DAG6 核心限定配置，不代表 Go/Worker 集成或容量验收。

与版本4相比，配置只增加：

- 顶层 `storage_budget_version=shared-storage-budget-2`。每根逻辑extent上限为4PiB（2^52），用于认证共享历史重复引用的计数；不分配相应内存或磁盘，不授权get/下载整根。
- replay内 `standard_projection=standard-graph-events-1`。明确要求保存每步旧标准graph/events；不对未携带字段的版本4/dev1结果追加新解释。

预检的 `logical_extent_guard` 明确记录该区别及 `whole_root_materialization_authorized=false`。1GiB完整物理输出、4CPU、8GiB RAM、4GiB临时、1800秒、8MiB/100项页预算保持；逻辑上限变大不是内存、物理输出或请求时限变大。物理是否足够与完整核心运行是否成功仍须独立实测。

默认生成器、旧capacity-3和版本4均保留。版本4仍缺省storage budget1/512GiB且不带standard_projection，S版offline/replay profile固定SHA分别`492f689a6b04ef28bf2fbdb1023993d748efba9fed41f0e165c8a46b3409473e`、`2bd7dcc4ff4682f1d0a201d88ad7f84fc902f96e6538df8d794f52e4ede029d0`。5→4升级操作明确拒绝，避免静默删投影版本。

使用方法：

```text
python scripts/validation/round19_scale_fixture.py --upgrade-from VERSION4_DIRECTORY --output NEW_DIRECTORY --version r19-density-capacity-5
```

S/M/L已生成在controlled `outputs/cpag-r19-core-standard-generator-{S,M,L}5-attempt1`。所有原始PCAP/CSV SHA与此前固定值一致，窗口5秒、缓冲300秒、允许迟到2秒、全部请求/响应/工艺记录和sequence均未改变；源目录不覆盖。每份matrix仍为core_only/integration_ready=false/operator_resource_profile=null，preflight仍为admissible_for_core_attempt，当前formal harness会在镜像/Go/Worker之前拒绝。

15项生成器测试通过（含所有旧版本、4和5，9.10秒静态测试）：验证原始SHA和源目录不变、剥去新增两字段后与版本4完整配置相等、storage预算只有version/逻辑extent两值变化、核心物理/资源预算相等、缺projection/篡改preflight/缺preflight拒绝、5→4拒绝及formal dispatch拒绝。未运行新的分析、回放或M/L重载。

公开证据在 `validation-round19-core-generator5/`，含全套日志与新目录逐件SHA；原始日志先保存到0700 controlled `outputs/cpag-r19-core-generator5-evidence-20261028`。本项没有失败测量被覆盖；旧首次失败仍在此前parser及核心运行目录保存。
