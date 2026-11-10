# R19 密度矩阵：显式生成与独立预算预检

基线 `aa16a4db525e55d0c435fc16bad5bb5edbab94b6`；R19不结项，不进入R20。此阶段修复测量工具与新容量版本脱节，未修改算法、旧默认、容量常量，也不把已知预算冲突当作密度验证通过。

## 1. 先复现、保留旧例

原样 `generate(...,'M')` 产生不带capacity的新旧基线，实际核心调用子进程以1退出，stderr为 `ValueError: operation_limit`，约2.989秒。原始PCAP/CSV、两profile及stdout/stderr在工作区 `outputs/cpag-r19-density-generator-aa16a4d/legacy-M*`，公开摘要与原始错误在 `validation-round19-density-generator/legacy-M-*`。输入/生成器SHA保留，未覆盖审查目录的原记录。

缺省 `version=r19-raw-scale-fixture-1` 不变；S/M/L两profile逐字节SHA回归，原始抓包和CSV与预变更生成器固定SHA完全一致。新版本为 `r19-density-capacity-2`。

## 2. 可直接接正式脚本的接口

```sh
python scripts/validation/round19_scale_fixture.py --output /tmp/r19-density-v2-S --scale S --version r19-density-capacity-2
python scripts/validation/round19_capacity.py --dev-run --resource-profile engineering-capacity-1 --image <固定镜像> --case-manifest /tmp/r19-density-v2-S/dual_source-1.json --output /tmp/r19-density-run-S-offline-1
```

`generate(root,scale,version=...)` 为S100/M1000/L10000各产生完整原件、离线/回放profile、六个三次测量case、fixture.json、preflight.json、matrix.json。新profile显式engineering-capacity-1；回放同时声明replay-history-checkpoint-delta-2，使用已注册预算。抓包请求间隔50ms、响应+10ms、CSV间隔80ms、交替0/1、5秒窗口、3秒采样间隙、300秒buffer、2秒lateness、每个原始到达步骤均保留，没有为了通过预算删响应/候选或缩短窗口。

case仍为既有 `r19-capacity-case-1`，可直接给read_case；matrix有六条case路径、profile SHA与预检状态。第一轮cache为unverified_cold，未声称清除OS缓存。

`read_preflight(case_manifest, require_new=False)` 是测量入口hook：

- 旧目录没有报告时返回None；新fixture声明缺报告、强制require_new或不安全文件时拒绝。
- 报告schema为r19-density-preflight-2；重新核对固定raw SHA、完整profile和到达序列、当前同版本Budget、独立数学结果、case所选原件和profile。手改issue列表或数学数值不能放行。
- 返回path/sha256/case_manifest_sha256、fixture_version、mode/scale、profile/config指纹、budget、density_math、issues、status和admission_scope。
- generator_sha256仅为生成时声明身份，验64hex，不要求等于今后注释修改后的脚本SHA；不能冒称密码学托管证明。真实raw/config/math核验保留。
- status只有admissible_for_formal_attempt或blocked_budget_design。root测量入口在PG/Worker启动前拒绝blocked，且operator resource profile必须匹配capacity profile。允许attempt不表示输出、耗时、恢复或参考环境验收通过。

已生成可用目录为工作区 `outputs/cpag-r19-density-generator-aa16a4d/capacity-v2-{S,M,L}`，可查公开generated-index.json。禁止在相同输出目录覆盖旧样本。

## 3. 独立数学，而非算法输出作答案

操作i的请求时间 `10s+0.05i`，工艺样本j时间 `9s+0.08j`，奇数j结束于1、偶数j结束于0。变化区间为前后两样本之间。整数微秒条件：

`transition_start < request+5s` 且 `transition_end >= request`。

分别计预期1变化e_i和反证0变化u_i。固定零误差时钟的向外浮点舍入可能增加右侧恰好相等的边界项，不能减少上述下界；另用包含右端相等的计数给上界。这些是固定原件几何的预算推导，不是评估gold、攻击预测或真实工业结论。

| 规模 | 候选下界..上界 | Σ e_i*u_i | 到达步骤 | 快照基础..保守上界 |
|---|---:|---:|---:|---:|
| S100 | 2594..2596 | 70576 | 304 | 308..612 |
| M1000 | 31751..31813 | 1008000 | 3004 | 3008..6012 |
| L10000 | 317500..318125 | 10080000 | 30004 | 30008..60012 |

快照上界考虑每次consume至多一个clock-before-arrival，以及初始化/末尾consume/advance/finish；不是实际测量数。L的45000快照上限尚不能覆盖这一保守保证，需后续版本明确解决，不假称已经实测溢出。

CSV原始SourceRef的完整规范JSON至少177bytes（64位摘要、27位原始时间、pump列、null帧、正行号）。回放引用字段更多，177仍为保守下界。每个候选在自身counterevidence及claim反证中重复2u_i条引用；旧离线两份analysis加graph.claims共10 e_i*u_i条，回放最终一份flat analysis加graph.claims共6 e_i*u_i条。candidate-加64hex的74bytes ID又分别出现5次和3次。只计这些互不重叠的必需字节，完全忽略其他键、容器、字段、历史和原件：

- 离线下界：`10*177*Σ(e_i*u_i)+5*74*Σe_i`。
- 回放最终flat下界：`6*177*Σ(e_i*u_i)+3*74*Σe_i`。

| 规模 | 离线flat下界bytes | 回放最终flat下界bytes | 静态入口状态 |
|---|---:|---:|---|
| S100 | 125879300 | 75527580 | 两模式可申请正式attempt；实际输出/历史/耗时仍需验 |
| M1000 | 1795907870 | 1077544722 | 两模式都已超过1GiB，blocked |
| L10000 | 17959075000 | 10775445000 | 两模式超过1GiB，候选下界超过100000，回放另有快照coverage gap |

因此不能只加capacity字段或把L候选上限调大就标作可跑。新共享存储格式必须覆盖最终analysis、完整graph.claims/evidence、评估projection/event_links、历史与query；不能只压缩SQLite历史而留flat终态继续超预算。原始到达均延迟0.1s，小于2秒允许lateness；窗口的所有必要样本在关闭前可到，不能以丢弃合法记录降低预算推导。

## 4. 测试与状态

生成器8项测试通过，覆盖旧默认全字节兼容、所有原始帧/行/到达保留、新模式绑定、独立手算/穷举和预检篡改拒绝；完整validation回归见all-validation-tests.log。未调用预测器产生预检答案，未启动本阶段M/L Worker或宣称性能成功。

后续500000候选、65000快照、90000修订仅是**待新version**的预算建议，不能修改既有engineering1解释旧产物；physical输出仍1GiB。共享存储原型、往返和分页需另行证据，并由root接Go/Worker/备份/评估正式入口。参考Ubuntu环境和真实授权材料缺口继续单列，不掩盖上述软件阻塞。
