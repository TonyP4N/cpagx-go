# 第十二轮：网络操作与工艺变化最小双源闭环验收

基线 `bd2031eabe5b13afae7c65f27d3e6485284ac08f`；分支 `refactor/m1-evidence-core`。有限计划、场景预期和禁止结论已在实现前独立提交 `4836550`，见 [计划](round12-plan-20261026.md)、[场景](round12-scenarios-20261026.md) 和 `fixtures/dual-source/expectations.json`。参考答案是人工预先指定，测试不从预测生成答案；分析不读取攻击标注。

## 新增分析能力

新增显式合成 CLI `cpag_core.dual_source`，复用现有 ENIP/CIP、PCAP/PCAPNG 和工艺 CSV 解析。同次分析保留标准 NetworkEvent、ProcessObservation、最小 DerivedEvent 与 hypothetical Claim；附加时间、映射与解释记录，不改变旧入口的事件或默认执行行为。

操作查询回答捕获到的源/目标 IP 和端口、CIP 服务/路径/原始数据、唯一协议响应及 general/additional status。身份仅为捕获端点，不是认证用户。状态0只说明协议服务成功，非物理执行证明；错误响应作为反证，无响应作为未知。既有不支持帧仍报告并使候选带未知原因。

映射按目标IP、服务16、8位CIP路径、请求data_hex精确匹配到 asset/tag 和预期值；不新增通用CIP值解码。配置包含 config_version、rule_version 和内容指纹；缺失/多重映射明确未知。工艺同一asset/tag对应多列视为冲突。预期物理值是配置假设，未通过真实设备核验。

原始时间不被覆盖。每源保留给定偏移、误差、依据和校正区间，不自动估计时钟。CSV按校正时间排序，原始逻辑记录引用不变。变化仅来自相邻有效采样，区间为 `(前样本下界, 后样本上界]`；缺测、超间隔、同时间重复/冲突不补全。源区间不交叠或时钟依据不足拒绝生成关联。窗口只可能交叠或顺序不确定时，候选保留unknown。

候选分列支持、反证、未知和替代解释；多操作对同一变化或一操作对多变化标ambiguous。Claim始终hypothetical。成功响应但观察窗口内未见预期变化时提供覆盖窗口的原始样本反证；覆盖不足只给unknown。孤立变化仅表示本次输入中没有候选操作，不能证明没有网络原因。

## 可重复命令及完整示例

在仓库根目录、Python3.11环境执行（输出目录必须不存在；运行本身仅标准库）：

```sh
python3 scripts/validation/round12_dual_source.py --output /tmp/cpag-round12-example
```

一条命令生成独立合成输入，完成映射/时间、两源事件、变化/候选、原始证据查询。输出 `run/analysis.json`、保留输入/配置、哈希清单及 `evidence.json`。再次查询：

```sh
PYTHONPATH=services/analysis/src python3 -m cpag_core.dual_source query --output /tmp/cpag-round12-example/run --operation first
```

自备合成输入可用 `analyze --network FILE --process CSV --profile JSON --output NEWDIR`；查询支持具体operation ID或 `--change ID/first`。当前范围明确限制16MiB抓包、2MiB CSV、64KiB配置、1000逻辑数据记录、16工艺列、100操作/映射规则、10000候选；超限报错。仅opt-in合成软件验收，不接入任务发布、备份或网页，旧路径不变。

实际完整产物见 [最终示例](validation-round12/example-final/evidence.json)、[分析结果](validation-round12/example-final/run/analysis.json)。192.0.2.1:1234向192.0.2.2:44818在10秒发出写属性请求（路径1/1/1、data0100），11秒观察到status0响应；映射synthetic-pump/pump_state，工艺在10.5秒为0、12秒为1。候选窗口[10,15]，变化区间(10.5,12]，结果supported_candidate但Claim仍hypothetical。证据查询返回请求/响应原始帧、命名字段字节及校验值、前后CSV原始记录、两源校正依据与配置指纹。样例绝对时间基于2026-01-01 UTC。

查询先校验保留文件清单，再重建分析比对，能够发现丢失/篡改以及改分析后重新计算表面哈希的伪造。不提供外部签名真实性保证；同时改写全部原始输入和可信清单不在本地完整性证明范围。每次查询重新分析为当前有界CLI的正确性选择，未宣称大规模查询性能。`example/`和first-tests是中间记录，正式样例为example-final。

## 合成验收矩阵

| 场景 | 实际结果及禁止结论 |
|---|---|
| 请求+成功响应+预期变化 | supported_candidate/hypothetical；不能宣称物理成功、因果或攻击 |
| 错误响应 / 无响应 | counterevidence_present / unknown；前者保留错误帧，后者不等同执行失败 |
| 成功响应无变化 | no_expected_change_observed，保留覆盖窗口样本；不能推出永远无效果 |
| 变化无对应请求 | orphan_change，零候选；不能编造操作或断定不存在网络原因 |
| 两操作对一变化 | 两候选均ambiguous；查询含竞争请求原始证据，不挑最近项 |
| 偏移 / 乱序 | 给定有依据偏移可恢复候选；排序不改原始记录引用，不估计真实偏移 |
| 缺测 / 采样间隔过大 | 不跨缺口生成变化；unknown，不把缺记录当状态不变 |
| 映射缺失 / 冲突 | 零候选、明确reason；不猜设备或列 |
| 时钟依据缺失 / 源区间不重叠 | unknown、零候选；不强行对齐 |
| 时间误差造成仅可能交叠 | 候选unknown；不能用点时间冒充确定顺序 |

15个预登记场景逐项实际值与预期比较见 [场景结果](validation-round12/scenario-results.json)，全部符合。另验PCAPNG时间、一个操作多个变化、非预期变化反证、工艺列冲突、重复时间、窗口开闭边界、CSV结构损坏与空源、限额、不可覆盖输出、重复结果一致、配置变更指纹、缺文件/篡改/重写表面哈希、未知ID及标签不得进入输入。

本地相关回归：双源13项（含15场景和子测试）、既有协议37、解析13、核心12、Python契约6、评估14通过；Go共享契约通过。详细输出在 `validation-round12/*tests.log`。首次Go校验因自定义校验器不支持数字enum失败（`go-contract-before.log`）；将新schema服务约束改为等价integer/min16/max16，补非法服务15/17/16.5/字符串拒绝回归，通过；未改旧校验器或放宽协议。Celery仅补失败异常的stdout/stderr留存，不修复或掩盖已有偶发启动待办。

## 原方案进度和仍不能判断的事项

| 阶段 / 工作包 | 当前状态和本轮增量 | 剩余退出条件 |
|---|---|---|
| M0 / R01 | 部分完成，无范围增量 | 全部真实历史入口/配置与失败语义核验 |
| M1 / R02—R04 | 既定骨架/最小范围已完成，新契约回归通过 | 维护兼容；不代表真实解析完成 |
| M2 / R05—R06 | 部分完成；已有协议与CSV接入一次分析 | 真实设备字段/映射/时间依据和协议准确性仍受阻 |
| M3 / R07、R11 | 部分完成；新增最小变化、候选、反证/歧义/未知及CLI证据查询 | 更广语义/真实正常攻击区间复核、原方案完整交互仍未完成 |
| M4 / R09—R10 | 部分完成；默认入口不变 | 完整历史兼容/生产迁移未验；Celery偶发启动待复现 |
| M5 / R08、R12 | 部分完成；本轮非研究效果评估 | 独立真实标注/保留集、完整顺序回放及工业指标仍受阻或未实现 |
| M6 / R13 | 部分完成；冻结工程候选保持 | 前序真实验收及正式发布仍未满足 |

需要材料：授权同批次PCAP/PCAPNG与工艺记录，来源版本/校验与采集点说明，设备IP/CIP字段/标签/单位/状态字典及有效期，两源时区/同步/偏移和误差依据；真实效果另需独立正常/攻击记录、标注、保留集及固定评估准则。历史兼容仍缺实际旧任务输入/配置/状态/产物及必要Neo4j材料。公开规则与本轮合成预期不能代替独立真实标准答案。

RC1标签仍指向 `49e998545b9b7b47f2b1dc9b19e6d8562f780765`，离线包SHA256仍为 `c199dd417e1c59c55563c5535e32d26197b164c95ae17c0ef3bb621f7228b49e`。本轮不修改已有解析器/核心入口/Worker/API/冻结目录，不切默认、不合并主分支、不部署生产。远端CI结果将在实现提交后补记；未通过前不将D5视为完成。

## 提交与远端退出验收

实现提交 `ad51ceb2312098e97b54b88f001cf7aa00704611` 的 [CI 40287532425](https://github.com/TonyP4N/cpagx-go/actions/runs/40287532425) 13项全部首次通过，包含新增dual-source-analysis及既有Go、核心、前端、旧服务、真实Celery队列、PostgreSQL/Worker、隔离、工程恢复、备份和性能作业。作业明细见 `validation-round12/ci-implementation.json`。本次Celery未复现启动失败，既有待办未宣称修复。

已下载远端 `dual-source-analysis-evidence`，重新查询双方原始证据通过，查询结果与远端保存结果一致；analysis.json与本地正式样例字节一致。核验摘要见 `validation-round12/ci-artifact-verification.json`。D1—D5本轮有限合成软件退出条件满足，未发现本次引入的未解释既有回归；这不代表没有任何问题，也不解除原方案真实工业退出条件。
