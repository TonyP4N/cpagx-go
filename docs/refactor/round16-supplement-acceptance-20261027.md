# 第十六轮补验收：固定历史预检与服务端运行门禁

第十五轮验收保持通过。本轮只补第十六轮，不启动第十七轮。基线 `b208bc9e8962c0db4cc3acfa03cb3b34e1f1be5c`，分支 `refactor/m1-evidence-core`，开始时工作区干净；修复实现固定为 `0665153be62c31618db5825ca2bd6e057a4dd8e7`。默认入口、现有用户部署和冻结 RC1 未切换，未新增协议或关联算法。

原16项CI通过没有覆盖“单源预检后补传”及“缺材料但携带双源配置提交”的组合，原第十六轮全部通过结论不充分。已在原验收报告置顶更正；旧有效结果与失败证据均保留。

## 修复前复现及保留夹具

阅读用户独立 `核验报告.md`、`reproduce.py`、`results.json` 后，在基线上原样运行其脚本，得到 [before.json](validation-round16-supplement/before.json)：

| 缺陷 | 实际失败证据 |
|---|---|
| 历史预检被当前文件集合重解释 | PCAP单源预检后备份有效；补CSV再预检后备份失败：`preflight report differs from retained sources/config` |
| 缺材料仍进队列 | 来源、批次、授权为空，预检 `material_gaps`，但提交返回201/queued；未启动Worker，此处只证明入队 |
| 非法来源契约漂移 | `source_kind=invalid` 返回422/invalid_dataset，预登记要求400 |

保留 [独立复现脚本](../../scripts/validation/round16_review_reproduce.py)，只把固定仓库路径改成相对定位、输出改为环境变量，不改场景或答案。修复后同脚本输出 [original-after.json](validation-round16-supplement/original-after.json)：补传后完整备份成功；原缺材料请求422且没有队列任务；非法来源400/invalid_source_kind。该输出的 `commit` 是执行时父提交（修复当时尚未提交），不是声称原基线已有修复；固定修复代码为上面的实现提交，最终CI另绑定最终SHA。

```sh
CPAG_REVIEW_RESULT=/absolute/private/review-result.json \
  .venv/bin/python scripts/validation/round16_review_reproduce.py
```

原夹具没有传新增预检ID，修复后被 `preflight_required` 拒绝。为防止只增加一个字段绕过问题，补验收另用**真实缺材料报告ID**执行 API/CLI/UI 请求，证明仍被 `preflight_incomplete` 拒绝。

## 实现与历史边界

- 每次预检保存 `snapshot_json` 精确UTF-8文本及SHA256：文件ID/来源文件ID/路径/角色/长度/哈希，来源/批次/授权声明，intake配置ID/版本/原件哈希/指纹/内容和实际manifest。快照只含预检输入，不含后续可变的核验状态。
- 备份只按快照所列历史文件重算报告，逐项校验不可变目录身份、配置、时间顺序及原件。不删除旧报告、不跳过一致性检查、不禁止正常补传。追加文件/配置不改写旧报告和已完成运行。
- `POST /api/v3/runs` 必须携带 `preflight_id`。服务端检查当前文件集合/原件/元数据及版本，复用既有 intake 核心重算报告；在持有数据集锁的入队事务中再核对，job、run binding和预检引用一起写入。拒绝有具体原因审计，无新job/binding。
- 合成标记不能替代来源、批次、授权、映射或时间依据。真实声明仍为已接收未核验，不能进入 synthetic-only核心。没有用真实材料缺失解释本次软件缺陷。
- 007仅添加结构；旧历史不在正常启动时重写。停写后显式 `--backfill-legacy`，按历史时点文件集合和原配置重算完全一致才标 `reconstructed`；旧运行只能在唯一较早合格记录可匹配时标 `reconstructed_match`，不冒称旧门禁已执行。失败原报告仍在，记录 `unreconstructable`/原因，命令非零并拒绝可信备份。
- 备份目录契约升为format4。旧format3不能改版本号跳过快照要求，须先用固定b208bc9工具在独立维护环境恢复，再应用007和显式重建后重新备份。原format2恢复支持保留；不承诺任意旧格式。详见 [操作与迁移](round16-operations-20261027.md)。

## 实际补验收结果

使用正式Go服务、真实PostgreSQL、既有Docker隔离Worker及两个独立目录/数据库。输入全为生成样例。主要记录：[顺序结果](validation-round16-supplement/sequence-results.json)、[浏览器拒绝](validation-round16-supplement/browser-rejections.json)、[恢复后浏览器](validation-round16-supplement/browser-restored.json)。

| 顺序/故障 | 实际结果 |
|---|---|
| PCAP→单源预检→完整备份 | 成功，历史快照只有1个文件 |
| 补CSV→第二次预检→正式Worker | ready；分析完成、4条原始证据可查；第一份报告/快照不变 |
| 再追加文件和配置版本 | 两份报告和已完成结果不变；旧预检用于新文件集合被409 preflight_stale拒绝 |
| 终态完整备份→空数据库/新目录 | 成功；目录与attempt一致；两份历史报告及各自快照逐项相等，恢复后4条原始证据可查 |
| 缺source、batch、authorization_ref | 分别API/CLI得到422 preflight_incomplete，job/binding计数不变，每次有具体审计；UI普通点击缺材料同码 |
| 批次冲突 | 预检和运行409 batch_conflict；API/CLI/UI均无入队 |
| 缺映射、缺时间依据 | 分别422 insufficient_basis；API/CLI和普通点击均验证 |
| 检查后改变原件字节/文件集合 | API/CLI409 preflight_stale；UI明确选择过期历史ID也409；没有任务/绑定 |
| 修改已存报告正文 | 不信任被伪改的状态，重算后409 preflight_stale，审计存在 |
| 篡改历史快照/原件后完整备份 | 明确拒绝；仅撤回试验注入后恢复正常，未删除任何历史行 |
| 显式重建可核历史 | 两报告和旧运行引用保留，标reconstructed及reconstructed_match；再次备份成功 |
| 无法重建的历史 | 保留原报告及具体原因，命令非零，完整备份拒绝；不静默跳过 |
| 合格合成正例与恢复后UI | 图、候选、四原始记录、下载及只读角色通过；所有浏览器报告 `page_errors=[]` |

两份历史预检ID和快照SHA、成功run ID见顺序结果；截图：[历史报告](validation-round16-supplement/two-history-reports.png)、[过期预检拒绝](validation-round16-supplement/stale-preflight-refused.png)、[恢复后四证据](validation-round16-supplement/restored-four-evidence.png)。

本地 Go全包、43项备份测试通过，日志在同目录。007在同一真实数据库重复应用成功；完整CI继续运行受影响数据库/服务、现有隔离故障、备份和普通点击回归。最终提交的16项完整CI必须全部成功，才关闭本补验收；不能以本地结果代替。

## 错误契约与复现

OpenAPI 0.2.0、预登记计划和实际接口统一：非法来源400 `invalid_source_kind`；无预检422 `preflight_required`；不完整422 `preflight_incomplete`；冲突409 `batch_conflict`；映射/时间不足422 `insufficient_basis`；输入/快照/报告改变409 `preflight_stale`。V3写客户端须增加预检ID，旧V1/V2不变。

构建前端并准备既有依赖后，一条命令运行旧有效链路及新增顺序/浏览器补验收：

```sh
CPAG_PYTHON="$PWD/.venv/bin/python" \
PLAYWRIGHT_MODULE=/absolute/path/node_modules/playwright \
bash scripts/validation/round16_acceptance.sh /absolute/private/new-r16-supplement
```

`round16_supplement.py --output NEWDIR --serve` 可单独保留隔离环境供浏览器检查；私有state/config/dump不得上传，只有public报告可公开。测试自动清理自建进程/容器。本地因iCloud重新下载导致缓存短读，重装锁定依赖并重建前端；完整本地回归复用未改动计算核心的现有镜像，ID记录在 `local-image-reused.txt`。CI默认始终重建镜像，不通过该本地选项降低远端验收。

## 更新后的第十六轮逐项状态

1. 正式入口浏览器全链：补验收通过，新增历史预检选择和查看。
2. UI/API/CLI同语义：补验收通过，新增有效预检引用及具体拒绝原因。
3. 上传/变更/冲突/缺元数据/中断/超限：原有效证据保留并复跑；新增操作顺序及非法来源400通过。
4. 配置版本：原有效版本运行回归通过，追加版本不改旧报告和运行。
5. 单源及跨源限制：修复后通过，真实来源仍接收未核验；synthetic不能绕过材料门禁。
6. 权限/审计：原三角色回归通过；本轮拒绝无job/binding并有具体原因审计。
7. 终态成套备份恢复：修复后通过；两份历史报告跨补传、空库及新目录恢复，不再只测静态目录。
8. 契约/集成/浏览器/完整CI：本地通过；最终CI结果与最终SHA一起交付，失败不得关闭。

M4/R09—R10补齐本轮限定的预检与运行一致性；R13补充历史输入快照的完整恢复证据；R03补充公开请求和备份格式版本契约，R06补充历史配置引用。M0—M6其他原范围及R01—R13整体状态沿首版清单，仍不得因本次修复宣称整个工作包或整体重构完成。

剩余**软件工作**仍在R17—R22（解析/规则、顺序回放、评估、综合页面、运维和独立发布验收），本次没有启动。**外部真实材料**仍缺授权同期PCAP/CSV、字段设备映射、时钟依据、独立标注和保留集；**历史实例材料**仍缺约定旧版本实际库/输入/配置/产物。本轮两处软件缺陷没有改列为这些材料缺口。结论只适用于软件实现与合成工程验收。
