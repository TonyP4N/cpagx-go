# 第十九轮阶段记录：独立评估已接通，容量退出条件未通过

**本轮未关闭，不进入R20。** 基线为`b0c627be2914fbf6958feb8dbe77ffd7c5f688fb`，分支`refactor/m1-evidence-core`。保留RC1、默认入口和旧产物版本语义。性能参考环境缺失经用户确认保留待办；容量软件扩展未完成另列，不能合并成“待真实数据”。

## 分阶段提交

- `402d0b0bc253e124d2b7bd7fba7d33d746dde851`：实现前预登记场景、统计口径及候选容量。
- `6a3d71b`：最终产物适配、详细独立指标、真实单源CLI和冻结侧包。
- `768d3d4`：Go授权服务、持久评估、格式5恢复、多抓包预留修复。
- 最终阶段提交：容量记录器、全部失败公开摘要、受影响回归和本报告。准确完整SHA/CI以该提交Git记录、Actions head SHA及交付汇报为准；报告不使用先前绿灯替代最终CI。

## 逐项门禁

|用户验收项|预期/实际|证据及状态|
|---|---|---|
|1 最终产物适配与统计|只读取校验后保留的离线/回放终态；请求观测与工艺变化分别计数；回放ID去重；候选只列未标注关系，首次出现/撤回另列；无路径gold则不可用|`evaluation_artifacts.py`及11个适配回归。已实现并合成验证；区间上界投影丢失区间分辨率，不宣称动作时刻。|
|2 独立手算|P01=TP1/FP1/FN1；容差1边界包含；重复预测TP1/FP1；增广匹配TP2；无预测漏检；争议并集正常40分钟；零分母null+原因|`test_round19_details.py`14项及原评估回归；答案人工预写。通过。|
|3 独立性与冻结|不把标签传入适配器/分析器；版本、划分、匹配和输入绑定；实际观察冻结完成时间必须早于解封；修改标签改变评估而非分析|本地56评估回归、正式三次语义哈希一致；标签修改例TP1/FP1/FN1，其余TP2/FP0/FN0。冻结文件与本机时间不构成外部保管链证明。声明来源/审核仍未独立证实。|
|4 三种模式|网络CLI只读网络、工艺CLI只读CSV、双源原核心；共同定义逐类对比|`test_single_source_export.py`9项，删除另一源并禁止其解析器/索引仍完成；共同独立小例与双源同类预测相同。CLI支持；尚无正式单源Worker任务类型，不冒充已有。|
|5 绑定、错误证据、服务/恢复|run/attempt、版本/规则/配置、输入/标注/划分/匹配完整绑定；预测查询原帧/CSV；FN查询独立参考定位；服务ACL/受控下载；PG与文件成套恢复|`evaluation_bundle.py`、`internal/catalog/evaluation*.go`、迁移010、`scripts/backup/bundle.py`。本地正式离线与回放导入、空库新目录恢复共12次查询成功；无授权404、viewer写入403、授权读取200、重复导入同ID，见formal-attempt2。外部gold原件仅有引用声明，未自动取回并验证其字节，明确显示未验证。|
|6 容量目标|4抓包/单件64MiB/合计128MiB，CSV8MiB/10000行/16列，全站1活动attempt|**未通过**。未修改当前运行限额；S100三attempt OOM，需版本化预算、增量/索引和历史存储优化；全站活动attempt约束需并发测试。|
|7 全链路性能|参考8vCPU/16GiB/SSD，每规模每模式3次，全部阶段/RSS/CPU/磁盘/查询/积压|**未通过**。参考环境用户明确暂缺；本机aarch64 Docker约8GiB只能开发记录。已保存S100失败110.603秒及环境/资源/镜像，未测项为null，未伪造阶段耗时。|
|8 既有回归与CI|R16补传/门禁/恢复、R17时间/历史、R18前缀/迟到/取消重跑/原件保持；新增接入CI|受影响Python/Go本地通过；原完整CI工作流保留并新增R19正式评估恢复与容量工具回归。最终同SHA CI为交付门禁；不替代参考环境测量。|

## 修复前失败与修复

1. 多抓包宿主容量账本只算第一件网络文件：独立算术回归复现4个失败；修复使用校验后的完整`network_refs`。重复预留不加倍，后续原件缺失与预算不足均拒绝。`capacity-reservation-before.log` / `after.log`。
2. 本轮新冻结侧包独立复核发现：冻结耗时跨解封边界、导入未检查完整时间顺序、重哈希后缺失参考可接受、声明字段可被改写。先保留12个失败子例，再统一校验字段/版本/摘要/时间、创建与导入共用参考校验，跨解封发布清理自己的新输出。`bundle-audit-before.log` / `after.log`。未改历史R18产物。
3. 新备份格式5测试首次仍期待4：`backup-first.log`保留；迁移010新增评估数据，测试更新为明确5，另增旧格式4无评估表兼容测试。不得将旧包改号冒充5。
4. S生成器首次回放缓冲3600超过旧schema300：原始样例attempt1保留；修为300，attempt2和schema测试通过。该错误未用于回放成功声明。
5. 预登记文档提交的isolated-executor CI首次失败为镜像远端层not found，发生在计算启动前；日志摘录`prereg-ci-image-failure.log`保留，不当作代码语义失败，也不以重试成功抹去。
6. S100实际OOM：三次失败/停止检查保留，尚未修复并达到容量目标；不是已关闭缺陷。

## 数据与权限

`GET /api/v3/runs/{id}/evaluation-input?projection=network|process|dual`取得服务端绑定的预测输入；投影视图不等于真实单源运行。
`POST /api/v3/runs/{id}/evaluations`导入完整已验证CLI侧包JSON；按run/文档SHA幂等；只读者拒绝写入。
`GET /api/v3/runs/{id}/evaluations/{evaluation}`、`/download`、`/evidence?event=ID[&reference=true]`每次重新核对当前发布与证据。没有权限隐藏存在性；修改原件/文档/绑定拒绝。JSONB另存精确JSON文本，避免数据库数值表示改变Python指纹。

迁移010后新终态备份格式5包含所有评估与原输入/产物。恢复格式4按旧表集校验；新源库须完成010后使用当前备份工具。旧部署/默认入口未迁移。外部标注留在控制侧数据库与独立侧包，不加入分析payload或容器输入。

## 复现命令

先准备Python验证依赖、Go、Node静态导出、Docker；容量参考门禁不会把本机冒充目标环境。

```sh
PYTHONPATH=services/analysis/src .venv/bin/python -m unittest discover -s tests/evaluation -v
PYTHONPATH=services/analysis/src .venv/bin/python -m unittest discover -s tests/backup -v
PYTHONPATH=services/analysis/src:services/worker .venv/bin/python -m unittest discover -s tests/isolated -v
.venv/bin/python -m unittest discover -s tests/validation -p 'test_round19*.py' -v
docker build -t cpag-isolated:r18-acceptance -f deployments/isolated-executor/Dockerfile .
.venv/bin/python scripts/validation/round19_evaluation_acceptance.py --output /tmp/cpag-r19-fresh
.venv/bin/python scripts/validation/round19_capacity.py --output /tmp/cpag-r19-reference-probe --probe-only
.venv/bin/python scripts/validation/round19_scale_fixture.py --scale S --output /tmp/cpag-r19-S
```

输出必须为全新目录，首次失败不覆盖。当前完整操作与冻结命令见`round19-evaluation-operations.md`；容量开发命令和原始私有证据位置见`round19-capacity-audit.md`。私有目录含临时凭据与数据库备份，仓库只收白名单公开证据；公开摘要不是删除失败原件。

## 三类剩余项与原方案状态

**软件未完成**：版本化128MiB/10000记录全链路扩容；解析/前缀判断/历史存储和查询成本优化；新资源profile和全站并发约束；阶段CPU/RSS等仪表；每侧500事件的评估容量扩展；更大规模一对一匹配成本验证；外部gold原件自动读取/哈希验证。独立单源正式任务入口尚无（本轮CLI比较已实现）。这些不能写成“缺真实数据”。

**外部验证环境**：Ubuntu24.04 x86_64 8vCPU/16GiB SSD及可用磁盘、容器镜像/内核固定记录。已获用户确认当前无此环境，参考容量验收待办。

**真实材料**：同期授权PCAP/工艺CSV小片段、来源批次授权、字段单位/设备映射、时区同步漂移依据、独立正常/攻击参考、保留集与审核记录。真实历史实例另需旧运行配置、原件、产物和版本；不合并到容量环境缺口。

M0/M1既有验收保持；M2/M4/M5继续部分完成；M3完整界面留R20；M6发布留后续。R01/R02/R04/R05/R06/R07/R11旧状态保持；R03增加独立单源与评估侧包契约；R08最终产物评估、独立手算及错误定位推进但大规模和真实验收未完成；R09/R10增加评估ACL/持久化并保持任务语义；R12增加终态统计适配，容量未完成；R13增加格式5成套恢复与测量记录器，性能退出未满足。软件实现、合成工程、真实验收分开记录，不宣布整体重构或工业验证通过。
