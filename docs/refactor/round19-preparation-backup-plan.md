# R19 准备库存 format6 备份预登记

在已完成 locator 小例后的独立增量。父任务明确同意 format6、真实 bytea、恢复同核验；本轮终态停写快照同时拒绝 queued/preparing，保留 ready/failed 全部真实 attempt。运行源码稳定后再做受影响的小例恢复，不把旧 format5 成功扩成准备库存已验证。

- format4/5 历史 catalog 集合不变；format6 才要求准备主表及 attempt 表。新增迁移 014，不占 locator 的 013。
- 私有 pg_dump 原样保全完整 bytea、owner、错误详情。人读 catalog 投影按字段显式构造，不先序列化 bytea 再删除；只保留 SHA/size、冻结版本/来源/成本与状态，去掉 owner/error_detail/document_bytes。
- 主表/attempt 必须终态一致，准备数/历史连续、单份 8/128 MiB（按原 payload 资源策略）、ready 合计 1 GiB；失败状态不能有部分字节。
- 冻结 snapshot 必须绑定当前 job/attempt/payload/publication/context，逐件核对原始来源和全部产物真实字节；哈希声明本身不替代源验证。
- 从真实 PostgreSQL bytea 每次最多读取 1 MiB，核对原始序列化 SHA/size；离线独立 adapt 验证完整准备对象，相同 run/投影在一次备份中只计算一次。报告执行次数与耗时；不将此离线代价作为 10 秒 HTTP 通过。
- 恢复从私有 dump 进入空库后再次核 bytea 与独立来源对象相等，服务查询仍须权限和当前 publication 检查；恢复会话撤销。工程整包 format6 也做相同准备审计，旧版本流程保持原读取。
- 独立单元覆盖：queued/preparing、同大小原件篡改、缺失/截断 bytea、正确大小错误 bytea SHA、混批/attempt/资源/版本/库存、历史缺口、私有字段泄入、全局超限、分块读取和原始序列化保留。真实准备服务完成后再串行做一次真实 PG/Worker/空库恢复，并保留失败。

实现自审补充：完整准备对象与 payload 身份使用不剥离字段的 canonical JSON SHA-256。`pipeline.fingerprint` 是历史“稳定业务值”指纹，会剥离 `run_id/ingest_time`，不适合此处完整对象相等；该差异的独立复现在 `validation-round19-record-locator/full-identity-audit-reproduction.json`，重哈希错误 run_id 的负例已加入。现有通用 task/catalog 审计仍有其独立完整来源验证，本增量只保证准备文档比较的 adapt 每 run/投影执行一次，不声称整个大备份只重算一次或已通过大型容量预算。

本轮备份单元初次出现的两项失败均保留：历史 format4 测试起初从“当前表集合减一个字段”伪造旧集合，新增表后该构造并非真实历史格式，现用冻结的历史表集合；之后扩展三版本恢复测试时，测试局部 `copy` 函数遮蔽模块名导致 NameError，已改名。`backup-format6-full-identity-unit.log` 最终 66 项通过，7.513 秒。上述均为单元测试，不等于真实准备服务与空库恢复完成。

正式小例脚本为 `scripts/validation/round19_preparation_acceptance.py`。通过显式服务 POST 请求准备 dual，等真实 ready 后才沿用 v3 独立标注与原件保存/查询。停服务后对可丢弃测试库作可恢复的 queued/preparing 和同大小 bytea 篡改负例，验证拒绝并恢复原记录；不会通过 SQL 创造 ready。完整备份恢复后必须直接读到原 ready id/sha/size/attempt，禁止重新 POST 伪装恢复成功；再次执行 v3 原片段查询和准备权限检查。脚本轮询的 90 秒只是后台测试等待上限，不提高服务的 10 秒 HTTP 请求预算。
