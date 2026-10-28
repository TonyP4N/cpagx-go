# R19 CSV 参考记录定位续作

## 版本与边界

`evaluation-bundle-3` 显式冻结 `csv-logical-record-1`。v3 引用包含原件 SHA-256、从 1 起计的数据逻辑记录号和必要列名，表头不计入数据记录。未知版本、记录不存在/越界、缺列、坏 CSV、文件身份不一致均拒绝，evaluate 和 verify 即核验全部引用。query 返回精确原字节片段、offset/size/sha/base64、物理行范围、必要列解析值及原表头片段；引号中的 CRLF 不拆成另一条记录，末尾无换行不补换行。

首版固定 UTF-8（允许文件开头 BOM）、逗号、双引号与双写转义、LF/CRLF；不猜格式。原件须 `.csv`，完整扫描包含目标之后的记录；重复/空表头、记录宽度错、NUL、非 UTF-8 拒绝。文件仍为每件 8 MiB、库存合计 32 MiB、最多 256 件；必要列/表头最多 1024 列，列名最多 4096 字符，数据逻辑记录最多 1,000,000。没有提高历史输入或原件预算。引用同一文件只扫描一次，验证不复制全部记录片段；查询只提取目标记录。

定位成功状态为 `reference_original_csv_record_verified` / `csv_logical_record_resolved`。这证明字节身份及 CSV 位置，不证明标注语义正确、独立性或保管链。v1 仍仅声明，v2 仍是原件字节已核验、自由文本 `record` 未解析；任何旧包都不自动升级。

## 独立复现及测试

原复核目录没有修改。原样复现输出位于 `validation-round19-record-locator/original-probe-before.json`，保留三行 CSV 的 `row:999999` 在旧 v2 被接受、返回未解析定位状态这一事实。新版本用显式结构化 locator 拒绝同类越界；测试还修复外层引用和结果摘要，避免仅因旧摘要不一致而通过负例。

- `locator-first-tests.log`：10 项手写 CSV/片段独立预期通过；包括 CRLF、带引号换行/双写引号、BOM、末行边界、坏记录之后仍拒绝、字段超过标准库默认 128 KiB、同大小篡改、一次扫描及独立 JSON Schema 验证器比对。
- `evaluation-regression.log`：当次工作源码 90 项 evaluation 测试通过，16.509 秒。后续父任务服务性能路径另有变更，最终集成身份另行记录。
- `go-first-tests.log`：最初因系统 Go 缓存写入权限受限未启动，保留原记录。`go-first-tests-retry.log`、`go-locator-tests.log` 使用可写缓存后通过。Go catalog 单元使用模拟数据库，覆盖 v2/v3 权限先拒绝、原件查询、精确 JSON 保留、新目录恢复及重哈希越界引用拒绝；不把这些单元测试称为真实空库恢复。

## 正式服务小例

`round19_evaluation_acceptance.py` 默认仍跑 v2，新增显式 `--bundle-version evaluation-bundle-3`。原独立手写预期表先序列化成 CRLF CSV，第一条注释含引号和换行；预测从最终产物投影产生，不用标注选择。错误 locator 只修改引用，不修改原分析；保留既有标签变更后的 TP/FP/FN 预期。

首次正式输出目录为工作区外层 `outputs/cpag-r19-record-locator-formal-attempt1`。本次固定旧 Worker 镜像 `cpag-isolated:spool-final-1` 仅负责既有分析产物，v3 定位与保存/查询在新宿主服务执行，不能称为新版镜像完整运行。限定定位源码清单在 `locator-source-before-formal.json`；父任务并行修改服务性能内部复用，故此记录不是整个仓库的固定运行时身份。正式运行 exit 0 / `status=passed`；7 个 replay 任务加额外 1 个 offline 任务，6 个独立评估包在原环境及恢复后共 12 次查询均定位成功。完整 PG 备份/空库恢复的 catalog、任务元数据、attempt 历史、文件库存均相等，恢复会话已撤销。未授权读 404、授权读 200、viewer 写 403；缺失/同大小篡改和 4 类重哈希错误定位导入均 409，恢复后重哈希越界导入仍 409。公开原始结果及二进制 SHA 在 `validation-round19-record-locator/formal-attempt1-public/`。本轮尚未包含其后新增的 014 准备表，准备库存备份另行补验。

## 引用合同示例

```json
{
  "manual-operation": {
    "source_ref": "controlled independent review CSV",
    "sha256": "<64 lowercase hex characters>",
    "locator": {
      "version": "csv-logical-record-1",
      "file_sha256": "<same original file SHA-256>",
      "record_number": 1,
      "columns": ["event_id", "kind", "asset", "time"]
    }
  }
}
```

示例中的角括号是文档占位，真实合同只接受 64 位小写十六进制 SHA。原件库存随 freeze 固定，独立标注及结构化引用在 holdout 开放后由 evaluate 输入；locator 不进入分析，也不读取预测来猜测记录号。`record_number=1` 指第一条数据逻辑记录，不能指 CSV 表头，也不能用自由文本 `row:1` 替代。
