# R19 参考原件库存及单源预算续作（2026-10-28）

依据 [续作预登记](round19-followup-plan-20261028.md)。本页只关闭下述限定的软件子项，
不代表 R19 结项、参考硬件容量验收或真实工业效果验证；未进入 R20。

## 独立参考原件

保留 `evaluation-bundle-1` 的历史读取、匹配策略及“仅声明引用”状态。
显式 `evaluation-bundle-2` 新增 `reference_inventory.json`，在解封前与最终产物、
划分、规则/配置、匹配与明细版本对一同冻结。匹配不按当前默认值重解释历史侧包。

原件由调用方显式指定的受控目录导入；相对文件名不能是绝对路径、包含 `..`、
链接或非普通文件。文件用 no-follow 逐级打开，拒绝硬链接并核对读取前后签名。
每件原始字节最多 8MiB，合计最多 32MiB，最多 256 件；先核声明的 SHA-256，
再以规范 base64 编入按摘要索引的库存。base64 长度必须恰好为 `4*ceil(size/3)`，
单件、合计和解码后字节哈希均检查，不允许隐式截断或不受限扩展。

侧包 v2 的完整 JSON 传输/数据库/备份预算为 128MiB；v1 服务传输/数据库仍为 8MiB，
旧目录读取保留原有逐文件 8MiB 约束。Go 子进程返回信封也有独立有限上限。
新增迁移 `012_v3_evaluation_reference_inventory.sql` 按侧包版本约束 JSON 字节，
未知或缺失版本拒绝；原件随已验证的精确 JSON 序列入既有 `v3_evaluations`，未增加分析挂载。

引用声明中的每个 SHA 必须命中库存；缺少库存、缺件、字节篡改、未知策略版本或摘要不一致
均拒绝。服务先检查数据集/运行授权，未授权请求不读取原件库存。详情、下载和原件查询再次验证
运行 attempt 与侧包，备份审计和恢复复用相同版本与字节校验。

新查询状态 `reference_original_bytes_sha256_verified` **只表示原件字节匹配声明摘要**。
返回的 `record_locator_status` 明确表示记录定位仍是声明，未冒称已解析验证对应行；
`independence_status` 明确表示独立性未经外部证明。哈希不证明标注独立性、保管链或可信时钟。
旧侧包继续返回 `independent_declared_reference_not_original_bytes_verified`。

## 正式链路证据

公开结果：[summary.json](validation-round19-followup/reference-inventory/summary.json)、
[原件结果](validation-round19-followup/reference-inventory/reference-originals-results.json)、
[完整主链结果](validation-round19-followup/reference-inventory/formal-results.json)。

实际使用 `cpag-isolated:r19-s100-dev2`，完整镜像 ID 为
`sha256:a2dfa3af7bfbc78054d0d4e8bbcc6867b85a4f7a9f72656a4211790b05c808ed`。
七项原回放任务主链及附加离线任务通过；六个已存评估产生十二条原始/恢复后检查，覆盖离线与回放。
完整 PostgreSQL 备份恢复到空库及新目录后，结果、历史证据和参考原件仍可查询。
外部受控参考文件在导入后已删除，恢复不依赖旧目录。

|场景|实际结果|
|---|---|
|正确原件字节|查询返回字节、大小与 SHA，重新解码核对通过|
|缺失/篡改原件库存导入|均 409 拒绝|
|未授权参考原件读取|404；单元测试另确认未进入运行/原件读取|
|获得数据集读取权限后|200，返回核过哈希的原件|
|viewer 导入|403|
|重复导入|同一个评估 ID|
|空库、新目录恢复|全部原件检查通过，字节摘要相同|

失败未删除：正式 run1 记录了开发中间态 Go 构建错误；run2 记录了验收脚本的局部变量遮蔽，
修复后 run3 完整通过。原始失败日志在同一公开证据目录。
恢复 Go 测试最初使用 macOS `/var` 别名，被既有禁止符号链接的根路径校验拒绝；
测试统一为真实根目录后通过，生产校验未放松。
[修复前](validation-round19-followup/reference-restore-before.log)与
[修复后](validation-round19-followup/reference-restore-after.log)均保留。
只复制公开记录；已用临时配置中的五个不同私有值做精确扫描，未发现泄漏，私有配置不入库。

## 单源容量联动

`single_source_export.py` 已贯穿 `resolve_capacity_profile`/`parser_limits`：
输入文件数、每件/合计网络字节、工艺字节/逻辑记录/列数、配置字节、网络解析/流重组、
原件查询和总输出按显式版本取预算。省略容量配置仍执行旧限制；新配置指纹包含容量版本。
没有更改双源核心函数、Worker 或旧分析版本语义。

新增三项测试实际导出/验证 1001 条工艺记录且完整保留，旧配置明确拒绝且不留半产物；
检验 64MiB 单件/128MiB 合计网络、8MiB CSV 字节守卫与 +1 拒绝，以及配置、输出预算；
小例在新旧容量下的观察预测和原始证据数量相同。
字节边界守卫测试使用稀疏文件，仅证明预算守卫，不冒称最大规模完整解析或性能通过。
[单源测试记录](validation-round19-followup/single-source-capacity-tests.log)；
既有九项单源导出、查询、历史合同测试继续通过。

Go 的评估投影端点按运行冻结的资源版本和当前服务许可选择预算：旧资源仍为 8MiB，
显式 `r19-dev-s100-1`/`engineering-capacity-1` 为 128MiB。
评估服务的十秒超时没有调大；大产物在此时限内可投影/查询仍需另行实测。
