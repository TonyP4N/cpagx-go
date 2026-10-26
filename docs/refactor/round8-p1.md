# Round 8 P1：数据接收预检验收记录

日期：2026-10-26。范围：R05/R06 的离线接收预检与材料模板。该记录只陈述本次软件检查；没有接收或核查真实工业材料。

## 交付与边界

- `services/analysis/src/cpag_core/intake.py` 提供独立入口 `python -m cpag_core.intake`。输入为 raw 根目录、现有 `DatasetManifest` JSON、批次配置 JSON；每次向新的 raw 外目录写 `report.json` 与 `report.txt`，`--json` 可在标准输出打印同一机器报告。原有默认分析入口未修改。
- `templates/intake/` 给出接收清单、批次配置及操作说明。清单由现有 `DatasetManifest` schema 验证，未建立另一套文件来源记录。
- 文件校验复用 `pipeline.file_hash`，输入指纹复用 `pipeline.fingerprint`。规范化输入指纹是对已核验文件的 `{kind, sha256, size_bytes}` 列表按 `(kind, sha256, size_bytes)` 排序后计算的 SHA256。文件本地路径、清单顺序和运行时间均不参与。双源各一个文件时与现有 pipeline 的角色顺序一致。`intake_config_fingerprint` 只包含批次 ID、显式 synthetic 模式和模板中授权、时间依据、映射字段的声明值；这些值不会在报告中输出，且不能混作分析 profile 的 `config_fingerprint`。
- 检查 `.pcap/.pcapng` 与 `.csv/.xls/.xlsx` 的文件扩展名、路径边界、符号链接、文件存在性、字节数和 SHA256。不会解析、下载、解压或修改 raw；不会调用双源分析入口。
- 报告固定字段包括状态、退出码、源范围、文件计数、输入/配置指纹、错误、材料缺口、时间范围状态、授权状态、对齐状态、下一步及限制。无 run ID、生成时间或绝对路径等易变字段；受限链接、凭据、原始来源与授权引用值不进入报告。原始配置/清单只在受控接收目录保存。

## 验收对照

| 计划条件 | 软件结果 | 证据 |
|---|---|---|
| 1. 完整包及五类负例 | 完整合成包可进入人工核查；缺文件 11、哈希/大小不符 12、越界/符号链接 13、冲突批次 14、不支持格式 15。无效清单/配置 16，输出位置冲突 17。错误报告均为 `invalid`，不发 `ready`。 | `tests/intake/test_intake.py` |
| 2. 来源、版本、授权、时间、映射缺口 | 空来源/版本及授权、时间、映射三类分别列出；非有限 JSON 配置拒绝并产出报告。即使声明齐全，授权仍为 `requires_manual_review`，时间范围为 `unknown`，双源对齐为 `not_verified`。 | 同上 |
| 3. 单源 | 返回 `single_source_review` 和退出码 2，仅提示核查到位的来源；不提交空源给现有执行入口。 | 同上 |
| 4. 输入内容及保密 | 合成原始文件、清单和配置在三次 CLI 运行前后 SHA256 相同；报告及标准输出不含测试凭据和受限链接。文件存在不被解释为取得授权。 | 同上 |
| 5. 分离及确定性 | 合成测试使用临时 raw 与独立报告目录；配置必须显式声明 synthetic 且与清单一致，真实材料应放独立受控 raw 根目录。同输入/配置三次报告完全一致。路径/清单顺序不改变输入指纹，配置声明变更会改变接收配置指纹。 | 同上 |

## 实际测试与剩余事项

`PYTHONPATH=services/analysis/src .venv/bin/python -m unittest discover -s tests/intake -v`：**8 passed**。`git diff --check`：通过。共享契约测试中原有固定 schema 数量断言已由总集成核查调整；P1 未修改既有 schema 或默认入口。

尚待材料核查：真实文件授权、字段及单位、设备映射有效期、时钟证据、实际文件内容格式、正常/攻击区间与独立标注。预检成功只允许进入人工接收核查；M2 双源解析/对齐及 M3/M5 真实验收继续受阻。真实材料不得进入公开 Git/CI。
