# P1 接收模板

将 `DatasetManifest.example.json` 复制为清单，并用实际文件的相对路径、字节数和 SHA256 替换示例值；原始文件留在独立 raw 目录。清单沿用已有 `DatasetManifest` 契约，`name` 必须指向 raw 目录内的普通文件。网络文件只接收 `.pcap` / `.pcapng`，工艺文件只接收 `.csv` / `.xls` / `.xlsx`；预检只核对扩展名与字节，不解析内容，也不解压。

将 `batch-config.example.json` 复制为批次配置。其 `dataset_id` 与 `synthetic` 必须等于清单中的同名字段；合成与真实材料分别使用不同的受控 raw 根目录。授权、时间依据和映射条目填本地记录 ID 和声明，不要填访问令牌、受限下载链接或原始材料。预检只检查这些声明是否齐全，不能确认其真实性。时间范围始终标记 `unknown`，双源对齐始终标记 `not_verified`。报告中的 `intake_config_fingerprint` 只表示接收配置，不能当作分析 profile 的 `config_fingerprint`。

运行（输出目录必须尚不存在，且位于 raw 目录之外）：

```sh
PYTHONPATH=services/analysis/src python3 -m cpag_core.intake \
  --raw-root /path/to/raw --manifest /path/to/DatasetManifest.json \
  --config /path/to/batch-config.json --output /path/to/new-report
```

每次生成 `report.json` 和 `report.txt`。`--json` 同时在标准输出打印机器报告。退出码：`0` 可进入人工接收核查；`2` 单源或材料缺口；`11` 缺文件；`12` 哈希/大小不符或读取中变化；`13` 越界、符号链接或非普通文件；`14` 批次冲突或文件名重复；`15` 不支持格式；`16` 清单/配置无效；`17` 输出位置无效。多个错误并存时报告列出全部代码，退出码取固定优先级。

仅一源到位时只可核查该源，不能将空源提交给现有双源分析入口。示例清单只用于合成测试；真实材料及报告应留在受控目录，不进入公开 Git/CI。
