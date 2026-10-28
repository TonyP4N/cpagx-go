# 外层契约修复后的实际核心复验

修复运行版本为`5d87429b75ced66b5ad63f45b74d6f77ab2cf0be`；镜像`sha256:082c4c6c9317bdc29303b98ef4feab9e2d24d17fc1aa501cf0d5c397ddbc5e8a`。83件core/schema逐文件核对，与56矩阵仅`contracts.py`和`CompactStoreRunManifest.schema.json`不同；未改变规则、窗口、输入或存储编码。镜像采用原dev4基底，仅复制这两件文件。见[镜像绑定](validation-round19-core-contract-fix/image-binding.json)与[实际记录](validation-round19-core-contract-fix/actual-regression.json)。

- **S100离线新产物完整链路通过**：导出、独立来源重建、所有所选操作原始引用分页、完整字节交接、新进程交接后读取，controller37.798秒。使用同一S6原件/配置与4CPU/8GiB/4GiB/1800秒/1GiB限制，新的采样器版本2。与56旧S产物全部业务逻辑根、事件/图摘要和计数完全相同，无字段删除或ID豁免。
- **旧M1000产物兼容读取通过**：复制原完整artifact，不修改内容；新镜像完整source核验233.650秒、查询阶段4.718秒、全流程238.916秒。首个操作166/166引用分页原始字节核对，原受控目录及副本前后所有artifact字节摘要均未改变。不是重新导出，不计作新的M容量完整运行。
- **未验证边界仍保留**：本次未重跑5d版本全部S/M/L矩阵；56版本的回放/大规模失败不因schema修复变成通过。大于512GiB逻辑根的完整业务来源导出/核验/查询尚未实跑，schema数值边界与底层共享节点测试不能替代容量验证。

复现先按冻结记录构建新镜像，再在新目录执行：

```sh
PYTHONPATH=services/analysis/src:scripts/validation .venv/bin/python scripts/validation/round19_core_matrix.py \
  --scale S --mode offline --fixture /absolute/path/to/S6-fixture \
  --profile /absolute/path/to/S6-fixture/offline-profile.json \
  --image sha256:082c4c6c9317bdc29303b98ef4feab9e2d24d17fc1aa501cf0d5c397ddbc5e8a \
  --scratch-root /private/tmp/r19-new-S-attempt --output /absolute/new/output-S
PYTHONPATH=services/analysis/src:scripts/validation .venv/bin/python scripts/validation/round19_core_contract_readback.py \
  --source /absolute/path/to/old-M-attempt --output /private/tmp/r19-new-M-readback \
  --image sha256:082c4c6c9317bdc29303b98ef4feab9e2d24d17fc1aa501cf0d5c397ddbc5e8a
```

路径必须为新目录；保持逐项串行，失败不覆盖。镜像ID为本地不可变身份，不是公开下载地址。只读兼容脚本保留能力在内存/私有stdin，不写凭据。以上均为开发核心验证，不是正式Worker/数据库恢复/工业数据验收。

原56已封存外清单的最大逻辑根声明分别为S离线168329190B、S回放16326764034B、M离线2563787148B，均低于旧512GiB上界；这解释为何这些已导出产物不触发此次跨界缺陷。数字为逻辑extent声明，不能当实际平铺写盘字节。M/L未完成的导出没有完整外清单，不能推定其值。
