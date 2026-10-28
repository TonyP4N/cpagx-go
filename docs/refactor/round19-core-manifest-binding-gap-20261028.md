# 核心运行清单绑定缺口：修复前复现

在39b8b36及当时未修改的shared_export.py上，以全新独立合成小例复现，不修改任何正式测量目录。四种变更分别为offline/replay的synthetic true→false、replay final_snapshot_number→0、final_snapshot_id→合法格式的伪造值。只重写run_manifest.json，artifacts、logical_artifacts及全部已列物理文件字节完全不变。

四个场景的完整source verify均返回被修改的清单；issue_approval均成功签发，批准后的metadata继续返回伪造字段。独立读取的实际analysis.synthetic仍为true；实际history末态编号/ID也与伪造清单不符。2项回归测试内8个“应拒绝”断言全部失败（ValueError not raised），用时2.031秒。运行前后runtime SHA相同；完整记录见validation-round19-core-manifest-binding/。

原因定位：_bound未将清单synthetic绑定保留profile，verify_task重建清单的对照字段遗漏synthetic及终态snapshot编号/ID。此记录不是修复证明。新测试应在修复后转为拒绝，不应修改测试以接受错误批准。

原始小例和日志保留在FYP/outputs/cpag-r19-manifest-binding-reproduction-20261028T145336Z/，公开副本将绝对仓库前缀和artifact路径改成相对表示、清理日志行尾空格以满足Git检查，并记录原/public SHA；原始日志未改。未保存测试批准密钥或批准MAC到公开报告。

既有dev3 producer耗时和产物可保留为测量记录；该旧校验器的批准不能当作本缺口已闭合的证据，需要用修复后的完整校验器重新核验。

## 修复及兼容边界

修复将来源声明与保留配置逐字绑定，终态编号/ID与历史末项绑定；完整来源重建同时比较这些字段。逻辑根清单须完整覆盖store根集合，额外未登记根也拒绝。独立追加根并更新所有物理校验值的首次失败保留于受控 outputs/cpag-r19-extra-root-first.log。

读取许可显式升为core-read-approval-2；v1许可不能沿用，必须重新完整核验。合法旧产物仍可读，不静默重写历史。新增回归覆盖旧许可拒绝、新许可签发、未改产物重新核验，以及上述篡改。修复后独立小例与负例记录见validation-round19-core-independent，dev3仅保留为历史测量，最终矩阵必须绑定新核验器。
