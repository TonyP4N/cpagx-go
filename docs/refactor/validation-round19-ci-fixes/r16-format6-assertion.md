# R16 unified-catalog format6 验收修复

中断恢复后检查：没有遗留的本代理 R16、准备验收或相关单元进程。原格式 5 断言仍在，先独立执行源码原样 AST guard，对已成功真实 format6 备份的审计元数据作输入。原断言在 catalog/preparation 均 valid 时抛出 `catalog backup failed`；失败 exit 1、原源码 SHA 和字段结果保留于 `r16-format6-assertion-before.json`，没有重跑产品备份、删除失败或改旧 reader。

修复仅为验收程序及其测试：当前 unified-catalog 明确只接受 format6，要求完整 catalog、源/复制 catalog audit 以及源/复制 preparation audit 全部有效。准备文档 ID 集、原字节 SHA/size、ready_bytes、完整独立来源相等和语义验证执行/复用状态必须与当前准备元数据匹配。空准备集合也必须有显式有效的空审计，不能以缺失字段替代。恢复之后另核 preparation audit 与原 ready 文档身份/字节一致。

`r16-format6-assertion-after.log` 五项手写合同测试通过：空/非空准备、旧/未知版本拒绝、缺失/失败审计、非终态/部分/错误摘要拒绝、恢复摘要比对。`r16-format6-real-metadata-after.json` 对受控保留的真实六份原/恢复文档元数据重新检查，修复后接受；这是 guard 复核，不是新服务或浏览器回归。

检查 `scripts/validation` 及工作流中的所有 `format_version` 断言：只剩 R16 显式 format6 门及 R19 准备验收显式 format6 断言，没有其他 hardcode5 验收点。历史 format4/5 读取仍由原 backup 版本分派及兼容测试保留；没有将本轮验收改成宽泛 `(5,6)` 放行。实际统一目录/浏览器复验等待父任务安排空闲窗口。
