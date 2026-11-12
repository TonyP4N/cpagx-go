# 固定阶段代码 S100 离线完整链路：一次开发验证

运行代码：`64c69fd8e932a14114b9da25c3c837cfd628f272`，从该提交创建隔离的只读验收 checkout，不使用正在开发的 capacity2 工作区。镜像 `sha256:7a142df1aee0229257ca2792152ed21b9903eff6c61a7c2eeb77895ba00216e8`。

本次仅一次离线 S100：100 请求、100 响应、100 工艺记录，正式 PostgreSQL、Go API、隔离 Worker，无自动重试，attempt1 发布；原始输入与配置指纹见 `public-summary.json`。资源为显式 engineering-capacity-1：4 CPU 配额、8 GiB 容器内存、4 GiB 临时目录、1 GiB 输出限制。宿主为 macOS/arm64 Docker 开发环境，不是 Ubuntu 参考环境，也不是旧 256 MiB 默认资源验证。

- 正式提交至终态 67.980 秒；提交、完整验证、原始证据查询、评估准备/冻结/保存/下载/参考定位共 132.168 秒。
- 计算进程 26.062 秒、用户 CPU 25.006 秒、系统 CPU 0.923 秒、进程 RSS 高水位 65,179,648 字节。CPU 配额不是累计 CPU 时间；进程 RSS不等于容器总内存或 tmpfs。
- 全产物 398,588,746 字节；独立手写时序规则生成的金标199事件，实际匹配199/0/0。候选不是攻击或因果金标。
- 停写后完整数据库与文件备份，空数据库、新目录恢复耗时另计124.284秒；任务/attempt/catalog/文件清单一致，准备文档原ID/版本/字节和原始证据均可查询。恢复不重新POST准备。
- HTTP 每次完整响应耗时见两份 http-measurements.jsonl；应用进程重启冷读与热读单列，OS冷缓存未验证。原件同大小篡改、缺失均拒绝，复原后查询恢复。
- `independent-restored-fragment-postcheck.json` 是对保存的真实HTTP响应补做的原始片段独立核验：解码字节、SHA、长度与独立参考CSV切片相等，未修改原试验记录。后续脚本已把断言内置。

本证据不替代最终运行版本离线/回放各三次，不替代M/L矩阵、两实际Worker竞争或参考环境容量验收。完整受控原始目录为 outputs/cpag-r19-64c69fd-offline-run1；公开文件只脱敏个人路径，原/公开SHA见publication-record.json，未公开SQL、会话、凭据。
