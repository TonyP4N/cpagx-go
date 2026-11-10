# R17 服务预登记场景

基线 6897707；沿用 R16 不可变预检、目录版本、ACL、M4 状态机与隔离 Worker。默认入口及 RC1 不变。本记录先于实现登记，不以生成样例证明真实现场正确性。

预期答案：

1. 旧 synthetic scalar 输入、旧 payload、11 件导出、历史预检/运行均保持只读可校验；单件路径不重写历史身份。
2. 新 bounded-real-capable-v1 配置允许明确 synthetic:false 的有限解析；来源声明与 accepted_unvalidated 保持，图/事件/结果旗标不得伪装 synthetic:true 或宣称现场核验。
3. 单次 1–4 件网络原件和一件 CSV；运行绑定按文件 ID 稳定顺序固定全部原件及其 SHA；跨件解析由既有核心完成。第五件、错误哈希、重复引用、未知字段/版本均拒绝；上传成功不等于可运行。
4. 缺 source/batch/authorization、映射/时间依据或配置与来源类别不符：直接 API 必须拒绝，无新 job/binding；viewer/无权限拒绝。预检后补传、改字节、改报告、改配置仍按 R16 current-preflight 门禁拒绝。
5. 新隔离 Worker 逐件校验、只读挂载全部网络原件；正式结果发布和证据查询按文件 SHA 与帧号共同定位，不因另一文件同帧号串证据。保留全部原件、manifest inventory、ordered hashes，任何遗漏或篡改拒绝发布/读取/备份。
6. 不增加任务状态、协议或关联算法，不进入 R18。限额失败明确失败且无可信半产物；最终容量性能仍须 R19 独立验收。

服务契约：payload.network 保留第一件；多件时 payload.networks 为包含第一件的完整有序 Ref 列表。v3_run_bindings.network_file_ids 为多件完整 ID 数组，null 只表示历史/单件 scalar。发布 manifest.networks 为可选完整有序 SHA 数组。原件导出 primary network.pcap，第二至四件 network-001.pcap 至 network-003.pcap。
