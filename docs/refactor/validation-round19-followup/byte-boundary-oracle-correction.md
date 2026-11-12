# 字节边界夹具预期修正（首次失败保留）

首次 `byte-boundary-core-first.log` 实际保留2网络事件、10000工艺观测、1操作、1变化，另有1条候选。原手写预期“0候选”错误地把额外不支持的以太网帧视为时钟/映射无效，混淆了已有语义。

依据未改变的 `dual_source._analyze_prepared`：请求/响应的时钟和唯一映射有效，工艺变化满足窗口，额外不支持记录加入 `unsupported_network_records_present` 未知原因；该原因不等于R17明确禁止关联的响应时钟失效。正确预期是 **1条unknown候选、hypothetical Claim且未知原因明确，不得为supported_candidate，不得表示攻击/因果/物理成功**。这不是降低原时间质量门禁，也不修改关联算法。

首次夹具和oracle文件保留 `/tmp/cpag-r19-byte-boundary-20261028-1`，本目录 `byte-boundary-oracle.json`、`byte-boundary-core-first.log` 不覆盖。修正先记录于本文，再运行第二份独立夹具和预期；仍独立逐项断言事件/变化/候选状态，不能从算法返回结果生成gold。字节占用帧不计作协议事件或协议覆盖。
