# 网页证据联动与顺序回放骨架

前置：TCP关闭、历史attempt、实际隔离发布及抓包成套恢复已有通过记录后实施。独立启用，不修改默认网页或执行器。

## 最小网页证据

`cpag_core.evidence_web`仅监听127.0.0.1，启动参数固定产物和抓包目录；HTTP不接受文件路径，不上传数据，不持有数据库或Worker令牌。图节点和协议关联两端可点击进入事件，再选择字段，显示所有贡献原帧（含重传）、原字节、字段片段、绝对偏移和SHA256。每次请求重核产物哈希、原抓包与语义解码；缺失/篡改返回409，不能展示旧结果为成功。多请求响应按选中版本保护，避免旧响应覆盖新选择。

```sh
PYTHONPATH=services/analysis/src python3 -m cpag_core.evidence_web --enable-evidence-viewer --output docs/refactor/validation-round5/packet-job-demo/artifacts --network docs/refactor/validation-round5/packet-job-demo/inputs/synthetic.pcap --port 18100
```

实际浏览器验证：请求节点 → cip.path显示frame1；切换encapsulation.context显示frame2、3重传证据及相同字段哈希。截图 `validation-round5/evidence-web.png`。两个HTTP测试覆盖图→事件→字段→帧、篡改拒绝和任意路径拒绝。这是本地合成证据查看入口，不是已集成的正式用户鉴权、任务目录与双源时间线。

## 顺序回放骨架

`cpag_core.replay.ReplayWindow`按调用者明确提供的available_at逐条接收已到达事件；不会读取数据集后缀、重排整份输入或预读下一条。只接受synthetic=true标准事件，不以raw capture ticks伪造对齐时间。window/max_events/max_bytes共同限制保留状态；空时间、未来时间、窗口外事件、容量超限和身份冲突都返回明确状态。窗口内迟到事件产生新revision，旧快照保持不变；advance推动时钟并清理过期事件。

五项测试覆盖前缀稳定/不可变快照、迟到修订、过期和未来时间、空时间、条数/字节边界、重复/冲突、非法时钟与真实数据拒绝。

这是输入到窗口状态的骨架，不是完整replay评估器：尚无迟到水位最终确认、关联规则重算、持久checkpoint、回放任务API、独立测试划分、1倍速积压与工业效果报告。M5/R12仅由未开始推进至部分完成。
