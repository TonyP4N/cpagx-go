# R18 正式回放主链与浏览器验收

本页对应签名预登记 `cc2db77`，仅验收合成软件工程机制。正式结果见 [主链记录](validation-round18-main/results.json)、[最终API重查](validation-round18-main/graph-trigger-recheck.json)及[普通浏览器记录](validation-round18-main/browser/browser-results.json)；最终提交与准确完整CI由本轮总报告绑定。

## 实际通过

- 七个真实PG/隔离Worker任务：正常同序列三次、响应过期一次、允许迟到一次、实际1倍/10倍节拍各一次。正常三次的snapshots/revisions/analysis/events/graph/metrics/arrivals字节哈希相同，三个场景CLI与API一致。
- 10秒历史仅有请求，pending_response、无响应/未来变化/候选；12秒正常版本产生hypothetical候选，旧pending仍可查询。12秒原始变化13秒才到达时记录late并修订。响应超出时钟有效期保留success协议事实与unknown，禁止候选/图边。
- 每个快照的引用按当时已到达序号检查，不含未来记录或完整file_sha256。pending查询1个网络原件，正常修订操作4个原件，响应过期操作2个网络原件，独立变化查询CSV物理记录3/4。新trigger=true出口分别核查本次到达的1个请求或1个CSV记录，不要求其已形成候选。
- 正常事件总数7/可计算7，响应过期可计算6；候选首次可发表延迟正常2秒、允许迟到3秒。正常候选已就绪时prerequisite_waiting_operations=0而open_window_operations=1，终态open=0；waiting_operations为前者的明确别名。1倍/10倍实际墙钟分别为10.0845秒/1.1058秒，模拟语义哈希相同；完整时延/积压/墙钟样本保留，不视为R19吞吐验收。
- 七任务终态成套备份，空库、新目录恢复后重查历史、原件及下载；只读用户确有read ACL、写入404/not_found且任务数量不变。404为既有不泄露存在性的拒绝语义，不是权限绕过。
- 新Go二次监听器对原source/restore各七任务共14组复核default/指定历史graph的mode/version/内容及trigger原件；不重新生成或改写已有业务产物。
- 最终普通点击从/workspace显式选择回放模式并实际提交新Worker任务；访问/replay切换pending→修订→旧pending、正常→响应过期unknown，点击操作/变化/本次到达原件，下载历史与指标。source、恢复环境、viewer均通过，page_errors为空，共15张实际截图；已目视核对pending、正常修订、unknown及原始记录显示。

## 首次失败与修复

[首次失败目录](validation-round18-main/first-failures/)保留原始事实，不把失败样本从记录中删掉：

1. Worker为synthetic追加--synthetic，但新CLI起初未接收，三个attempt失败。冻结image源码独立复现returncode=2/unrecognized arguments，原件输出不存在；宿主随后清理的Exit137且OOMKilled=false不等于计算OOM。修复CLI显式断言和有界stderr记录后通过，不增加超时。
2. 验收脚本曾硬要求viewer403，实际返回既有404隐藏存在性语义；改为先证实read ACL，再接受既有403/404拒绝并核查无新任务，不修改生产权限。
3. 旧image与新host metrics校验短暂交叉使新UI任务metrics.json语义校验失败；保留该无效环境记录，重建同版本image后复验。
4. 两次浏览器脚本定位问题分别匹配Next空announcer和隐藏JSON中的同名状态。收窄真实运行错误区域及可见article段落，未改产品状态或用force规避；失败报告/截图分别保留，最终完整交互通过。
5. default graph顶层版本丢失与trigger出口缺失均保留修复前/后证据。旧Go对实际pending的trigger查询返回409；新Go对同一历史版本返回200/1原件。

## 镜像与范围说明

七个有效输入任务使用冻结的新metrics计算代码。随后仅ReplayProfile.speed的number类型门禁和replay_export的query_task/main选择器变化；[AST/源差异核查](validation-round18-main/valid-input-image-change-scope.json)确认所有生成函数不变。最终UI提交使用完整当前schema/selector镜像；两套实际源文件SHA清单均保留。最终CI会从最终提交重新构建全部。

早期本地构建复用了共享测试标签cpag-isolated:round5；没有在R18首次build前独立保存其旧绑定，不能猜测恢复或声称该标签从未改变。此前R17日志可证明本会话曾创建该测试标签，但不作为紧接R18之前绑定的证据。正式R18脚本现统一使用独立cpag-isolated:r18-acceptance（可用CPAG_R18_WORKER_IMAGE指定独立标签）；[实际最终镜像ID与标签记录](validation-round18-main/test-image-scope.json)如实保留，不改用户既有服务配置或猜测retag。

最后的来源banner加载态修补仅将尚未取得来源标记时显示为“来源标记加载中，尚未核验”；已加载true/false标签与本页截图不变。浏览器脚本增加已加载合成来源标记断言，最终CI使用新前端构建；本地截图不冒称已检查新的加载瞬间。

所有一次性source/restored/额外API监听器、Worker和数据库已清理。只保存经过私有凭据精确扫描的public记录、受控下载与截图；不保存session/worker配置、cookie、数据库凭据或原始控制receipt。离线R16/R17回归、生命周期故障矩阵、真实数据适用性、R19容量和最终CI分别由总验收报告记录，本页不替代它们。
