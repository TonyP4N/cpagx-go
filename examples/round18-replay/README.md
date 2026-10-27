# R18 合成双源顺序回放示例

原始抓包字节和CSV由独立夹具构造：请求位于`network.pcap`，响应位于`response.pcap`，工艺从0变为1。仅作软件机制验证，不是工业材料或真实设备依据。配置固定到达序列、时间/映射/规则版本和资源上限；响应及变化未到达时不得提前可见。

仓库根目录执行（Python 3.11及`services/analysis/requirements-test.txt`依赖）：

```sh
PYTHONPATH=services/analysis/src python -m cpag_core.replay_export \
  --network examples/round18-replay/network.pcap \
  --network examples/round18-replay/response.pcap \
  --process examples/round18-replay/process.csv \
  --profile examples/round18-replay/profile.json \
  --output /tmp/cpag-r18-example
PYTHONPATH=services/analysis/src python -m cpag_core.replay_export \
  --output /tmp/cpag-r18-example --verify
PYTHONPATH=services/analysis/src python -m cpag_core.replay_export \
  --output /tmp/cpag-r18-example --revision 3 --operation first
```

输出目录必须尚不存在。最后命令查询待响应历史快照，只有已到达的请求原件，不可见未来响应。完整修订链在`revisions.jsonl`，快照及标准图在`snapshots.jsonl`；按其中`snapshot_number`查询对应操作或变化。全文件SHA位于最终完整性清单，回放引用使用槽位+原始记录摘要，查询时两层均核验。

当前限额：最多4抓包、合计16MiB/10000帧，CSV2MiB/1000记录/16列，配置64KiB；活动缓冲、11000原始记录账本、4096快照/8192修订及16MiB全部输出另有约束，触及任一上限明确失败。不能据此认定已通过R19容量验收。默认入口及RC1不变，完整回放界面留R20。

实际1x/10x输入计时与全样本保存：

```sh
python scripts/validation/round18_metrics.py --output /tmp/cpag-r18-pacing
```

模拟到达时间与真实墙钟耗时分开；正式任务的run/attempt也不参与语义哈希。候选始终是假设关联，不表示物理执行成功、因果或攻击。
