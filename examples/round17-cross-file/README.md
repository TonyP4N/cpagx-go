# 跨文件合成离线示例

本例所有字节、采样、时钟、映射与阈值均为生成夹具，不含真实工业材料。预先答案：两条网络事件（请求/成功响应）、一次采样0→1变化、一条符合配置的候选关联；候选含两份原抓包各第1帧及CSV第2、3条逻辑记录，共四条原始证据。不得得出物理执行、因果或攻击结论。

仓库根目录执行（输出目录须不存在）：

```sh
PYTHONPATH=services/analysis/src .venv/bin/python -m cpag_core --dual-source \
  --network examples/round17-cross-file/capture-1.pcap \
  --network examples/round17-cross-file/capture-2.pcap \
  --process examples/round17-cross-file/process.csv \
  --profile examples/round17-cross-file/profile.json \
  --output /tmp/cpag-r17-example
```

正式Go/隔离Worker与空库恢复、浏览器命令见 `docs/refactor/round17-operations.md`；解析必须使用同样的抓包顺序和版本配置。工艺规则结果包含支持、反证及未知，不把所有规则输出视为异常。
