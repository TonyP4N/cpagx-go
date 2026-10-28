# 固定DAG6核心验收的复现命令

这些命令只运行核心容器，不启动Go、PostgreSQL、正式Worker或界面。须在本机Docker可用、至少满足开发配额和可用磁盘时执行；不是Ubuntu参考环境资格证明。当前冻结源码与结果见验收报告，不能将失败格子写成支持规模。

当前checkout包含5d外层契约修复，下面使用对应新镜像；不能使用旧56镜像混配新源码，控制器会明确拒绝。报告六格原测量仍绑定56旧镜像，5d只补验S完整链路和旧M读取；此命令允许继续尝试未通过格子，不代表已支持。

## 新目录生成和完整测量

以下循环使用bash或zsh。在仓库根目录使用已有Python环境（3.11或3.12；验收镜像内3.12.12）与Docker。每格独立目录，不覆盖旧输出；三种scale的原PCAP/CSV来自固定生成器，版本6不删响应、不降低密度。

```sh
export PYTHONPATH=services/analysis/src
stamp=$(date +%Y%m%dT%H%M%S)
run_root="../outputs/r19-core-reproduce-$stamp"
mkdir -p "$run_root"
image_id=sha256:082c4c6c9317bdc29303b98ef4feab9e2d24d17fc1aa501cf0d5c397ddbc5e8a
docker image inspect "$image_id" >/dev/null
for scale in S M L; do
  .venv/bin/python scripts/validation/round19_scale_fixture.py \
    --scale "$scale" --version r19-density-capacity-6 \
    --output "$run_root/fixture-$scale"
  for mode in offline replay; do
    if [ "$scale" = L ]; then
      controller=scripts/validation/round19_core_matrix_l.py
      scale_args=()
    else
      controller=scripts/validation/round19_core_matrix.py
      scale_args=(--scale "$scale")
    fi
    .venv/bin/python "$controller" "${scale_args[@]}" \
      --mode "$mode" --image "$image_id" \
      --fixture "$run_root/fixture-$scale" \
      --profile "$run_root/fixture-$scale/$mode-profile.json" \
      --scratch-root "/private/tmp/r19-core-$stamp-$scale-$mode" \
      --output "$run_root/$scale-$mode"
    cell_exit=$?
    printf '%s %s exit=%s\n' "$scale" "$mode" "$cell_exit"
  done
done
```

不可变镜像须已在本地，以上ID不是公开镜像仓库下载地址。代码、基础Python镜像和构建文件的身份在冻结记录中；不同代码/镜像重建须建立新freeze并重跑，不复用旧通过。每格非零退出是实际失败，不自动重试；后续格继续，失败目录与日志保留。全站仅顺序运行一个本测量分析进程，不将此机制当两个正式Worker竞争验收。

## 小例、完整核验和有界读取

```sh
PYTHONPATH=services/analysis/src .venv/bin/python scripts/validation/round19_core_small.py \
  --output "$run_root/independent-small"
PYTHONPATH=services/analysis/src .venv/bin/python -m unittest discover -s tests/core -v
PYTHONPATH=services/analysis/src .venv/bin/python -m unittest discover -s tests/replay -v
PYTHONPATH=services/analysis/src .venv/bin/python -m cpag_core.shared_cli \
  --action verify --root "$run_root/S-offline/result/artifact" \
  --verification-strategy dag6-full-source-merkle-sink-1
PYTHONPATH=services/analysis/src .venv/bin/python -m cpag_core.shared_cli \
  --action evidence --root "$run_root/S-offline/result/artifact" \
  --operation first --ref-offset 0 --ref-limit 100
```

最后一个独立CLI没有读取许可，会重新做完整来源核验，不能把它当已批准后单页10秒指标。矩阵通过继承的私有IPC给各独立读取进程传递内存密钥和当次许可，逐次检查字节而不在日志/文件/参数中保存密钥；其完整核验成本已经计入整链。实际服务集成还须由Go实施用户授权、任务/attempt有效性及许可隔离。

历史大对象使用路径和分页，禁止无界展开：`page --logical-root history/snapshots --path '[0,"graph","edges"]' --offset 0 --limit 100`、`revisions --after 0 --limit 1`。不超过单页上限；完整图或某修订本身过大时明确拒绝，改用更深路径分页，不能截断后标完整。

独立小例/负例可在无Docker时运行，但不代替六格容器配额、CPU/内存/临时盘、交接及完整查询实测。参考Ubuntu、正式链路三次重复和真实工业材料继续分别待验。
