# 第七轮运维交付：容量账本重建与证据丢失处理

基线：`1386a4f`。本项仅处理单机隔离执行器的容量账本与人工恢复流程，不改变默认入口，不增加协议、界面、回放或分析算法。工具不会删除任务文件、停止容器、修改任务状态，也不会补造退出证明。

## 一、适用范围与操作前提

工具入口：`python -m cpag_worker.capacity_rebuild`。不带 `--apply-plan` 时只生成预览，不修改账本。

使用时必须与原执行器保持一致：

- `CPAG_SHARED_ROOT`、`CPAG_CONTROL_ROOT` 的绝对路径；两者不能互相包含。
- Docker daemon/context，以及绑定这两个目录的同一单机范围。
- 同一 Go API，以及原有 `CPAG_WORKER_TOKEN`、`CPAG_COORDINATOR_TOKEN`。
- 同一单次输出上限 `--output-bytes`；默认值为 `16777216`。

先暂停领取任务的 controller，保留 API、PostgreSQL 和 Docker 可读。不要删除锁文件：是否正在占用以 `flock` 为准，不能根据文件是否存在判断。

预览与结果报告必须写到 shared/control 之外，例如安装数据目录下独立的 `audit` 目录。报告中不会保存私密 attempt token。完整配置与数据库备份仍含凭据，按原有权限保存。

本工具只适用于遵守现有 owner→capacity 锁顺序的隔离执行器。它不是针对恶意宿主用户或绕过锁协议的写入者的操作系统级证明。

## 二、先预览、再核对差异

开发检出可设置 `PYTHONPATH=services/worker` 后运行；离线工程包可直接在其 app 镜像内运行，不需要宿主机另装 Python，见后面的免安装示例。

```sh
python -m cpag_worker.capacity_rebuild \
  --root /data/shared --control /data/control \
  --api-url http://127.0.0.1:18115 \
  --output-bytes 16777216 --report /audit/capacity-preview.json
```

重点核对这些字段：

| 字段 | 核对内容 |
|---|---|
| `ledger_before` | 原账本是有效、损坏还是缺失；原始字节摘要与长度 |
| `decisions` | 每个 attempt 的旧预留、新预留、实际保留字节和判断原因 |
| `execution_discovery` | 同 daemon、同 shared/control scope 的数据库执行记录 |
| `unknown_attempts` | 哪些任务/attempt 身份或原预留无法确认 |
| `discovery_unknown` | Docker/API 发现阶段是否不可用 |
| `outside_job_bytes`、`unattributed_job_bytes` | 任务目录之外及尚未归属的实际保留字节 |
| `proposed_ledger` | 拟写入的完整账本，包含保留的 catch-all 预留 |
| `applicable` | 当前证据是否允许应用；为 false 时不得强行绕过 |
| `plan_id` | 本次完整预览的指纹，用于显式确认 |

工具读取实际文件的大小与哈希，并查询任务/attempt 历史和协调器发现 API。发现范围根据 Docker daemon ID 与两个目录的 scope hash 精确匹配。因此，即使本地执行记录和账本同时丢失，数据库仍知道的活跃执行也不会被当成“不存在”。无法归属到当前目录的旧版无 scope 执行记录会阻止应用。

仅当 API 任务已处于 `succeeded`、`failed` 或 `cancelled`，且对应 attempt 已有退出证明时，才允许将该 attempt 预留降为实际保留字节加 64KiB 记账余量。

运行中、排队、取消中、缺少退出证明的 attempt，至少保留原预留及保守增长余量；存在这类保护项或未知项时，旧 catch-all 预留也不会被清空。如果原账本已坏/丢失，同时仍有未证明退出的 attempt，因为无法确认原预留，工具拒绝应用。未知 API 身份、发现服务不可用、未知执行模式或历史范围有歧义，同样保留 pending，不能借“重建”释放空间。

## 三、显式确认并应用

核对预览无误后，把该报告中的完整 `plan_id` 复制到确认参数。`yes` 不能替代指纹。

```sh
python -m cpag_worker.capacity_rebuild \
  --root /data/shared --control /data/control \
  --api-url http://127.0.0.1:18115 --output-bytes 16777216 \
  --apply-plan /audit/capacity-preview.json \
  --confirm REVIEWED_PLAN_ID --report /audit/capacity-applied.json
```

应用时的安全顺序：

1. 先以非阻塞方式取得现有 attempt 的 `owner.lock`，再取得 `capacity.lock`，与执行器顺序一致。锁正在占用就拒绝，不等待形成锁顺序倒置。
2. 重新查询 API/执行发现，重新检查文件、账本与目录命名空间；再次重核后，任何实质变化都会使旧预览失效，必须重做预览。
3. 在 `control/capacity-backups/<唯一编号>/` 保存原账本精确字节、预览和备份清单。原账本不存在时记录“缺失”，不造一个空原文件。
4. 先同步备份文件、备份目录及其父目录，再以 fsync 和原子替换写入新账本。备份与报告文件权限为 0600。

目录遍历遇到权限/读盘错误会抛出，不会静默漏掉目录。符号链接、硬链接、特殊文件、外来 root 账本、不安全目录和并发占用都会被拒绝。

工具保留全部任务与证据文件。备份本身也占空间，后续预览和正常接单会继续计入。重建成功不代表必然有足够空间：如果真实保留数据仍超过预算或最低剩余空间阈值，接单继续拒绝是正确结果。

应用后核对结果哈希与备份，先恢复一个受控任务，再恢复一般接单。发生异常时，不要在已有新任务接单后直接把旧账本覆盖回去，否则可能丢掉新预留。应再次暂停接单，根据当前证据生成新预览。损坏的原 JSON 是审计备份，不是可直接恢复接单的有效账本。

## 四、控制证据与 Docker 事件同时丢失时怎么办

容量重建不能替代“计算确已退出”的证据。按以下顺序处理，不能靠改状态绕过：

1. **先保全。** 暂停新接单；复制剩余 shared/control、API 状态、协调器 attempt 历史、数据库备份、Docker daemon ID、仍可取得的 `ps -a`/inspect、镜像 ID 和外部审计记录。完整历史含私密 token，不要放入公开报告。
2. **再对应身份。** 核对 job、attempt、worker、完整不可变 container ID、daemon/scope、执行 nonce 与 labels。不能用同名新容器或重建后的新 daemon 代替原执行环境。只有来自可信备份且身份匹配的原始证据，才可以恢复到控制目录，并保留原损坏现场。
3. **原容器仍存在。** 在正确 daemon 上，由原有可信协调器重新 inspect、stop/wait、再 inspect 并不可逆 remove，形成正常绑定退出回执。这是重新取得真实证据，不是根据“应该已停”写回执。
4. **原容器已不可见，控制回执和 destroy 事件也都丢了。** Docker 404、PID 查不到、目录空了，都不能单独证明退出。只能恢复可信备份/数据库中原有完整回执，或恢复原 daemon 的可信事件记录。若仍无法确认，已登记执行保持 `cancelling`/pending，不修改 SQL `state`、`exited_at`，不伪造 receipt，也不释放其未证明预留。
5. **有限的未启动例外。** 只有数据库已明确登记为 `isolated-v2`、尚无 registered container 的 attempt，才允许协调器调用既有 `/not-started` 原子撤销 start gate。证明来自数据库门禁关闭，不来自文件或容器缺失。legacy attempt 和已登记容器不能套用此例外。
6. **证据齐后再收尾。** 通过正常恢复流程核对所有有关 attempt、发布指针与哈希，然后做容量预览/确认应用。若证据无法找回，保留 pending 并隔离待人工调查，报告中明确缺口；本轮不自动重建不可恢复的取证事实。

特别注意：如果原 Docker daemon 数据也丢失，另起一个 daemon 后“看不到旧容器”，仍不能证明旧 daemon 的执行已退出。

## 五、离线包中运行工具，不安装宿主 Python

使用安装时已有的 `CPAG_DATA_ROOT`、`CPAG_PROJECT`、`CPAG_APP_IMAGE`。先优雅暂停 controller，API/PG 保持在线：

```sh
: "${CPAG_DATA_ROOT:?请先设置原安装的数据目录}"
: "${CPAG_PROJECT:?请先设置原安装的项目名}"
: "${CPAG_APP_IMAGE:?请先设置已导入并核对的app镜像}"
docker stop --time 30 "$CPAG_PROJECT-controller"
mkdir -p "$CPAG_DATA_ROOT/audit"
```

如果停止超时而被强制终止，剩余执行仍按活跃/未证明退出处理，先走正常协调器恢复，不能直接降预留。

下面的维护容器从已有受保护配置读凭据，不把秘密值写在命令行上；数据保持相同绝对挂载路径以保留 scope，审计报告在 shared/control 之外。

```sh
docker run --rm --pull=never --network "$CPAG_PROJECT-internal" \
  --mount "type=bind,src=$CPAG_DATA_ROOT,dst=$CPAG_DATA_ROOT" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e CPAG_DATA_ROOT -e CPAG_PROJECT "$CPAG_APP_IMAGE" \
  python -c 'import json,os,runpy; r=os.environ["CPAG_DATA_ROOT"]; c=json.load(open(r+"/config.json")); os.environ.update(CPAG_SHARED_ROOT=r+"/shared",CPAG_CONTROL_ROOT=r+"/control",CPAG_API_URL="http://"+os.environ["CPAG_PROJECT"]+"-api:8094",CPAG_WORKER_TOKEN=c["worker_token"],CPAG_COORDINATOR_TOKEN=c["coordinator_token"]); runpy.run_module("cpag_worker.capacity_rebuild",run_name="__main__")' \
  --report "$CPAG_DATA_ROOT/audit/capacity-preview.json"
```

应用时保持相同维护命令，换成新的结果报告路径，并增加：

```sh
--apply-plan "$CPAG_DATA_ROOT/audit/capacity-preview.json" --confirm REVIEWED_PLAN_ID
```

两步期间 controller 都保持暂停。核对后通过工程包正常 restart 操作恢复服务。本例只是维护容器调用已打包模块，不增加常驻服务或公开运维 API。

## 六、验收证据及边界

- `validation-round7/capacity-unit.log`：缺/坏账本、原字节备份、确认拒绝、过期预览、锁占用、活跃/未知保留、链接/外来 root 拒绝、遍历错误、执行器兼容 ID、非 `inputs` 安全路径和数据库独存活跃执行。当前 11 项通过。
- `capacity-review-negative-before-fix.log`：保留主审发现的三个问题的修复前失败复现，不代表当前仍失败。
- `scripts/ops/validate-capacity-rebuild.sh`：实际独立 PostgreSQL、Go API 与 Docker 计算。坏、缺失和过量预留三类账本，均先拒绝容量准入，再经预览、原字节备份和指纹确认重建，随后新的实际容器任务成功发布。
- `capacity-live.log`、`capacity-database-only-active.json`：实际运行 owner 拒绝重建；杀掉 controller 并移走其本地记录、删除账本后，Docker 仍运行，工具通过协调器发现数据库独存执行并阻止不安全应用；恢复保全证据后，正常清理孤儿并由 API 确认取消。
- `capacity-live-summary.json` 与唯一编号的 preview/applied 报告：记录每例差异、备份核对和实际 compute image ID。报告不含私密 token。

脚本支持 `CPAG_CAPACITY_IMAGE=<最终不可变imageID>` 与 `CPAG_CAPACITY_SKIP_BUILD=1`，用于绑定已导入的最终离线计算镜像。不指定时构建独立 `cpag-capacity:round7` 测试镜像，不覆盖 round5 标签。原生 CI 软件检查与本地 arm64 离线镜像验收必须分别标明。

最终离线候选镜像另行实测：构建源为干净提交 `a75d2238cb3dc569c4b443ed7dbe2502295607de`，以 `CPAG_CAPACITY_SKIP_BUILD=1` 绑定宿主实际运行 ID `sha256:f7e318cff745bc6abda33b04b45c7f032815720f6b96d2332a848aef771607e9`。`validation-round7/capacity-offline-image.log` 及 `capacity-offline-image/capacity-live-summary.json` 保存该次独立验收：三类重建后的新任务均成功，备份核对均通过，运行中 owner 锁与数据库独存活跃执行均阻止不安全应用。离线打包方提供的同一 saved image portable config ID 为 `sha256:8819d054de3a8a385fd66f06c51b269dd1e1fbea97a5f2131ca2ee76d5499486`；不同 Docker 存储后端的 ID 表示分别记录，不混称为同一字符串。本次记录绑定该候选，后续重建镜像须重新验收。

以上均是合成软件的生命周期与存储验收，不是工业数据验证或生产上线验收。本轮范围外事项保留登记，不扩展协议、界面、回放或算法。

最终冻结源码 `49e998545b9b7b47f2b1dc9b19e6d8562f780765` 的镜像再次完整实测通过：OCI ID `sha256:99d890615dbf7667af785470e77160b1d2f0ee77d97e6076069d876be0780c53`，portable config ID `sha256:bf4c9d0208dff86d6e7868c357a9f114697d544dc517f4a8d71bae7f56b556a9`。最终依据为 `validation-round7/capacity-final-image.log` 和 `capacity-final-image/capacity-live-summary.json`：损坏、缺失、超额三类账本均经预览、备份和确认重建后成功接单；活跃 owner 及仅数据库可发现的活跃执行均阻止不安全应用。上段 a75 镜像结果保留为过程记录，不是冻结镜像依据。
