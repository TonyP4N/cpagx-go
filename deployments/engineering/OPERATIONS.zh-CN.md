# 候选工程离线包操作说明

版本：cpag-engineering-synthetic-rc1。仅支持合成数据的软件工程验证。

本轮验收环境是全新、独立的 Linux/arm64 Docker-in-Docker 主机：Alpine Linux 3.23、Docker Engine 29.1.3，使用新建镜像存储卷。它是容器化目标环境，不能作为裸机或虚拟机操作系统安装验收。外层 Docker internal 网络没有公网默认路由；内层私有 bridge 用于服务之间通信和本机端口发布。

## 文件与依赖

- images.tar：候选应用、独立计算器、旧基线1386a4f应用和计算器、PostgreSQL镜像。
- lab-engine.tar：复现容器化验收环境所用的固定Docker 29.1.3-dind镜像。
- release.json、baseline-release.json：源码版本、包装来源、Linux/arm64、各源码文件及镜像摘要。config digest与准备主机OCI索引ID分开记录。
- SHA256SUMS：包内全部文件的SHA-256核验清单。
- config.env.example：无口令配置样例。运行期凭证由install随机生成，保存在数据目录config.json，权限0600。
- validate-upgrade-rollback.sh：只能在显式声明可丢弃的工程主机运行的升级、独立恢复和真实基线回滚验证。

目标主机预置Docker Engine 29.1.3、POSIX sh和sha256sum；无需Python、Go、pip、npm或在线软件源。Python 3.12.12、Go 1.26.5构建的静态API/恢复器、Docker CLI 29.1.3和PostgreSQL 17.6均封装在已保存镜像中。固定镜像源摘要见dependencies.lock.json。

## 安装及运行

在目标Linux主机上，将整个包复制到一个目录，创建数据父目录。可先按样例设置环境变量，再运行：

```sh
export CPAG_DATA_ROOT=/cpag-root/data
export CPAG_PROJECT=cpag-engineering
mkdir -p "$CPAG_DATA_ROOT"
sh ./cpag.sh install
sh ./cpag.sh start
sh ./cpag.sh demo
sh ./cpag.sh check
```

install先核验包内容，再docker load，不执行在线pull或build。start等待数据库和API就绪；schema迁移及其内容哈希在同一数据库事务登记。已有PG容器必须与本project的镜像、数据卷、数据库名及凭证匹配；不覆盖其他数据。start对完整匹配且运行中的服务返回已启动，对部分/不同服务明确失败。

demo通过真实API提交两项合成任务（旧网络JSONL+过程CSV，以及抓包任务），由持API凭证的独立主机协调器领取，交给没有网络/凭证的计算容器执行，校验后持久发布。check查询API终态、原始抓包字段证据，下载并解开两套结果逐文件核验。证据/下载HTTP入口只支持demo登记的两项任务，不是通用任务浏览器；要求Bearer认证，缺失、篡改或与API发布摘要不一致时拒绝下载。

服务本机接口为127.0.0.1:18115（任务API）、127.0.0.1:18120（证据/下载）。计算容器不暴露端口；Docker socket只交给可信的协调器和运维工具。

## 维护、重启、保留数据

```sh
sh ./cpag.sh maintenance  # 移除应用/协调器/恢复器/证据服务，保留PG用于备份
sh ./cpag.sh start        # 复用已验证的PG与数据库迁移登记
sh ./cpag.sh restart      # 重建全部服务，保留PG数据卷和数据目录
sh ./cpag.sh stop         # 停止并移除本project服务容器，保留数据库卷与数据目录
```

停止操作会验证Docker可用性及容器归属；整体Docker故障或不匹配资源会明确失败，不以成功掩盖故障。维护前应等待任务结束，再按配套备份工具执行快照。升级或回滚前保留完整检查点；不得把单纯停止服务当作回滚。离线验证脚本会在独立目录和数据库卷恢复旧检查点，启动旧应用/计算器并实际执行新合成任务。

容量账本、控制回执、原始输入、发布结果与config.json都是检查点内容。容量重建工具已封装在应用镜像的cpag_worker.capacity_rebuild模块，按配套运维手册先预览、核验摘要、确认后应用；不直接删除账本把占用归零。

本包不代表真实工业数据验证、生产部署验收或主机文件系统硬配额。完整断公网与依赖恢复、旧版本回滚的实际证据见随交付说明引用的validation-round7记录。
