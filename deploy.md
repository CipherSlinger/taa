# taa-fhe 部署命令

一个容器同时运行 FHE 服务（redis + api_server + worker，镜像 `latti/latti-server-node:latest`）
与 TAA。TAA 在容器内经 `127.0.0.1:58996` 访问 FHE，58996 不发布到宿主机；只发布 TAA 的
6001，供 platform/platform-mock 调用。

```bash
# 打包（本地构建 taa-fhe 镜像、导出归档、上传并 load 到远端）
./deploy-fhe.sh taa save

# 只部署统一容器（FHE + TAA；platform-mock 假定已在运行，否则设置 PLATFORM_IP）
./deploy-fhe.sh taa

# 只部署 platform-mock
./deploy-fhe.sh platform-mock

# 把 TAA 部署进已有 pod（Kubernetes 里的 FHE 实例）
# 会重渲染配置以匹配 pod 内的 FHE 数据根，重启 pod 内的 supervisor 并等待健康检查
./deploy-fhe.sh pod=<pod 名>

# 默认命名空间 osr；其它命名空间用 namespace=<ns> 或 POD_NAMESPACE=<ns>
./deploy-fhe.sh namespace=osr pod=<pod 名>

# 同一 pod 里有多个容器时指定容器
POD_CONTAINER=<容器名> ./deploy-fhe.sh pod=<pod 名>

# 只看会执行什么
./deploy-fhe.sh pod=<pod 名> -n

# 查当前 pod 名
kubectl -n osr get pods | grep taa-fhe

# 全量（platform-mock → 统一容器）
./deploy-fhe.sh

# 用打包好的镜像部署
TAA_IMAGE=taa-fhe:20261019 ./deploy-fhe.sh taa

# 只看会执行什么
./deploy-fhe.sh taa save -n
```

# taa 部署命令

```bash
TARGET_POD=taa-env-slim-v2-20261016-7104e03003ae0072-f7fbbf8f5-kkdb2 ./deploy.sh taa 
./deploy.sh docker save
```


# platform-mock 部署命令

platform-mock 的构建、启动、停止和就绪检查统一由仓库根目录的 `deploy-platform-mock.sh`
负责；`deploy.sh` 与 `deploy-fhe.sh` 只负责发现 TAA 目标并调用它。

```bash
./deploy-platform-mock.sh <local|remote> <start|stop|restart|status> [选项]
```

```bash
# 本地：构建 bin/platform-mock 并后台启动
./deploy-platform-mock.sh local start --taa-target http://127.0.0.1:6001 --allow-empty-attestation

# 查看状态（未运行且端点无应答时退出码非 0）
./deploy-platform-mock.sh local status

# 重启 / 停止
./deploy-platform-mock.sh local restart
./deploy-platform-mock.sh local stop

# 远端：静态构建后经 SSH 上传并后台启动
./deploy-platform-mock.sh remote start \
  --host 172.16.10.178 --user root --password 'Osrd@2026' \
  --remote-dir /root/taa --taa-target http://127.0.0.1:6001
./deploy-platform-mock.sh remote status --host 172.16.10.178
./deploy-platform-mock.sh remote stop --host 172.16.10.178

# 只查看会执行什么，不构建、不连接
./deploy-platform-mock.sh remote start --host 172.16.10.178 --dry-run
```

**常用选项**

| 选项 | 说明 |
|---|---|
| `--binary PATH` | 本地构建产物，默认 `bin/platform-mock` |
| `--binary-name NAME` | 进程名与远端安装名，默认 `platform-mock` |
| `--addr ADDR` / `--port N` | 监听地址，默认 `0.0.0.0:18080` |
| `--state-dir DIR` / `--upload-dir DIR` | 为空时不传对应参数，沿用二进制自身默认目录 |
| `--log-file PATH` / `--pid-file PATH` | 默认分别在 `.local/logs/`、`.local/run/`（远端在 `--remote-dir` 下） |
| `--taa-target URL` | 固定到单个 TAA 地址；不传时按注册信息推导每个实例的地址 |
| `--taa-pod` / `--taa-ns` / `--taa-port` | `--taa-target` 为空时的 Kubernetes 发现参数；`--taa-port` 同时用于多实例地址推导 |
| `--allow-empty-attestation` | 非 TEE 测试环境跳过证明校验 |
| `--reuse` | 端口已有实例应答时直接复用，不停止、不重启 |
| `--reset-register` | 就绪后 `POST /api/register/reset` |
| `--skip-build` | 复用 `--binary` 指向的现有二进制 |
| `--static` | 强制 `CGO_ENABLED=0 GOOS=linux`（远端模式默认如此） |
| `--ready-timeout` / `--ready-interval` | 就绪等待，默认 60s / 2s |
| `--dry-run` | 只打印计划 |
| `--host` / `--user` / `--password` / `--remote-dir` / `--remote-binary` | 远端目标、SSH 凭据与安装路径 |
| `--ssh-port` / `--ssh-opt` | 自定义 SSH 端口与额外选项 |

**生命周期语义**

- `start` 默认先构建，然后写 pidfile、后台启动并轮询 `GET /api/register/status`；
  超时会打印日志末尾并以非 0 退出。
- `stop` 先按 pidfile 终止，再按进程名兜底，未运行时也返回成功。
- `restart` 等于 `stop` + 构建 + `start`。
- `status` 打印 pid、日志与端点结果；进程存活或端点应答即返回 0。
- 远程启动使用 `nohup` 脱离 SSH，二进制上传到 `--remote-binary`（默认
  `--remote-dir/platform-mock`）。

**多实例（默认）**

- 不传 `--taa-target` 即进入多实例模式：一个 platform-mock 进程同时服务多个 TAA 实例，
  实例身份取注册请求里的 `dockerId`，每个实例在注册时按请求源 IP 推导自己的地址
  （`http://<源 IP>:<--taa-port>`，默认端口 6001）。
- `deploy.sh` 通过 `MULTI_INSTANCE=1` 开启该模式，`docker` 与 `remote` 两种模式都支持：
  ```bash
  MULTI_INSTANCE=1 ./deploy.sh docker
  MULTI_INSTANCE=1 ./deploy.sh remote
  ```
- 直接调用 `deploy-platform-mock.sh` 时省略 `--taa-target` 即可：
  ```bash
  ./deploy-platform-mock.sh local start --taa-port 6001
  ```
- 仍需要固定单实例地址时继续使用 `--taa-target http://<ip>:6001`（未按注册推导出地址时
  作为后备）。
- 限制：反向代理或端口转发会丢失请求源 IP，此时无法按注册推导地址，应退回
  `--taa-target` 指定固定地址。

**调用方差异（保持不变）**

- `deploy.sh remote` 不传 state/upload/allow-empty 参数，沿用二进制自身默认值。
- `deploy-fhe.sh` 显式传 state/upload 目录、`--allow-empty-attestation`、`--static`，
  并使用 `--reuse --reset-register`。
- `deploy.sh` 默认用 kubectl 发现 TAA Pod IP 后通过 `--taa-target` 传入；发现失败时
  退回 `--taa-pod/--taa-ns/--taa-port`。设置 `MULTI_INSTANCE=1` 时跳过发现，直接传
  `--taa-port`，由每个注册推导各自的目标地址。


# taa-teellm 部署命令

```bash
TARGET_POD=taa-teellm ./deploy-llm.sh taa 
./deploy-llm.sh pod=***
```

---

# 打包镜像依赖清单：基础镜像自带什么

四个部署脚本共五条打包链路；第 6 节是远端 DCU 测试 Pod 用的 vLLM 镜像，不由本仓库脚本打包。
每一节先列该镜像**从基础镜像继承到的依赖**，最后标注打包脚本
自己补进去的东西（"新增"），以便区分"镜像凭什么能跑"和"打包补了什么"。

体积取 `docker image inspect .Size`。`docker images` 的 SIZE 列对同一镜像会显示成 3.77 GB
这类更大的数字（实测与 inspect 不一致），本文一律用前者。

**镜像与归档命名规则**（四条打包链路统一）

| 打包路径 | 镜像 | 归档 |
|---|---|---|
| `deploy.sh save` | `taa-train-infer:<YYYYMMDD>` | `deploy/out/taa-train-infer-<YYYYMMDD>.tar.gz` |
| `deploy-fhe.sh taa save` | `taa-fhe:<YYYYMMDD>` | `deploy/out/taa-fhe-<YYYYMMDD>.tar.gz` |
| `deploy-dataanaylsis.sh save` | `taa-dataanaylsis:<YYYYMMDD>` | `deploy/out/taa-dataanaylsis-<YYYYMMDD>.tar.gz` |
| `build-teellm-image.sh` | `teellm:<YYYYMMDD>` | `deploy/out/teellm-<YYYYMMDD>.tar.gz` |

标签只有打包当天的本地日期，不带基础镜像的标签、不带 commit、不自动打 `latest`；
归档名与镜像名一一对应，只把 `:` 换成 `-`。推 registry 时加统一前缀
`172.16.10.178:31313/`，仓库名不变。基础镜像（`taa-env:slim-v2`、
`jupyter-nologin-full:v2.2`、`latti/latti-server-node:latest`、中间层 `teellm-base:<日期>`）
不适用本规则。每个名字都能用环境变量或 `--image`/`--tag`、`--archive` 覆盖。

**部署侧不按日期猜**：`deploy-llm.sh --create-pod` 建 Pod 前会查 registry 的
`/v2/teellm/tags/list`，取最新的日期 tag 填进 Pod 清单，而不是直接用当天日期 ——
镜像 tag 是构建日期，隔天部署时"今天"指向一个没人推过的 tag，Pod 会在 guest 启动之后
停在 ImagePullBackOff。显式给了 `TEELLM_POD_IMAGE` 就原样使用；查询失败（401、不可达）
则退回当天日期并告警。

## 1. TEE 训练 / 推理 — `deploy.sh`

`tee` 训练与 `tee` 推理共用这一条链路和同一个镜像：平台在启动时注入 `CONTRACT_TYPE`
（`1` 训练 / `2` 推理），两者都落到普通 `tee` 角色，差别由平台下发的请求决定。
`data-anaylsis` 也复用 `configs/taa-production.json` 这个模板，但保留自己的 jupyter
基座镜像，见第 3 节。

基础镜像 `taa-env:slim-v2`：Ubuntu 24.04.4，glibc 2.39，dpkg 130 个包，解压 1.84 GB，`/opt` 为空。

**基础镜像自带**

- shell / 内核接口：`bash`、`dash`、`sh`、`mknod`
- Python：`/usr/bin/python3` = 3.12.3、`pip3`、`pip`
- Python 包（64 个，实测可 import）：`torch 2.13.0+cpu`、`torchvision 0.28.0+cpu`、
  `numpy 2.5.2`、`scipy 1.18.1`、`scikit-learn 1.9.0`、`scikit-image 0.26.0`、
  `opencv-python-headless`（cv2 5.0.0）、`pandas`、`matplotlib`、`ipython`、`sympy`、
  `tensorboardX`、`openpyxl`、`PyYAML`
- 命令：`curl`、`tar`、`gzip`、`unzip`、`openssl`、`sed`、`grep`、`find`、`mawk`、
  `ls/cat/cp/mv/rm/mkdir`、`ps`、`pgrep`/`pkill`、`flock`、`timeout`、`du`、`nproc`、
  `stat`、`md5sum`、`sha256sum`、`base64`、`hostname`、`passwd`、`useradd`
- 库：`libc.so.6`(2.39)、`libssl.so.3` / `libcrypto.so.3`、`libstdc++.so.6`、
  `libgcc_s.so.1`、`libgomp.so.1`、`libz.so.1`
- CA 证书：`/etc/ssl/certs/ca-certificates.crt`（TLS 校验依赖它）

**基础镜像没有（别在容器里调）**

`wget`、`git`、`xz`、`jq`、`rsync`、`ssh`、`sshpass`、`go`、`node`、`file`、`cpio`、`sudo`、`ip`

**打包新增**

`/root/taa/taa`（静态二进制，不吃 glibc）、两份证明证书、`taa-supervisor.sh`、
渲染后的 `taa-config.json`、`/opt/taa/semgrep/{pylib,MANIFEST,rules}`。
`semgrep` 的 wrapper 是 `exec /usr/bin/python3` —— 解释器就来自上表的基础镜像，
bundle 只带 `pylib`（66 个 wheel）。supervisor 的单例锁用 `flock`，也在基础镜像里。

**继承的历史残留**

基础镜像自己就带着 `/root/taa/{taa 10.8 MB, start.sh 858 B, taa.log}`，ENTRYPOINT 原本是
`bash /root/taa/start.sh`。打包时 `taa` 被 `docker cp` 覆盖，`start.sh`/`taa.log` 不删
（脚本没有对应 rm），`commit` 才把 ENTRYPOINT 指向 `taa-supervisor.sh`。

## 2. FHE 推理 — `deploy-fhe.sh`

基础镜像 `latti/latti-server-node:latest`：Ubuntu 24.04.4，glibc 2.39，dpkg 237 个包，解压 681 MB。

**基础镜像自带**

- 进程模型：`/opt/entrypoint.sh` 一个容器起三件套 —— `redis-server`（仅回环）、
  `python3 -u api_server.py`、`python3 -u worker.py`；源码在 `/app/server`（WORKDIR）
- Redis：`/usr/bin/redis-server`、`/usr/bin/redis-cli`
- Python：`/opt/venv/bin/python3` = 3.10.22（PATH 首位，26 个包：`fastapi 0.143.1`、
  `uvicorn 0.54.0`、`redis 8.1.0`、`pydantic 2.14.1`、`requests 2.34.2`、`python-multipart`、
  `sse-starlette`）；系统另有 `/usr/bin/python3` = 3.12.3 与 `/usr/bin/python3.10`，
  但系统解释器没装 redis 包
- FHE 运行时：`/opt/latti-runtime`，含 `build/inference/lattisense/` 下的
  `liblattisense.so`、`cxx_sdk_v2`、`fhe_ops_lib`、`mega_ag_runners`，以及 `SHA256SUMS`、licenses；
  `LATTI_AI_ROOT`、`LATTI_AI_BUILD` 与 9 段 `LD_LIBRARY_PATH`（首段 `/opt/cuda-libs`）
  已烘进 ENV，运行时不需要再设
- CUDA：`/opt/cuda-libs` 只放两个 —— `libcudart.so.12`、`libcurand.so.10`；
  `NVIDIA_VISIBLE_DEVICES=all`、`NVIDIA_DRIVER_CAPABILITIES=compute,utility` 已设
- 命令：`bash`、`dash`、`tar`、`gzip`、`openssl`、`sed`、`grep`、`find`、`mawk`、
  `flock`、`timeout`、`sha256sum`、`ps`、`mknod`、`passwd`、`useradd`
- 库：`libc`(2.39)、`libssl3`/`libcrypto3`、`libstdc++.so.6`、`libgcc_s.so.1`、`libgomp.so.1`
- 默认端口/路径：`API_PORT=58996`、`CONTAINER_DATA_DIR=/data`、
  `CONFIG_PATH=/data/config/config.toml`、`TZ=Asia/Shanghai`；`/data` 构建时为空

**基础镜像没有（TAA 侧也不该依赖）**

`curl`、`wget`、`git`、`xz`、`jq`、`rsync`、`unzip`、`ssh`、`sudo`

**打包新增**

`/root/taa/taa`、`/root/taa/taa-supervisor.sh`、`/opt/taa-fhe-supervisor.sh`、
`/root/taa/taa-config.json`（只改 5 个键）。镜像**不含**模型、密钥、redis 数据，
运行时挂 `/data`、`/data/redis`、`$HOST_TAA_STATE_DIR`。GPU 由宿主 NVIDIA 驱动 +
nvidia-container-toolkit 提供，镜像自带的只有上面那两个 CUDA 用户态库。

## 3. 数据分析 — `deploy-dataanaylsis.sh`

透传 `deploy.sh`，基座为 `jupyter-nologin-full:v2.2`：Ubuntu 22.04.3，glibc 2.35，
dpkg 437 个包，解压 7.55 GB，ENTRYPOINT `tini -g --`，USER `jovyan`(1000)，
HOME/WORKDIR = `/home/jovyan`，EXPOSE 8888。

配置不再有自己的模板：脚本把 `configs/taa-production.json` 渲染成副本，只写入
`server.type=data-anaylsis` 与 `storage.data=/home/jovyan/systemAuthData`（jupyter 运行时读取的
位置），`codeAudit` 块与生产模板逐字一致。加载器按角色在启动时关闭整个审计（开关、LLM、
带规则的引擎），所以模板里的 semgrep 选择到不了扫描。真正需要处理的是打包路径：`deploy.sh`
按模板文本决定是否注入 semgrep payload，脚本因此导出 `TAA_SCAN_ENGINE_PROVISION=skip`，
让 `save`/`remote` 两条路都不再装这个镜像用不上的 payload。
密封密钥来源不需要渲染：TAA 启动时按 `/dev/csv-guest` 是否存在自动选择硬件密钥或 SM2 派生，
docker 与远端两种路径行为一致。

**基础镜像自带**

- Python（两套并存，默认 conda 那套）：
  - `/opt/conda/bin/python3` = 3.11.6（PATH 首位），conda 环境 226 个包：
    `numpy 1.24.4`、`pandas 2.2.3`、`scipy 1.11.3` 等；`pip3`/`pip` 同源
  - `/usr/bin/python3` = 3.10.12（系统解释器，不经 conda）
- 命令：`curl`、`wget`、`git`、`tar`、`gzip`、`xz`、`unzip`、`openssl`、`ssh`、`sudo`、
  `tini`、`sed`、`grep`、`find`、`mawk`、`flock`、`timeout`、`sha256sum`、`ps`、`pgrep`/`pkill`
- 其他运行时：`julia 1.9.3`（`/usr/local/bin`）、`node v20.19.6` + `npm`（conda 内）
- 库：`libc`(2.35)、`libssl3`/`libcrypto3`、`libstdc++.so.6`、`libgcc_s.so.1`、`libgomp.so.1`
- Jupyter 基础：`/home/jovyan`（`.jupyter`、`.cache`、`.conda`、`.config`、`work`）、
  `start-notebook.sh` 等启动脚本

**基础镜像没有**

`jq`、`rsync`、`java`、`torch`、`semgrep`；`/home/jovyan/systemAuthData` 不存在（TAA 启动时自建）；
`/root/taa`、`/opt/taa` 也不存在（打包时新建）。

**打包新增**

与审计镜像相同的 TAA 载荷（`taa` 静态二进制、两份证书、`taa-supervisor.sh`、
渲染后的 `taa-config.json`、空目录 `/root/taa/{models,data,results,keys}` 与
`/opt/taa/{input,output}`）。**不装 semgrep、不装 teellm**：配置里的 `codeAudit` 与生产模板
一致（含 `codeScan.engine=semgrep`），但运行时按角色关掉审计，打包时由
`TAA_SCAN_ENGINE_PROVISION=skip` 跳过 payload 注入。

## 4. TEE 推理网关 — `build-teellm-image.sh`（由 `deploy-llm.sh` 部署）

基础镜像 `teellm-base:<日期>` = `taa-env:slim-v2` 加一层 `RUN rm -rf /root/taa`，
**所以基础依赖与第 1 节完全相同**（Ubuntu 24.04.4、glibc 2.39、Python 3.12.3、`curl`、
`bash`、`flock`、CA 证书）。`/opt/teellm` 是打包新建的，基础镜像里没有。

**这份基础镜像真正承担的三件事**（缺一样就跑不起来）

- `bash` —— ENTRYPOINT 是 `bash /opt/teellm/teellm-supervisor.sh`，缺了容器直接起不来
- `curl` —— supervisor 轮询 `http://127.0.0.1:11434/api/tags` 判就绪，缺了就绪探测永远失败，
  120s 后放弃
- `libstdc++.so.6` / `libgcc_s.so.1` —— `llama-server`、`ollama` 的 `ldd` 直接解析到
  `/lib/x86_64-linux-gnu/`，缺了 `llama-server` 无法 exec

`libgomp.so.1` **不用基础镜像的**：bundle 自带 `lib/ollama/libgomp.so.1`，`RUNPATH=$ORIGIN`
先命中它。`teellm-service` 是 `CGO_ENABLED=0` 静态二进制，不吃 glibc。

**打包新增**

`teellm-service`、`teellm-supervisor.sh`、两份配置、两份证书、`ollama` + `start-ollama.sh` +
`lib/ollama` 顶层 30 项（排除 cuda/mlx/vulkan/include）、`qwen2.5-coder:7b` 的 5 个 blob、
`.teellm-model`，以及 6 个 soname 软链（缺则 exit 127）。

## 5. CSV2 机密 VM 启动镜像 — `deploy-taa-vm.sh`

基座 `kata-containers-initrd-confidential-csv.img`：57.3 MB，4682 条目，只追加不重写。
这一层的"依赖"是 guest 开机到 kata-agent 起来之前的全部家当。

**基座自带**

- kata-agent：`usr/sbin/init`（19 MB Rust 二进制，`/init -> /sbin/init` 即 `rdinit`/`init` 入口）；
  CoCo 侧 `usr/local/bin/attestation-agent`；`etc/kata-opa/{default-policy,allow-all}.rego`；
  `pause_bundle/`
- 通用工具面：4682 个条目里 `usr/bin/` 占 307 个，另有 `usr/sbin/` 的 `fsck.*`、`iptables-nft`、
  `ebtables-nft`、`ldconfig.real`、`installkernel` 等系统级命令
- shell / 通用命令：`bash`（1.4 MB）、`dash`（126 KB）、`perl`（`usr/bin/perl` →
  `perl5.34.0` 硬链接）、`mawk`；`ls/cat/cp/mv/rm/mkdir/ln/chmod/chown/touch/df/sync/env/
  stat/basename/dirname/readlink/printf`、`sed/grep/awk/find`、`ps/pgrep/pkill`、
  `tar/gzip/gunzip`、`flock/timeout`、`sha256sum/base64`、`head/tail/wc/tr/cut/sort/xargs/which`、
  `ip/mount/dmesg`、`mknod`、`nsenter/unshare`
- 库：`libc.so.6`（GLIBC 2.35）、`ld-linux-x86-64.so.2`、`libssl.so.3`/`libcrypto.so.3`、
  `libz.so.1`、`libgcc_s.so.1`；**没有 `libstdc++.so.6`**
- 没有内核模块工具：无 `modprobe`（`/dev/csv-guest` 得靠 `mknod` 建节点）

**基座没有**

`python3`、`semgrep`、`curl`、`wget`、`openssl`（命令行）、`xz`、`unzip`、`cpio`、`file`、`less`

**追加进 initrd**

`usr/local/bin/taa`（必须静态链接 —— 基座 glibc 2.35，动态链接会随打包机漂移）、
`usr/local/bin/taa-init`、`etc/taa/taa-config.json`、
`etc/default/taa.env`；选中 semgrep 时整棵 `semgrep-payload/rootfs`（4242 文件，
**自带 `python3.10`**，不依赖基座）。

## 6. DCU 机密测试 Pod — `/home/wj/dcu/dcu-tee-test-pod-create.sh`

基础镜像 `harbor.sourcefind.cn:5443/dcu/admin/base/vllm:0.9.2-ubuntu22.04-dtk26.04-0130-py3.10-20260202`：
Ubuntu 22.04.5，glibc 2.35，dpkg 984 个包，29 层，解压 25.6 GB（25611144188 B），
用户 root，WORKDIR `/workspace`（空），ENTRYPOINT `docker-entrypoint.sh`（figlet 横幅 +
检查 `/dev/kfd`、`/dev/dri`），CMD `/bin/bash`。

脚本本身**不构建镜像**：它只保证本地私有仓库有 `172.16.10.178:31313/vllm:ubuntu-dtk`
（没有就 `docker tag` + `docker push` 这份 25.6 GB 的上游镜像，`PULL_TIMEOUT=2400`），
把 initdata 与 root 口令渲染进 `dcu-tee-test-pod-template.yaml`，apply 后校验 vfio 绑定和
NodePort。所以这一节的"依赖"就是镜像里已经烘好的东西。

**基础镜像自带**

- 系统：`/usr/bin/python3` = 3.10.12（无 conda），237 个 pip 包，CA 证书齐全，`TZ=Asia/Shanghai`
- AI 栈（全是海光 das 分支）：`vllm 0.9.2+das.opt5.dtk2604.20260129.g56d6c689`、
  `torch 2.5.1+das.opt1.dtk2604.20260116.g78471bfd`、
  `triton 3.1.0+das.opt1.dtk2604.20260123.g0732375a`、`transformers 4.57.6`、`ray 2.48.0`、
  `numpy 1.25.0`、`fastapi 0.128.0`、`uvicorn 0.40.0`、`pydantic 2.12.5`、`accelerate 1.12.0`、
  `safetensors 0.7.0`、`tokenizers 0.22.2`、`sentencepiece 0.2.1`；`python3.10-dev` 也在
- DTK 26.04：`/opt/dtk -> /opt/dtk-26.04`，clang 17.0.0、dcc 25.10.0、`hipcc`、`rocminfo`、
  `rocm-smi`、`rocm_agent_enumerator`、`librccl.so.1`、hipblas/hipblaslt/opencl/dushmem/dcc-gcvm、
  `hipkernel.bin.gfx906/926/928/936/938`；另带 `/opt/ucx`、`/opt/mpi`、`/opt/hwloc`、
  `/opt/mellanox`（MOFED 23.10-4.0.9.1）
- 相关 ENV 已烘进镜像：`PATH`、`LD_LIBRARY_PATH`、`HYHAL_PATH=/opt/hyhal/`、
  `AMDGPU_TARGETS=gfx906;gfx926;gfx928;gfx936;gfx938`、`ROCM_PATH`、`HIP_PATH`、
  `MIOPEN_FIND_MODE=3`、`CMAKE_PREFIX_PATH`、`LIBRARY_PATH`、`*_INCLUDE_PATH`、
  `MOFED_VERSION`、`UCX_HOME`
- ssh：`openssh-server`/`client 1:8.9p1-3ubuntu0.13`，四把 host key 全部烘好
  （`ssh_host_{rsa,ecdsa,ed25519,dsa}_key`，重建 Pod 指纹不变），`chpasswd`/`useradd`/`passwd` 可用
- 命令：`bash`/`sh`/`dash`、`curl`、`wget`、`git`、`tar`、`gzip`、`xz`、`unzip`、`rsync`、
  `openssl`、`vim`、`sudo`、`figlet`、`gcc`/`g++ 11.4.0`、`make`、`cmake 3.29.0`、`ninja`、
  `ld`、`ifconfig`（net-tools）、`pgrep`/`pkill`、`flock`、`timeout`、`sha256sum`、`nproc`、`ldconfig`

**基础镜像没有（别调）**

`jq`、`ip`（iproute2，只有 `ifconfig`）、`less`、`nc`、`conda`、CUDA

**已知坑：`/opt/hyhal` 不存在**

镜像 ENV 里的 `HYHAL_PATH=/opt/hyhal/` 是宿主驱动路径，镜像和宿主上都没有这个目录。
`/opt/dtk-26.04/env.sh` 会连报两次找不到，然后回退到 `/opt/dtk-26.04/.hyhal`（把
`.hyhal/rocm_smi/lib` 追加进 `LD_LIBRARY_PATH`）。**不 source 就直接 `import torch` 会失败**：
`librocm_smi64.so.2: cannot open shared object file`；source 之后 torch / vllm 都能 import，
只留一条 `get hyhal driver version error!` 警告。`hy-smi` 在
`/opt/dtk-26.04/.hyhal/bin/hy-smi`，**不在烘好的 PATH 里**（`/opt/dtk/bin/hy-smi` 不存在）；
在没透传卡的普通容器里执行会报 `/dev/dri is empty or missing`。
`/etc/bash.bashrc` 第 72–73 行会 source `env.sh`，但只对交互式 shell 生效。

**不属于镜像的部分**（模板 command 运行时才造）

`/dev/kfd`、`/dev/mkfd`、`/dev/dri/*`（vfio 直通）、`/etc/profile.d/00-dtk-env.sh`、
root 口令、`sshd_config` 改动（放开 root 登录）。这些每次起 Pod 由
`dcu-tee-test-pod-template.yaml` 的 command 现场写入，镜像里没有。

## 基础镜像横向对照

taa-env（TEE 训练 / 推理、teellm）
- `bash` ✓，`python3` 3.12.3，`curl` ✓，`flock`/`timeout` ✓/✓
- `libstdc++` ✓，`jq`/`rsync` ✗/✗，`torch` ✓ 2.13.0+cpu

latti（FHE 推理）
- `bash` ✓，`python3` 3.10.22 (venv)，`curl` ✗，`flock`/`timeout` ✓/✓
- `libstdc++` ✓，`jq`/`rsync` ✗/✗，`torch` ✗

jupyter（数据分析）
- `bash` ✓，`python3` 3.11.6 (conda) / 3.10.12 (系统)，`curl` ✓，`flock`/`timeout` ✓/✓
- `libstdc++` ✓，`jq`/`rsync` ✗/✗，`torch` ✗

initrd 基座（CSV2 机密 VM）
- `bash` ✓，`python3` ✗（payload 自带 3.10），`curl` ✗，`flock`/`timeout` ✓/✓
- `libstdc++` ✗，`jq`/`rsync` ✗/✗，`torch` ✗

vllm:ubuntu-dtk（DCU 机密测试 Pod）
- `bash` ✓，`python3` 3.10.12，`curl` ✓，`flock`/`timeout` ✓/✓
- `libstdc++` ✓，`jq` ✗ / `rsync` ✓，`torch` ✓ 2.5.1+das（DTK 26.04，需先 source `env.sh`）
