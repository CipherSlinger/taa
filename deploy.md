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


# taa-teellm 部署命令

```bash
TARGET_POD=taa-teellm ./deploy-llm.sh taa 
./deploy-llm.sh pod=***
```

---

# 打包镜像依赖清单：基础镜像自带什么

四个部署脚本共五条打包链路。每一节先列**该镜像从基础镜像继承到的依赖**，
最后标注打包脚本自己补进去的东西（`新增`），以便区分"镜像凭什么能跑"和"打包补了什么"。

| 部署脚本 | 产出镜像 | 基础镜像 | 基础镜像解压体积 |
|---|---|---|---|
| `deploy.sh` | `taa-env:slim-v2-<日期>` | `taa-env:slim-v2` | 1.84 GB |
| `deploy-fhe.sh` | `taa-fhe:<日期>` | `latti/latti-server-node:latest` | 681 MB |
| `deploy-dataanaylsis.sh` → `deploy.sh` | `taa-dataanaylsis:<日期>` | `jupyter-nologin-full:v2.2` | 7.55 GB |
| `build-teellm-image.sh`（`deploy-llm.sh` 部署） | `teellm:teellm-<日期>` | `teellm-base:<日期>` ← `taa-env:slim-v2` | 1.84 GB |
| `deploy-taa-vm.sh`（initrd，不是镜像） | `kata-containers-initrd-taa-csv.initrd` | `kata-containers-initrd-confidential-csv.img` | 57.3 MB / 4682 条目 |

体积取 `docker image inspect .Size`。`docker images` 的 SIZE 列对同一镜像显示 3.77 GB，
与 inspect 不一致（实测），本文一律用后者。

## 1. `deploy.sh` → `taa-env:slim-v2-<日期>`

基础镜像 `taa-env:slim-v2`（Ubuntu 24.04.4，glibc 2.39，dpkg 130 个包，`/opt` 为空）。

**基础镜像自带（打包不再提供）**

- **shell / 内核接口**：`bash`、`dash`、`sh`；`/usr/bin/mknod`
- **Python**：`/usr/bin/python3` = **3.12.3**、`pip3`、`pip`
- **Python 包（64 个，实测可 import）**：`torch 2.13.0+cpu`、`torchvision 0.28.0+cpu`、
  `numpy 2.5.2`、`scipy 1.18.1`、`scikit-learn 1.9.0`、`scikit-image 0.26.0`、
  `opencv-python-headless`（cv2 5.0.0）、`pandas`、`matplotlib`、`ipython`、`sympy`、
  `tensorboardX`、`openpyxl`、`PyYAML`
- **命令**：`curl`、`tar`、`gzip`、`unzip`、`openssl`、`sed`、`grep`、`find`、`mawk`、`ls/cat/cp/mv/rm/mkdir`、
  `ps`、`pgrep`/`pkill`、`flock`、`timeout`、`du`、`nproc`、`stat`、`md5sum`、`sha256sum`、`base64`、
  `hostname`、`passwd`、`useradd`
- **库**：`libc.so.6`(2.39)、`libssl.so.3` / `libcrypto.so.3`、`libstdc++.so.6`、`libgcc_s.so.1`、`libgomp.so.1`、`libz.so.1`
- **CA 证书**：`/etc/ssl/certs/ca-certificates.crt`（TLS 校验依赖它）

**基础镜像没有（别在容器里调）**：`wget`、`git`、`xz`、`jq`、`rsync`、`ssh`、`sshpass`、`go`、`node`、`file`、`cpio`、`sudo`、`ip`

**打包新增**：`/root/taa/taa`（静态二进制，不吃 glibc）、两份证明证书、`taa-supervisor.sh`、
渲染后的 `taa-config.json`、`/opt/taa/semgrep/{pylib,MANIFEST,rules}`。
`semgrep` 的 wrapper 是 `exec /usr/bin/python3` —— **解释器就来自上表的基础镜像**，
bundle 只带 `pylib`（66 个 wheel）。supervisor 的单例锁用 `flock`，也在基础镜像里。

**继承的历史残留**：基础镜像自己就带着 `/root/taa/{taa 10.8 MB, start.sh 858 B, taa.log}`，
`ENTRYPOINT` 原本是 `bash /root/taa/start.sh`。打包时 `taa` 被 `docker cp` 覆盖、
`start.sh`/`taa.log` 不删（脚本没有对应 rm），`commit` 才把 ENTRYPOINT 指向 `taa-supervisor.sh`。

## 2. `deploy-fhe.sh` → `taa-fhe:<日期>`

基础镜像 `latti/latti-server-node:latest`（Ubuntu 24.04.4，glibc 2.39，dpkg 237 个包）。

**基础镜像自带**

- **进程模型**：`/opt/entrypoint.sh` 一个容器起三件套 —— `redis-server`（仅回环）、
  `python3 -u api_server.py`、`python3 -u worker.py`，源码在 `/app/server`（WORKDIR）
- **Redis**：`/usr/bin/redis-server`、`/usr/bin/redis-cli`
- **Python**：`/opt/venv/bin/python3` = **3.10.22**（PATH 首位，26 个包：`fastapi 0.143.1`、
  `uvicorn 0.54.0`、`redis 8.1.0`、`pydantic 2.14.1`、`requests 2.34.2`、`python-multipart`、`sse-starlette`）；
  系统另有 `/usr/bin/python3` = 3.12.3 与 `/usr/bin/python3.10`（系统解释器没装 redis 包）
- **FHE 运行时**：`/opt/latti-runtime`（`build/inference/lattisense/` 下的
  `liblattisense.so`、`cxx_sdk_v2`、`fhe_ops_lib`、`mega_ag_runners`、`SHA256SUMS`、licenses）、
  `LATTI_AI_ROOT`、`LATTI_AI_BUILD` 与 9 段 `LD_LIBRARY_PATH`（首段 `/opt/cuda-libs`）已烘进 `ENV`，
  运行时不需要再设
- **CUDA**：`/opt/cuda-libs` 只放两个 —— `libcudart.so.12`、`libcurand.so.10`；
  `NVIDIA_VISIBLE_DEVICES=all`、`NVIDIA_DRIVER_CAPABILITIES=compute,utility` 已设
- **命令**：`bash`、`dash`、`tar`、`gzip`、`openssl`、`sed`、`grep`、`find`、`mawk`、`flock`、`timeout`、
  `sha256sum`、`ps`、`mknod`、`passwd`、`useradd`
- **库**：`libc`(2.39)、`libssl3`/`libcrypto3`、`libstdc++.so.6`、`libgcc_s.so.1`、`libgomp.so.1`
- **默认端口/路径**：`API_PORT=58996`、`CONTAINER_DATA_DIR=/data`、`CONFIG_PATH=/data/config/config.toml`、
  `TZ=Asia/Shanghai`；`/data` 构建时为空

**基础镜像没有**：`curl`、`wget`、`git`、`xz`、`jq`、`rsync`、`unzip`、`ssh`、`sudo` —— TAA 侧也不该依赖它们

**打包新增**：`/root/taa/taa`、`/root/taa/taa-supervisor.sh`、`/opt/taa-fhe-supervisor.sh`、
`/root/taa/taa-config.json`（只改 5 个键）。镜像**不含**模型、密钥、redis 数据，
运行时挂 `/data`、`/data/redis`、`$HOST_TAA_STATE_DIR`。GPU 由宿主 NVIDIA 驱动 +
nvidia-container-toolkit 提供，镜像自带的只有上面那两个 CUDA 用户态库。

## 3. `deploy-dataanaylsis.sh` → `taa-dataanaylsis:<日期>`

透传 `deploy.sh`，只换基座为 `jupyter-nologin-full:v2.2`（Ubuntu 22.04.3，glibc 2.35，
dpkg 437 个包，`ENTRYPOINT ["tini","-g","--"]`，`USER jovyan`(1000)，`HOME`/`WORKDIR` = `/home/jovyan`，`EXPOSE 8888`）。

**基础镜像自带**

- **Python（两套并存，默认 conda 那套）**：
  - `/opt/conda/bin/python3` = **3.11.6**（PATH 首位），conda 环境 226 个包：
    `numpy 1.24.4`、`pandas 2.2.3`、`scipy 1.11.3` 等；`pip3`/`pip` 同源
  - `/usr/bin/python3` = **3.10.12**（系统解释器，不经 conda）
- **命令**：`curl`、`wget`、`git`、`tar`、`gzip`、`xz`、`unzip`、`openssl`、`ssh`、`sudo`、`tini`、
  `sed`、`grep`、`find`、`mawk`、`flock`、`timeout`、`sha256sum`、`ps`、`pgrep`/`pkill`
- **其他运行时**：`julia 1.9.3`（`/usr/local/bin`）、`node v20.19.6` + `npm`（conda 内）
- **库**：`libc`(2.35)、`libssl3`/`libcrypto3`、`libstdc++.so.6`、`libgcc_s.so.1`、`libgomp.so.1`
- **Jupyter 基础**：`/home/jovyan`（`.jupyter`、`.cache`、`.conda`、`.config`、`work`）、`start-notebook.sh` 等启动脚本

**基础镜像没有**：`jq`、`rsync`、`java`、`torch`、`semgrep`；`/home/jovyan/systemAuthData` 不存在（TAA 启动时自建）；
`/root/taa`、`/opt/taa` 也不存在（打包时新建）

**打包新增**：与 audit 镜像相同的 TAA 载荷（`taa` 静态二进制、两份证书、`taa-supervisor.sh`、
渲染后的 `taa-config.json`、空目录 `/root/taa/{models,data,results,keys}` 与 `/opt/taa/{input,output}`）。
**不装 semgrep、不装 teellm**（配置 `codeScan.engine=regex`、`codeAudit` 三项全关，前置闸门会拒绝相反配置）。

## 4. `build-teellm-image.sh` → `teellm:teellm-<日期>`

基础镜像 `teellm-base:<日期>` = `taa-env:slim-v2` 加一层 `RUN rm -rf /root/taa`，
**所以基础依赖与第 1 节完全相同**（Ubuntu 24.04.4、glibc 2.39、Python 3.12.3、`curl`、`bash`、`flock`、
`libstdc++.so.6`、`libgcc_s.so.1`、CA 证书）。`/opt/teellm` 是打包新建的，基础镜像里没有。

**这份基础镜像真正承担的三件事**（删掉就跑不起来）：

| 依赖 | 谁用 | 缺了会怎样 |
|---|---|---|
| `bash` | `ENTRYPOINT ["bash", "/opt/teellm/teellm-supervisor.sh"]` | 容器直接起不来 |
| `curl` | supervisor 轮询 `http://127.0.0.1:11434/api/tags` 判就绪 | 就绪探测永远失败 → 120s 后放弃 |
| `libstdc++.so.6` / `libgcc_s.so.1` | `llama-server`、`ollama` 的 `ldd` 直接落在 `/lib/x86_64-linux-gnu/` | `llama-server` 无法 exec |

`libgomp.so.1` **不用基础镜像的**：bundle 自带 `lib/ollama/libgomp.so.1`，
`RUNPATH=$ORIGIN` 先命中它。`teellm-service` 是 `CGO_ENABLED=0` 静态二进制，不吃 glibc。

**打包新增**：`teellm-service`、`teellm-supervisor.sh`、两份配置、两份证书、
`ollama` + `start-ollama.sh` + `lib/ollama` 顶层 30 项（排除 cuda/mlx/vulkan/include）、
`qwen2.5-coder:7b` 的 5 个 blob、`.teellm-model`，以及 6 个 soname 软链（缺则 exit 127）。

## 5. `deploy-taa-vm.sh` → CSV2 initrd

基座 `kata-containers-initrd-confidential-csv.img`（57.3 MB，4682 条目，只追加不重写）。
这一层的"依赖"是 guest 开机到 kata-agent 起来之前的全部家当。

**基座自带**

- **kata-agent**：`usr/sbin/init`（19 MB Rust 二进制，`/init -> /sbin/init` 即 `rdinit`/`init` 入口）；
  CoCo 侧 `usr/local/bin/attestation-agent`；`etc/kata-opa/{default-policy,allow-all}.rego`；`pause_bundle/`
- **通用工具面**：4682 个条目里 `usr/bin/` 占 307 个，另有 `usr/sbin/` 的 `fsck.*`、`iptables-nft`、
  `ebtables-nft`、`ldconfig.real`、`installkernel` 等系统级命令
- **shell / 通用命令**：`bash`（1.4 MB）、`dash`（126 KB）、`perl`（`usr/bin/perl` → `perl5.34.0` 硬链接）、`mawk`；
  `ls/cat/cp/mv/rm/mkdir/ln/chmod/chown/touch/df/sync/env/stat/basename/dirname/readlink/printf`、
  `sed/grep/awk/find`、`ps/pgrep/pkill`、`tar/gzip/gunzip`、`flock/timeout`、`sha256sum/base64`、
  `head/tail/wc/tr/cut/sort/xargs/which`、`ip/mount/dmesg`、`mknod`、`nsenter/unshare`
- **库**：`libc.so.6`（**GLIBC 2.35**）、`ld-linux-x86-64.so.2`、`libssl.so.3`/`libcrypto.so.3`、
  `libz.so.1`、`libgcc_s.so.1`；**没有 `libstdc++.so.6`**
- **没有内核模块工具**：无 `modprobe`（`/dev/csv-guest` 得靠 `mknod` 建节点，与已知结论一致）

**基座没有**：`python3`、`semgrep`、`curl`、`wget`、`openssl`(命令行)、`xz`、`unzip`、`cpio`、`file`、`less`

**追加进 initrd**：`usr/local/bin/taa`（必须静态链接 —— 基座 glibc 2.35，动态链接会随打包机漂移）、
`usr/local/bin/taa-init`、`etc/taa/taa-config.json`、`etc/taa/certs/*.cert`、`etc/default/taa.env`；
选中 semgrep 时整棵 `semgrep-payload/rootfs`（4242 文件，**自带 `python3.10`**，不依赖基座）。

## 一句话对照

| 依赖 | taa-env | latti | jupyter | initrd |
|---|---|---|---|---|
| `bash` | ✓ | ✓ | ✓ | ✓ |
| `python3` | 3.12.3 | 3.10.22 (venv) | 3.11.6 (conda) / 3.10.12 (系统) | ✗（payload 自带 3.10） |
| `curl` | ✓ | ✗ | ✓ | ✗ |
| `flock` / `timeout` | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ | ✓ / ✓ |
| `libstdc++` | ✓ | ✓ | ✓ | ✗ |
| `jq` / `rsync` | ✗ / ✗ | ✗ / ✗ | ✗ / ✗ | ✗ / ✗ |
| `torch` | ✓ 2.13.0+cpu | ✗ | ✗ | ✗ |
