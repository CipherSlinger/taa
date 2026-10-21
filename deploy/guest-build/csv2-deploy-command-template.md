# CSV2 部署命令模板

> 说明：这份模板把 `guest-build/build-initrd.sh` 和 `../deploy.sh` 的关键信息整理成可复制执行的命令。
> 默认只用于查阅和手工执行，不会自动部署。
>
> **先看仓库根的 `deploy-taa-vm.sh`**：它是这套流程的合一入口（`up` = 构建 → 部署 → launch → 验证），
> 并且补上了本模板没有的一步——`delete` 清理。下面的手工命令仍适用于需要分步排查的场合。
> 它自己不带任何默认值，全部设置都向这里的 `build-initrd.sh print-config` 要，所以两边不会漂移。

## 0. 先确认基础变量

下面这些值来自当前仓库脚本中的默认值；按你的实际环境替换即可。

```bash
# 远程宿主机 / Kata 侧
# 脚本全程在远端 sudo 改 kata/containerd 配置并重启服务，所以默认用 root（公钥登录，不需要密码）。
# 换成非 root 账号前，先确认该账号有免密 sudo，否则会在改配置的中途失败。
export REMOTE_USER=root
export REMOTE_HOST=172.16.10.178
export REMOTE="${REMOTE_USER}@${REMOTE_HOST}"

# guest-build/build-initrd.sh 使用的远程 bundle
export REMOTE_BUNDLE_DIR=/opt/kata/share/kata-containers/taa-csv-20260901
export REMOTE_BASE_INITRD_SRC=/opt/kata/share/kata-containers/kata-containers-initrd-confidential-csv.img
export REMOTE_KERNEL_SRC=/opt/kata/share/kata-containers/vmlinuz-confidential-csv.container
export REMOTE_OVMF_SRC=/opt/kata/share/ovmf/OVMFCSV.fd
export REMOTE_KATA_CONFIG_SRC=/opt/kata/share/defaults/kata-containers/configuration-qemu-csv2.toml
export REMOTE_KATA_CONFIG=/etc/kata-containers/configuration-qemu-csv2-taa.toml
export RUNTIME_HANDLER=kata-qemu-csv2-taa
export RUNTIME_TYPE=io.containerd.kata-qemu-csv2.v2
export RUNTIME_PATH=/opt/kata/bin/containerd-shim-kata-v2
export SNAPSHOTTER=nydus

# Kubernetes
export TEST_NODE_NAME=<kubectl get nodes 里显示的节点名>
export TEST_POD_NAME=test-kata-csv2-taa
# 默认已是宿主本地 registry 的镜像。**别改成 Docker Hub 上的 tag**：guest 内的 CDH
# 没有到外网的路由，实测 busybox:latest 报 error sending request for index.docker.io，
# Pod 停在 StartError。另外 verify 步骤要在 Pod 内执行 curl，busybox 不带 curl。
export TEST_IMAGE=172.16.10.178:31313/taa-env:slim-v2-20260916

# 测试 Pod 的注解，必须是 JSON 对象。在这台宿主上 **不能省**：CoCo 的 CDH 在 guest 内拉镜像，
# 注册表 CA 只能经 cc_init_data 注解投递，缺了就会 TLS 失败、Pod 停在 StartError。
# 从宿主上任何一个跑得通的 CoCo Pod 取出来复用：
#   kubectl -n <ns> get pod <pod> -o jsonpath='{.metadata.annotations.io\.katacontainers\.config\.runtime\.cc_init_data}'
export TEST_POD_ANNOTATIONS='{"io.katacontainers.config.runtime.cc_init_data":"<从上面那条命令取到的 base64>"}'

# 注意：**不要**把原 Pod 的注解整份照抄。其中
#   io.containerd.cri.runtime-handler            -> 会把 runtime 劫持回原 handler，测试 pod 不走我们的
#   io.katacontainers.config.hypervisor.kernel_params -> 空值会覆盖掉 kata 配置里的 rdinit=，TAA 不再启动
# 两者都会让验证静默失效（Pod 照样 Ready，但根本不是被测路径）。

# build-initrd.sh 的输入
# 走仓库根 deploy-taa-vm.sh 时**不用设**这两个：它自带默认值（平台地址跟随
# REMOTE_HOST，端口 PLATFORM_PORT=18080；DOCKER_ID=kata-csv2-taa-test-0001），
# 要用别的值再覆盖。下面列出来是因为手动分步执行 build-initrd.sh 时仍需显式给，
# 且两者必须成对（只给一个会被拒）。
# 取值参考：在跑的 osr pod 里注入的就是 PLATFORM_IP=172.16.10.178:18080
# （宿主上 18080 由 ccs-node-agent 监听）。DOCKER_ID 每个实例必须唯一，别照抄
# osr pod 的 2c928086a11a54d301a11acb7d1c0000，否则平台会看到两个实例共用一个身份。
export TAA_PLATFORM_IP=172.16.10.178:18080
export TAA_DOCKER_ID=kata-csv2-taa-test-0001
# 证明闸门：1（默认）= TAA 自校验不通过就不启动 kata-agent，Pod 停在 NotReady
export TAA_REQUIRE_ATTESTATION=1
# TAA_REQUIRED：1（默认）= TAA 起不来时同样不让 kata-agent 启动
export TAA_REQUIRED=1
```

---

## 1. 仅查询，不执行部署

先登录远程服务器，查看现有 Kata / containerd / Kubernetes 信息。

```bash
ssh "${REMOTE}"
```

远程服务器上可执行：

```bash
# 查看 Kata 原始配置
sudo grep -nE '^(initrd|kernel|firmware|kernel_params|image)\s*=' \
  /opt/kata/share/defaults/kata-containers/configuration-qemu-csv2.toml

# 查看容器运行时配置
sudo grep -nE 'version\s*=\s*2|\[plugins\."io\.containerd\.grpc\.v1\.cri"|runtimes|ConfigPath' \
  /etc/containerd/config.toml

# 查看当前 containerd / kubelet / kata 状态
systemctl status containerd --no-pager
systemctl status kubelet --no-pager

# 查看节点与 RuntimeClass
kubectl get nodes
kubectl get runtimeclass
kubectl get pod -A | grep -E 'taa|kata' || true
```

如果你还想确认 CSV VM 里 TAA 容器的状态，可以参考 `deploy.sh` 的默认值：

```bash
export TARGET_NAMESPACE=osr
export TARGET_POD=taa-env-slim-base-402ca5dd0469c7c9-594c85455c-sfzkq
export TARGET_CONTAINER=taa-env-slim-v2
```

然后在远程宿主机上查询：

```bash
# k8s 模式
kubectl -n "${TARGET_NAMESPACE}" get pod "${TARGET_POD}" -o wide
kubectl -n "${TARGET_NAMESPACE}" exec "${TARGET_POD}" -c "${TARGET_CONTAINER}" -- sh -lc 'pwd; id; env | sort | sed -n "1,80p"'

# 如果需要查看容器内 TAA 相关文件
kubectl -n "${TARGET_NAMESPACE}" exec "${TARGET_POD}" -c "${TARGET_CONTAINER}" -- sh -lc '
  ls -l /root/taa /root/taa/attestation 2>/dev/null || true
  ls -l /root/taa/hrk.cert /root/taa/hsk_cek.cert 2>/dev/null || true
'
```

---

## 2. 本地构建带 TAA 的 CSV initrd

先从宿主拉取权威 base 资产（initrd / kernel / OVMF）。**不要**用历史里入库过的那份：
它的 gzip 流是截断的，`gzip -t` 会失败，构建脚本会直接拒绝。

```bash
cd /home/hjy/taa/deploy/guest-build
REMOTE_USER=root ./build-initrd.sh fetch-base
```

`fetch-base` 会打印每个文件的 sha256、字节数与 initrd 的条目数——记到 `base/source-paths.txt`，
下次能看出 base 是否被换过。

构建前先编出**静态链接**的 TAA（initrd 里没有 glibc；动态链接版会被 `check_build_inputs` 拒绝）：

```bash
cd /home/hjy/taa
CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa
```

然后构建 initrd：

```bash
cd /home/hjy/taa/deploy/guest-build
TAA_PLATFORM_IP="${TAA_PLATFORM_IP}" \
TAA_DOCKER_ID="${TAA_DOCKER_ID}" \
./build-initrd.sh build
```

构建结果默认输出到：

```bash
/home/hjy/taa/deploy/guest-build/out/kata-containers-initrd-taa-csv.initrd
```

摘要里会打印 base 的 sha256 与条目数、以及全部追加条目。**条目数必须等于
`base 条目数 + 追加条数`**，不等就说明有重复或丢失，脚本会拒绝发布。

如果你暂时只想构建，不想生成 `/etc/default/taa.env`，可以不设置 `TAA_PLATFORM_IP` / `TAA_DOCKER_ID`，但后续 `deploy` 可能会拒绝。
注意：只要 `TAA_ADDR` / `TAA_REQUIRED` / `TAA_REQUIRE_ATTESTATION` 中任何一个偏离默认值，
env 文件仍会生成（否则构建期覆盖会静默失效）。

证明闸门：默认 `TAA_REQUIRE_ATTESTATION=1`，即 TAA 的自校验不通过就不启动 kata-agent，
Pod 停在 NotReady。要观察"降级也能起来"的行为才需要 `TAA_REQUIRE_ATTESTATION=0`。

---

## 3. 上传 initrd 并安装远程 guest bundle

```bash
cd /home/hjy/taa/deploy/guest-build
REMOTE_USER="${REMOTE_USER}" \
REMOTE_HOST="${REMOTE_HOST}" \
./build-initrd.sh deploy
```

这一步会在远程服务器上安装：

- `initramfs.img`
- `vmlinuz`
- `OVMF.fd`

目标目录是：

```bash
${REMOTE_BUNDLE_DIR}
```

---

## 4. 配置 Kata / containerd / RuntimeClass 并拉起测试 Pod

这一步现在是**本地渲染 → 上传 → 远端安装**：`.toml` 和 YAML 全部在本地生成，
因此同样的文件既是 `launch` 的输入，也是可以直接交给别人的交付物。

### 4.1 先渲染交付包（本地，不访问宿主）

`launch` 会自己渲染一次到临时目录；要把配置留存或交付时，显式渲染到固定目录：

```bash
cd /home/hjy/taa/deploy/guest-build
./build-initrd.sh render
```

产物在 `dist/kata-qemu-csv2-taa/`：

- `config/kata-config.toml` — 改写后的 Kata hypervisor 配置
- `config/containerd-runtime-handler.toml` — containerd handler 片段（供审阅）
- `k8s/runtimeclass.yaml`、`k8s/test-pod.yaml`
- `install.sh`、`render.py`、`measure.py` — 包内自带的安装器、合并器与度量计算器
- `manifest.env` — 本次交付的全部参数，以及度量输入/结果（`KERNEL_PARAMS`、
  `OVMF_SHA256`、`KERNEL_SHA256`、`INITRD_SHA256`、`MEASUREMENT_HEX`、
  `MEASUREMENT_BASE64`、`MEASUREMENT_CMDLINE`、`MEASUREMENT_SMP`）
- `cmdline.txt` — 计算预期度量所用的 QEMU `-append` 原文（输入齐全时才生成）
- `SHA256SUMS` — 包内文件校验和
- `README.md` — 包内使用说明，含预期 MEASUREMENT

渲染是离线的：`REMOTE_HOST` 不参与，也不执行 ssh/scp。Kata 配置模板来自
`fetch-base` 拉下来的宿主权威副本 `base/configuration-qemu-csv2.toml`；
宿主的模板变了就要重新 `fetch-base` 再 `render`，否则安装时会因模板 sha 不一致而拒绝。

`render` 会顺带算出预期 MEASUREMENT：

- 公式：`SM3(OVMF || 哈希表)`，哈希表里按 cmdline、initrd、kernel 各放一个 SHA256，
  cmdline 是 QEMU 实际 `-append` 的字节（末尾换行替换为 NUL）
- 输入：`base/` 下的 OVMF/kernel、`out/` 下的 initrd；任一缺失时包照样生成，
  但 README/manifest 会标成 `MEASUREMENT_STATUS=unavailable`
- cmdline 由渲染后的 Kata 配置推导（`kernel_params`、`enable_debug`、
  `debug_console_enabled`、`default_vcpus`）；`nr_cpus` 和调试参数最终由 Kata 版本决定，
  所以安装后以 `/proc/<qemu>/cmdline` 里的实际值为准重算（见 §5）
- 需要手工指定时可用 `MEASURE_SMP`、`MEASURE_APPEND` 覆盖

交付包只含配置，不含 initrd/kernel/OVMF（约 153 MB）。对方宿主仍需先有 bundle
（由 `deploy` 或 `build-initrd.sh deploy` 放置），包里的 `install.sh` 会在缺失时明确报错，
并在安装前核对 bundle 三个文件的 sha256 与包内记录一致（度量就是基于它们算的）。

### 4.2 在目标宿主上安装

```bash
cd /home/hjy/taa/deploy/guest-build
REMOTE_USER="${REMOTE_USER}" \
REMOTE_HOST="${REMOTE_HOST}" \
TEST_NODE_NAME="${TEST_NODE_NAME}" \
RUNTIME_HANDLER="${RUNTIME_HANDLER}" \
TEST_POD_ANNOTATIONS="${TEST_POD_ANNOTATIONS}" \
./build-initrd.sh launch
```

`launch` 等价于：`render` → `scp` 到远端临时目录 → `sudo bash install.sh`。
`install.sh` 会自动完成：

1. 校验包内 `SHA256SUMS`、宿主 Kata 模板 sha、base initrd sha，以及 bundle 三个文件的 sha256
2. 安装新的 Kata 配置：
   - `/etc/kata-containers/configuration-qemu-csv2-taa.toml`
3. 在 `containerd` 中新增 runtime handler：
   - `kata-qemu-csv2-taa`
4. 重启 `containerd`——**只有在配置真的变了才重启**（先 `cmp` 一次，未变化就打印
   `containerd 配置未变化，跳过重启`）。这决定了 `launch` 对已在跑的 Pod 有没有动效
5. 视配置可选重启 `kubelet`
6. 创建 Kubernetes `RuntimeClass`
7. 创建测试 Pod（带 `TEST_POD_ANNOTATIONS`）
8. 等待 Pod Ready；超时会打印 Pod 状态与 `Events:` 再退出
9. 校验 QEMU 是否使用了新的 initrd
10. 从 QEMU 的 `/proc/<pid>/cmdline` 取实际 `-append`，用包内 `measure.py` 重算
    MEASUREMENT，并与包内预期值对照（不一致只告警，并打印实际 cmdline）

手工在目标宿主上安装同一个包时：

```bash
cd dist/kata-qemu-csv2-taa
sha256sum -c SHA256SUMS
sudo bash install.sh --dry-run   # 先看会改什么
sudo bash install.sh
```

`install.sh` 支持 `--dry-run`、`--skip-template-check`、`--skip-base-check`；
包里的 `manifest.env` 记录绝对路径与节点名，所以包是**目标宿主特定**的，换宿主或换
`REMOTE_BUNDLE_DIR` 要重新 `render`。

`TEST_IMAGE` 默认就是宿主上**已有**的镜像 `172.16.10.178:31313/taa-env:slim-v2-20260916`
（本地 registry，guest 拉得通，且带 curl 供 verify 使用）。改成 Docker Hub 上的 tag 会等满
180s 后 `StartError`：guest 内没有到外网的路由。

如果你想一次性执行全部步骤：

```bash
cd /home/hjy/taa/deploy/guest-build
REMOTE_USER="${REMOTE_USER}" \
REMOTE_HOST="${REMOTE_HOST}" \
TAA_PLATFORM_IP="${TAA_PLATFORM_IP}" \
TAA_DOCKER_ID="${TAA_DOCKER_ID}" \
TEST_NODE_NAME="${TEST_NODE_NAME}" \
./build-initrd.sh all
```

---

## 5. 手工验证点

如果你是想确认流程有没有走通，重点看这几个地方：

```bash
# 远程 Kata 配置里必须出现新 initrd
sudo grep -nE '^(kernel|initrd|firmware|kernel_params)\s*=' \
  /etc/kata-containers/configuration-qemu-csv2-taa.toml

# containerd 里必须有 runtime handler
sudo grep -nF '[plugins."io.containerd.grpc.v1.cri".containerd.runtimes."kata-qemu-csv2-taa"]' \
  /etc/containerd/config.toml

# RuntimeClass 必须存在
kubectl get runtimeclass kata-qemu-csv2-taa

# 测试 Pod
kubectl get pod test-kata-csv2-taa -o wide
kubectl describe pod test-kata-csv2-taa

# TAA 是否真的在跑：/v1/taa/* 全部是 POST-only（GET 得到 405），容器里只有 curl
kubectl exec test-kata-csv2-taa -- curl -s -X POST localhost:6001/v1/taa/health

# 取证明（attestationValues 里已解掩码的 digest 就是报告的 MEASUREMENT）
kubectl exec test-kata-csv2-taa -- \
  curl -s -X POST localhost:6001/v1/taa/getAttestation \
  -H 'Content-Type: application/json' -d '{"requestId":"probe"}'

# 用实际 QEMU append 重算预期度量（在宿主上执行；与包内 README 的 hex 对照，
# 也应与上面 getAttestation 的 digest 一致）
pkg=/path/to/kata-qemu-csv2-taa
pid=$(ps -eo pid=,args= | grep -F qemu | grep -F /opt/kata/share/kata-containers/taa-csv-20260901/initramfs.img | awk '{print $1}' | head -1)
tr '\0' '\n' < /proc/$pid/cmdline | grep -A1 '^-append$' | tail -n1 > /tmp/append
echo >> /tmp/append
python3 "$pkg/measure.py" digest \
  --ovmf /opt/kata/share/kata-containers/taa-csv-20260901/OVMF.fd \
  --kernel /opt/kata/share/kata-containers/taa-csv-20260901/vmlinuz \
  --initrd /opt/kata/share/kata-containers/taa-csv-20260901/initramfs.img \
  --cmdline /tmp/append
```

---

## 6. 常见变量速查

### guest-build/build-initrd.sh

- `REMOTE_USER=root`（需免密 sudo 或直接是 root；脚本会在写入前先检查）
- `REMOTE_HOST=172.16.10.178`
- `REMOTE_BUNDLE_DIR=/opt/kata/share/kata-containers/taa-csv-20260901`
- `REMOTE_KATA_CONFIG=/etc/kata-containers/configuration-qemu-csv2-taa.toml`
- `RUNTIME_HANDLER=kata-qemu-csv2-taa`
- `DIST_DIR=dist/kata-qemu-csv2-taa`（`render` 的固定输出目录）
- `KATA_CONFIG_TEMPLATE=base/configuration-qemu-csv2.toml`（宿主权威模板，`fetch-base` 拉取）
- `LAUNCH_KEEP_DIST=1`（`launch` 用的临时渲染结果额外复制一份到 `DIST_DIR`）
- `MEASURE_OVMF` / `MEASURE_KERNEL` / `MEASURE_INITRD`：预期度量的本地输入
  （默认 `base/` 下的 OVMF/kernel 与 `out/` 下的 initrd）
- `MEASURE_SMP`：覆盖推导出的 `nr_cpus=`（默认取渲染配置的 `default_vcpus`）
- `MEASURE_APPEND`：整条覆盖推导出的 QEMU `-append`（单行）
- `TEST_POD_NAME=test-kata-csv2-taa`
- `TEST_IMAGE=172.16.10.178:31313/taa-env:slim-v2-20260916`（宿主本地 registry；guest 无外网）
- `TEST_POD_ANNOTATIONS='{}'`（该宿主上需填 `cc_init_data`，见 §0）
- `TAA_REQUIRED=1`、`TAA_REQUIRE_ATTESTATION=1`（证明闸门）
- `TAA_PLATFORM_IP`、`TAA_DOCKER_ID`：平台注册身份，必须成对。由**驱动**给默认值
  （`172.16.10.116:${PLATFORM_PORT}` / `kata-csv2-taa-test-0001`；平台跑在自己的宿主上，
  不跟随 `REMOTE_HOST`），直接调 `build-initrd.sh` 时默认仍为空。用
  `ALLOW_MISSING_TAA_ENV=1` 可显式放弃注册（注册失败本就只是 warning，不影响 TAA 启动）
- 本地输入覆盖（主要给测试用）：`BASE_INITRD`、`INITRD_OUT`、`TAA_SRC`、`TAA_INIT_SRC`、`TAA_CONFIG_SRC`

### ../deploy.sh

- `TARGET_NAMESPACE=osr`
- `TARGET_POD=taa-env-slim-base-402ca5dd0469c7c9-594c85455c-sfzkq`
- `TARGET_CONTAINER=taa-env-slim-v2`
- `REMOTE_DIR=/root/taa`
- `PLATFORM_PORT=18080`（非 DEBUG）
- `PLATFORM_PORT=28080`（DEBUG）

---

## 7. 备注

- 这份模板**不执行部署**，只整理可复制命令。
- 合一入口与清理见仓库根的 `deploy-taa-vm.sh`：`up` / `render` / `verify` /
  `delete [--dry-run] [--force]` / `print-config`（打印解析后的实际取值，确认这次会用什么）；
  离线自测是根目录的 `./test-deploy-taa-vm.sh` 和 `deploy/guest-build/test-render.sh`。
- 真实密码、证书、环境变量值请按现场环境填入，不要直接写死到仓库。
- 如果远程 base initrd 与本地 `guest-build/base/` 不一致，`build-initrd.sh deploy` 可能会拒绝，需要先同步 base 文件。
- base 资产**不入库**（`base/*.img`、`base/*.container`、`base/*.fd`、`base/*.toml`、`out/`、
  `dist/` 已在 `.gitignore` 里）：
  宿主机是权威，入库的副本只会静默过期——历史上那份 `out/kata-containers-initrd-taa-csv.initrd`
  与 base 逐字节相同，就是复制品而非构建产物。用 `./build-initrd.sh fetch-base` 取
  （同时拉 Kata 配置模板，供 `render` 使用）。
- 宿主上做度量预测时注意 `csv-measure.py` 的四个坑：必须 `python3 <脚本>` 调用（shebang 指向
  不存在的 `/usr/libexec/platform-python`）；`--cmdline` 收**文件**；**输出是 base64 不是 hex**；
  `--smp` 必填且 `--vcpumodel host` 与真机 QEMU 参数绑定。真机记录见 spec 的 §5.5。
  包内 `render/measure.py` 是同一算法的 stdlib 实现（纯 Python SM3，无 pysmx 依赖）：
  `render` 用它离线算预期值，宿主上也能直接用它复核 `csv-measure.py` 的结果。
- 注入的 TAA 必须是静态链接的：`CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa`。
- wrapper（`taa-init.sh`）的判定逻辑有单测：`./test-taa-init.sh`，改动后先跑它。
