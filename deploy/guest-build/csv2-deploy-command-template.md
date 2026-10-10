# CSV2 部署命令模板

> 说明：这份模板把 `guest-build/build-initrd.sh` 和 `../deploy.sh` 的关键信息整理成可复制执行的命令。
> 默认只用于查阅和手工执行，不会自动部署。

## 0. 先确认基础变量

下面这些值来自当前仓库脚本中的默认值；按你的实际环境替换即可。

```bash
# 远程宿主机 / Kata 侧
export REMOTE_USER=osr
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
export TEST_IMAGE=busybox:latest

# build-initrd.sh 的输入
export TAA_PLATFORM_IP=<平台IP:端口>
export TAA_DOCKER_ID=<docker_id>
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

```bash
cd /home/hjy/taa/deploy/guest-build
REMOTE_USER="${REMOTE_USER}" \
REMOTE_HOST="${REMOTE_HOST}" \
TEST_NODE_NAME="${TEST_NODE_NAME}" \
RUNTIME_HANDLER="${RUNTIME_HANDLER}" \
./build-initrd.sh launch
```

这一步会自动完成：

1. 生成新的 Kata 配置：
   - `/etc/kata-containers/configuration-qemu-csv2-taa.toml`
2. 在 `containerd` 中新增 runtime handler：
   - `kata-qemu-csv2-taa`
3. 重启 `containerd`
4. 视配置可选重启 `kubelet`
5. 创建 Kubernetes `RuntimeClass`
6. 创建测试 Pod
7. 等待 Pod Ready
8. 校验 QEMU 是否使用了新的 initrd

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
```

---

## 6. 常见变量速查

### guest-build/build-initrd.sh

- `REMOTE_USER=osr`
- `REMOTE_HOST=172.16.10.178`
- `REMOTE_BUNDLE_DIR=/opt/kata/share/kata-containers/taa-csv-20260901`
- `REMOTE_KATA_CONFIG=/etc/kata-containers/configuration-qemu-csv2-taa.toml`
- `RUNTIME_HANDLER=kata-qemu-csv2-taa`
- `TEST_POD_NAME=test-kata-csv2-taa`
- `TAA_REQUIRED=1`、`TAA_REQUIRE_ATTESTATION=1`（证明闸门）
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
- 真实密码、证书、环境变量值请按现场环境填入，不要直接写死到仓库。
- 如果远程 base initrd 与本地 `guest-build/base/` 不一致，`build-initrd.sh deploy` 可能会拒绝，需要先同步 base 文件。
- base 资产**不入库**（`base/*.img`、`base/*.container`、`base/*.fd`、`out/` 已在 `.gitignore` 里）：
  宿主机是权威，入库的副本只会静默过期——历史上那份 `out/kata-containers-initrd-taa-csv.initrd`
  与 base 逐字节相同，就是复制品而非构建产物。用 `./build-initrd.sh fetch-base` 取。
- 注入的 TAA 必须是静态链接的：`CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa`。
- wrapper（`taa-init.sh`）的判定逻辑有单测：`./test-taa-init.sh`，改动后先跑它。
