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

先把远程原始 initrd 放到：

```bash
mkdir -p guest-build/base
# 该文件需要从远程服务器复制回来
# guest-build/base/kata-containers-initrd-confidential-csv.img
```

构建前先确认本地二进制存在：

```bash
make taa
make attestation-ioctl
```

然后构建 initrd：

```bash
cd /mnt/d/可信数字空间/tee/guest-build
TAA_PLATFORM_IP="${TAA_PLATFORM_IP}" \
TAA_DOCKER_ID="${TAA_DOCKER_ID}" \
./build-initrd.sh build
```

构建结果默认输出到：

```bash
/mnt/d/可信数字空间/tee/guest-build/out/kata-containers-initrd-taa-csv.initrd
```

如果你暂时只想构建，不想生成 `/etc/default/taa.env`，可以不设置 `TAA_PLATFORM_IP` / `TAA_DOCKER_ID`，但后续 `deploy` 可能会拒绝。

---

## 3. 上传 initrd 并安装远程 guest bundle

```bash
cd /mnt/d/可信数字空间/tee/guest-build
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
cd /mnt/d/可信数字空间/tee/guest-build
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
cd /mnt/d/可信数字空间/tee/guest-build
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
