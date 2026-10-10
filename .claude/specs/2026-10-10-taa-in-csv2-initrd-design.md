# 把 TAA 放进 Kata CSV2 initrd，使 MEASUREMENT 覆盖 TAA（2026-10-10）

- **状态**：设计已定，待实现
- **日期**：2026-10-10
- **宿主**：`root@172.16.10.178`（`hygon-master`），kata CSV2 机密容器
- **目标路线**：**先路线 A**（`kata-qemu-csv2`，**不涉及 DCU**），完成后再做路线 B
- **相关文件**：`deploy/guest-build/build-initrd.sh`、`deploy/guest-build/base/`、`configs/taa-production.json`、`pkg/csvattest/constants.go`
- **前序**：`.claude/specs/2026-10-10-dcu-passthrough-route-evaluation-design.md`

---

## 1. 目标与验收口径

**目标**：让 TAA 出现在 CSV2 的 `MEASUREMENT` 里，并且**在 TEE 内真正运行**。

验收口径（本轮明确）：

| 项 | 要求 |
| :--- | :--- |
| TAA 运行位置 | VM 内（initramfs 阶段起，PID 1 交还 kata-agent 后持续运行） |
| 网络 | 应答 `:6001` |
| 证明 | 能出**真实**的 CSV 证明报告（非降级空报告） |
| LLM 扫描 | **不要求**在 VM 内，后续分开部署 |
| DCU | **本轮不涉及** |

---

## 2. 度量口径：为什么必须是 initrd

```
MEASUREMENT = SM3( OVMF || table{ cmdline, initrd, kernel } )
```

**容器镜像与 rootfs 磁盘不进度量。** 因此要让 TAA 出现在 `MEASUREMENT` 里，TAA 只能落在
initrd（或 kernel / cmdline）中——这是"注入 initrd"而不是"改镜像"或"改磁盘"的全部理由。

**路线 A 的注入点天然存在**，不需要先回答"`image=` 与 `initrd=` 同时给是什么语义"
（前序 spec §2/§7 的未决项 2）。实测：

```
/opt/kata/share/defaults/kata-containers/configuration-qemu-csv2.toml
  15: kernel = "/opt/kata/share/kata-containers/vmlinuz-confidential-csv.container"
  16: initrd = "/opt/kata/share/kata-containers/kata-containers-initrd-confidential-csv.img"
  65: kernel_params = "cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1"
  69: firmware = "/opt/kata/share/ovmf/OVMFCSV.fd"
  （无 image=）

/etc/containerd/config.toml
 213: ConfigPath = "/opt/kata/share/defaults/kata-containers//configuration-qemu-csv2.toml"
```

**`kata-qemu-csv2` 本来就是 kernel + initrd 的 measured boot。** 前序 spec 里"`image=` 在第 17 行、
`initrd=` 在第 16 行被注释"描述的是 **`configuration-qemu-hygon-dcu-csv2.toml`**（DCU 那份），
不是这一份。**未决项 2 就此关闭**。

---

## 3. 实测事实基线

### 3.1 guest 的启动结构

| 事实 | 证据 |
| :--- | :--- |
| PID 1 是 **kata-agent** | `usr/sbin/init` = 普通文件 **19,024,912 B**；`strings` 命中 `kata-agent` |
| 没有 systemd 可执行文件 | `lib/systemd/systemd`、`usr/lib/systemd/systemd` 均不在 manifest |
| `etc/systemd`、`usr/lib/systemd/system/*.service` 存在但是**死物** | 发行版底包残留，没有解释器执行它们 |
| `/sbin/init` 可用 | `sbin -> usr/sbin`（符号链接）、`usr/bin/sh -> dash` |
| 根级 `init` | `init -> /sbin/init`，即内核默认 init |
| `mknod` / `mount` 可用 | `usr/bin/mknod`、`usr/bin/mount` 在 manifest |
| `/dev` 里有**上千个真实设备节点** | `dev/ttyS*`、`dev/vcsa*` … |
| 顶层是 merged-usr | `bin lib lib32 lib64 libx32 sbin` 均指向 `usr` |

**两条硬结论**：

1. **只能有一个挂点**：`kernel_params` 追加 `init=/usr/local/bin/taa-init`。systemd unit 方案
   在本镜像里不成立（没有 systemd）；把 TAA 放进容器镜像或 rootfs 磁盘则**不进度量**。
2. **注入必须 append-only**。「解包 → 重打包」会丢设备节点（`/dev/console` 等），这一条写在
   `build-initrd.sh` 头部注释里，本次实测（上千个真实节点）再次确认。

### 3.2 目录与节点的在位情况

base initrd 里**已存在**：`/tmp` `/var/tmp` `/opt` `/etc` `/run` `/var` `/dev` `/proc` `/sys`。
**不存在**：`/dev/csv-guest`、`/etc/taa`。

### 3.3 仓库资产与宿主的偏差（本次新发现）

| 资产 | 仓库 | 宿主真身 | 判定 |
| :--- | :--- | :--- | :--- |
| initrd | 12,058,624 B / 265 条目 / `48da6bed…` | **57,258,203 B / 4682 条目 / `a19d387c…`** | **仓库这份是坏的（gzip 流截断）且过期** |
| kernel | `cc7e8e9f…` | `cc7e8e9f…` | 一致 |
| OVMF | `508b8679…` | `508b8679…` | 一致 |

并且 `out/kata-containers-initrd-taa-csv.initrd` 的 SHA **与 `base/` 完全相同**（都是 `48da6bed…`）
→ **那个"已构建产物"是 base 的复制品，不是产物。**

265 vs 4682 这个差值本身就是证据：`cpio -t` 在截断的 gzip 流上只读到 265 条就停了。

### 3.4 TAA 的启动依赖（读代码得出）

`internal/app/taa/app.go` 的 `RunWithConfig` 顺序：

| 步 | 行为 | 对本设计的意义 |
| :--- | :--- | :--- |
| 1 | `if cfg.EnableLLM` → `probeInferenceService`，失败时 **fail-closed 直接 `return err`** | 必须 `llm.enabled=false` |
| 2 | keys 目录 `MkdirAll 0o700`，生成 SM2 密钥对与 `state.sealed` | rootfs 可写即可，**不要预建**（预建易踩 0700 权限校验） |
| 4 | `prepareAttestationReport` | **完全降级安全**：生成失败只 warning，写空报告；`VerifyReport` 失败也只 warning |
| 5 | `registerPlatform` 失败只 warning | 不需要管控平台在线 |
| 6 | `buildSecurityConfig` → `codeaudit.NewEngine` | `regex` 走 `return regexEngine{...}, nil`，**无失败模式**；`semgrep` 会 `os.Stat` rules 路径，缺失即启动失败 |
| 6 | `ensureSecurityDirectories` `MkdirAll 0o755` | `/opt/taa/**` 自建 |

设备路径常量：`pkg/csvattest/constants.go:60 defaultCSVGuestDevice = "/dev/csv-guest"`
（裸 QEMU 路线实测为 misc 设备 `10, 256`）。

**第 4 步是本次最关键的一条**：证明失败**不会**阻止 TAA 启动，只会静默降级成空报告。
所以"pod 起来了"完全不能证明"证明是真的"——验收必须直接看日志里的
`attestation report verified successfully` / `continuing with empty report` 二者之一。

---

## 4. 设计

### 4.1 启动模型

```
kernel: init=/usr/local/bin/taa-init
          │
          ├─ 加载 /etc/default/taa.env（PLATFORM_IP / DOCKER_ID）
          ├─ mknod /dev/csv-guest（若缺失）
          ├─ 后台起 TAA（-config /etc/taa/taa-config.json -addr 0.0.0.0:6001）
          ├─ sleep 2 探活；失败时按 TAA_REQUIRED 决定是否继续
          └─ exec /sbin/init    ← 把 PID 1 原样交还 kata-agent
```

`exec /sbin/init` **不修改**：`sbin -> usr/sbin` 是符号链接，这条本来就对，落地即 kata-agent。
`TAA_REQUIRED=1`（默认）时 TAA 起不来就死循环、pod 不 Ready——这是有意的 fail-closed。

### 4.2 注入清单（6 个新条目）

| 路径 | 来源 | 缺失后果 |
| :--- | :--- | :--- |
| `usr/local/bin/taa` | `CGO_ENABLED=0` 静态构建（约 19.8 MB） | 现有 `rootfs/usr/local/bin/taa` 是**动态链接**（glibc），initramfs 内必崩 |
| `usr/local/bin/taa-init` | 脚本内 heredoc | —— |
| `etc/taa/taa-config.json` | 新增仓库文件 | config 是硬依赖且**不搜索路径** |
| `etc/taa/certs/hrk.cert` | `deploy/certs/hrk.cert`（832 B） | 证明**自校验失败** |
| `etc/taa/certs/hsk_cek.cert` | `deploy/certs/hsk_cek.cert`（2916 B） | 同上 |
| `etc/default/taa.env` | 构建时 `TAA_PLATFORM_IP` / `TAA_DOCKER_ID` | wrapper 跳过 TAA 启动 |

注入方式不变（append-only）：

```
gzip -dc base > base.cpio
cpio -o -H newc -R 0:0 -A -F base.cpio --quiet   # 只追加新条目
gzip -n -9 < base.cpio > candidate
```

`etc/taa` 与 `etc/taa/certs` 由现有 `append_missing_parent_dirs` 自动补（base 里没有）。
**`/opt/taa/**` 不预建**——TAA 自己 `MkdirAll`，且 keys 目录要求 0700，预建只会引入权限风险。

### 4.3 `configs/taa-initrd.json`（新增）

以 `configs/taa-production.json` 为基线，**只有四处差异**：

| 项 | 生产值 | initrd 值 | 理由 |
| :--- | :--- | :--- | :--- |
| `server.addr` | `:6001` | `:6001` | 不变 |
| `security.codeScanEngine` | `semgrep` | **`regex`** | semgrep 构造时 `os.Stat` rules 路径，缺失即**启动失败**；regex 无失败模式、无外部依赖 |
| `security.semgrepRulesPath` | `/opt/taa/semgrep/rules` | **删除** | regex 引擎不读它 |
| `llm` | 一大段 | **`{"enabled": false}`** | 关掉 `probeInferenceService`；它默认 fail-closed，会直接终止启动 |
| `attestation.*CertPath` | `/root/taa/certs/*` | **`/etc/taa/certs/*`** | 与注入路径一致 |

其余（`storage` / `model` 的 `/opt/taa/**`、`resultCheck`）保持生产值。

### 4.4 wrapper 的三处修改

```sh
# 1) 补 -config（现状只传 -addr，TAA 会去 CWD 找 taa-config.json 并 os.Exit(1)）
/usr/local/bin/taa -config /etc/taa/taa-config.json -addr "$TAA_ADDR" >/tmp/taa.log 2>&1 &

# 2) 补 mknod（插入在起 TAA 之前）
#    kata 的 guest 内核内建 csv-guest 驱动、misc 设备已注册，但节点不在 initramfs 里。
#    设备号从 sysfs 读，不写死：宿主模块与 guest 内建的 minor 未必相同。
if [ ! -e /dev/csv-guest ] && [ -r /sys/class/misc/csv-guest/dev ]; then
  mknod /dev/csv-guest c \
    "$(cut -d: -f1 /sys/class/misc/csv-guest/dev)" \
    "$(cut -d: -f2 /sys/class/misc/csv-guest/dev)"
fi
```

第 3 处 **不是**新代码：`exec /sbin/init "$@"` 保持不变。

`set -eu` 下 mknod 失败会让 wrapper 直接退出（PID 1 退出 = kernel panic）。因此 mknod 用
`[ -e ]` 先判、且不加 `-e` 之外的额外严格性；若 sysfs 不存在则跳过（此时报告会降级，
由验收第 4 条负责发现）。

### 4.5 `build-initrd.sh` 的改动（精确到行）

| 位置 | 现状 | 改成 |
| :--- | :--- | :--- |
| `:19` `TAA_SRC` | `$ROOT_DIR/bin/taa` | 保持路径，但在 `check_build_inputs` 里**断言静态链接**（`file` 含 `statically linked`，或 `ldd` 报 `not a dynamic executable`），否则拒绝构建 |
| `:222-257` wrapper heredoc | 无 `-config`、无 mknod | 按 §4.4 补两处 |
| `:264-272` env 文件 | 只写 `TAA_ADDR`/`PLATFORM_IP`/`DOCKER_ID`/`TAA_REQUIRED` | 不变 |
| `:279-282` `append_entries` | 只有 `taa`、`taa-init` | 增加 `etc/taa/taa-config.json`、`etc/taa/certs/hrk.cert`、`etc/taa/certs/hsk_cek.cert`；证书用 `install -m 0644` 落到 `extra/etc/taa/certs/` |
| `:318` 校验循环 | **硬编码** `usr/local/bin/taa usr/local/bin/taa-init` | 改成遍历 `append_entries`——否则新加的条目没有任何校验 |
| `:331` 发布 | `mv candidate → INITRD_OUT` | 不变（失败不覆盖旧产物，这个设计是对的） |

新增：把 `configs/taa-initrd.json` 拷进 `extra/etc/taa/taa-config.json`（`install -m 0644`），
并在 `check_build_inputs` 里校验它存在。

**`deploy_remote` 与 `launch_remote` 不需要改动。** 它们已经实现了正确的隔离（新 bundle 目录、
新 kata 配置文件、新 handler、新 RuntimeClass），本轮改动完全落在 `build_initrd` 一侧。

### 4.6 base 资产的治理

**决策：从 git 移除 base 的大文件，新增 `fetch-base` 子命令从宿主拉真身。**

理由：base 的权威在宿主机（kata 装什么就是什么），入库的副本只会**静默过期**——现在这份假的
`out/` 正是这么来的。55 MB 进 git 也是纯浪费。

| 动作 | 对象 |
| :--- | :--- |
| `git rm --cached` | `base/kata-containers-initrd-confidential-csv.img`、`base/vmlinuz-confidential-csv.container`、`base/OVMFCSV.fd`、`out/initramfs.img`、`out/kata-containers-initrd-taa-csv.initrd` |
| 新增 `.gitignore` | `deploy/guest-build/base/*.img`、`base/*.container`、`base/*.fd`、`out/` |
| 保留在 git | `base/source-paths.txt`（记录宿主来源路径）、`build-initrd.sh`、`csv2-deploy-command-template.md` |
| 新增子命令 | `fetch-base`：从 `$REMOTE_BASE_INITRD_SRC` / `$REMOTE_KERNEL_SRC` / `$REMOTE_OVMF_SRC` scp 到 `base/`，并打印 SHA-256 与条目数 |
| 打印校验 | `build_initrd` 开头打印 base 的 SHA-256 与条目数，作为"这份 base 是什么"的现场记录 |

`fetch-base` 复用脚本已有的 `REMOTE_*` 变量与 ssh 惯用法；`REMOTE_USER` 默认 `osr`，
本次实操用 `root`（与凭据来源一致），通过环境变量覆盖。

---

## 5. 验证

| # | 验证项 | 判据 |
| :--- | :--- | :--- |
| 1 | 构建完整性 | 条目数 `4682 → 4682+6`；新增条目与 `append_entries` 逐条一致 |
| 2 | **度量确实变了** | 宿主上 `csv-measure.py` 对 base 与 taa 版各算一次 MEASUREMENT，**两者必须不同**——这是"度量覆盖 TAA"的直接证据 |
| 3 | QEMU 真的用了新 initrd | pod 起来后宿主 `ps -eo args=` 里 `-initrd` 指向 taa 版路径 |
| 4 | TAA 真的在跑 | 容器内 `wget -qO- localhost:6001`（kata 的 pod netns 即 guest netns）有应答 |
| 5 | **证明是真的** | TAA 日志出现 `attestation report verified successfully`，而**不是** `continuing with empty report` |
| 6 | 回归 | 原 `kata-qemu-csv2` handler 与其配置文件零改动；新 handler 为 `kata-qemu-csv2-taa`，新配置文件 `configuration-qemu-csv2-taa.toml`。逐层证据见 §5.1 |
| 7 | 不撞共享 pod | 测试 pod 名 `test-kata-csv2-taa`（默认值），与共享的 `dcu-tee-test` 无交集 |

第 2 条是最有力的一条：它把"TAA 在 initrd 里"翻译成一个**可比较的密码学量**，
而不是"文件确实被追加了"这种间接推断。

### 5.1 爆炸半径：哪些 pod 会拿到含 TAA 的 initrd

**结论：只有显式声明 `runtimeClassName: kata-qemu-csv2-taa` 的 pod。** 四条隔离各自独立，
逐行核过：

| 隔离层 | 新 | 原（只读，不写） | 证据 |
| :--- | :--- | :--- | :--- |
| initrd 文件 | `<bundle>/initramfs.img`（`taa-csv-20260901/`，新目录） | `/opt/kata/share/kata-containers/kata-containers-initrd-confidential-csv.img` | `:445` 装进新目录，原文件未被触碰 |
| kata 配置 | `/etc/kata-containers/configuration-qemu-csv2-taa.toml` | `/opt/kata/share/defaults/…/configuration-qemu-csv2.toml` | `:560` 先 `cp` 成副本再改；`:660` 装到新路径 |
| containerd handler | `kata-qemu-csv2-taa` | `kata-qemu-csv2` | `:679` target 为该 handler；`:724-731` 只删它自己的块 |
| RuntimeClass | 新建 `kata-qemu-csv2-taa` | 现有 14 个 | `:848-858` |

`dcu-tee-test` 走 `kata-qemu-hygon-dcu-csv2` → `configuration-qemu-hygon-dcu-csv2.toml`，
与本流程零交集。

**唯一的宿主级动效**：`:821` `sudo systemctl restart containerd`（新 handler 必须重启才生效）。

- 正在运行的容器**不会**被杀（shim 是独立进程，containerd 重启后重连）；
- 但重启窗口内**新建容器、镜像拉取、`kubectl exec`** 会短暂失败——若此刻有人正在用
  `dcu-tee-test`，`exec` 可能被打断，**pod 本身与 DCU 卡不受影响**；
- 脚本带回滚（`:807-813`：起不来就还原备份配置再启一次），但**回滚重启若也失败，
  containerd 会停在那里**。这是本流程风险最高的一步，执行前应确认无人在用集群。

**其它两个小项**（不影响隔离性）：测试 pod 用 `nodeName` 固定调度（`:874`），`TEST_IMAGE`
默认 `busybox:latest`（`:58`）——该 tag 拉不下来会卡在 `:886` 的 180s 等待；用宿主上已有的
镜像覆盖 `TEST_IMAGE` 即可。测试 pod 名默认 `test-kata-csv2-taa`，与 `dcu-tee-test` 不重名。

---

## 6. 非目标

- **不做 DCU 透传**。本轮用 `kata-qemu-csv2`（非 DCU handler），**完全不碰那张卡**，
  因此前序 spec 记录的"不复位换手"缺陷不阻塞本设计。
- 不把 LLM 扫描放进 VM（用户已明确后续分开部署）。
- 不改 `pkg/csvattest`、不改 `internal/app/taa`、不改 `configs/taa-production.json`。
- 不做路线 B（`csv2-vm.sh`）——那是本设计完成后的下一轮。
- 不把 `:6001` 暴露到集群外（NodePort/Service 另议）。

---

## 7. 风险与未决

1. **`/sys/class/misc/csv-guest/dev` 在 kata guest 内是否可读**——若不可读则 mknod 跳过、
   报告降级。验收第 5 条会直接暴露。若发生，退路是写死 `10, 256`（裸 QEMU 路线实测值）。
2. **静态二进制体积**（19.8 MB）会把 initrd 从 55 MB 推到约 75 MB。QEMU 与 pod 启动时间
   会受影响，但可接受。
3. **`fetch-base` 之后 base 与宿主再次漂移**——这是把资产移出 git 的固有代价，
   由"每次 build 打印 SHA + 条目数"来暴露。
4. **`regex` 引擎与生产 `semgrep` 不同**——本轮只要求 TAA 起来并出证明，不要求扫描等价。
   扫描能力的等价性属于另一条线（见 semgrep 相关 spec）。
5. **`out/` 从 git 移除后，历史里的假产物仍可被 checkout 出来**——在文件头注释里点明，
   避免后来者把它重新当成真的构建产物。
