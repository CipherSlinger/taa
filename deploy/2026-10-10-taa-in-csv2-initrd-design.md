> 权威副本在 `.claude/specs/2026-10-10-taa-in-csv2-initrd-design.md`；本文件是随 `deploy/` 分发的副本。

# 把 TAA 放进 Kata CSV2 initrd，使 MEASUREMENT 覆盖 TAA（2026-10-10，v2）

- **状态**：**已实现并在真机验证通过**（2026-10-10）。`deploy/guest-build/` 与 `configs/taa-initrd.json` 已落地；本地合成 base 端到端与负例实测见 §5.4；宿主 §0 的三个问题已由真机只读实验回答（§0）；真机 `fetch-base → build → deploy → launch` 已跑通，§5.1 的 8 条判据**全部实测通过**（§5.5）。路线 A（`kata-qemu-csv2`，不涉及 DCU）到此完成，路线 B 未开始
- **日期**：2026-10-10（v2 修订同日）
- **宿主**：`root@172.16.10.178`（`hygon-master`），kata CSV2 机密容器
- **目标路线**：**先路线 A**（`kata-qemu-csv2`，**不涉及 DCU**），完成后再做路线 B
- **相关文件**：`deploy/guest-build/build-initrd.sh`、`configs/taa-production.json`、`configs/taa-initrd.json`（新增）、`pkg/csvattest/constants.go`、`CLAUDE.md`、`README.md:482`
- **前序**：`.claude/specs/2026-10-10-dcu-passthrough-route-evaluation-design.md`
- **v1 → v2 改了什么**：见 §8。v2 修掉两处会让 TAA 根本不启动/悄悄降级的问题（`init=` 无效、`/sys` 未挂载），并把两条站不住的验收判据换成可机器判定的形式。

---

## 0. 先决条件：宿主判定实验（**2026-10-10 已执行，三个问题均有答案**）

v1 §3.1 自己写着 initrd **根级存在 `init -> /sbin/init`**；而内核 `kernel_init()` 的顺序是
**先试 `rdinit=`（默认 `/init`），成功了就不再理会 `init=`**（见 §3.2）。两者不能同时成立：
要么 v1 的事实有误，要么 v1 §4.1 的 `init=/usr/local/bin/taa-init` 从来没生效过。

**结论：v1 §3.1 是对的。** 真机读数如下（只读，未改动宿主；脚本已入库为
`deploy/guest-build/host-precheck.sh` 与 `host-precheck2.sh`）：

| # | 问题 | 实测答案 |
| :--- | :--- | :--- |
| 1 | 真实 base 是否有根级 `init` | **有**：`lrwxrwxrwx init -> /sbin/init`；`sbin -> usr/sbin`，实体是 19,024,912 B 的 `usr/sbin/init` |
| 2 | base 的 size / sha256 / 条目数 | 57,258,203 B / `a19d387cfd1822d8aedcd47f443fc691d6460adabdabcf46cfbe6e28ec842287` / **4682 条**，`gzip -t` 通过 —— 三项与 §4.9 预期**完全一致** |
| 3 | 出厂 `kernel_params` | `cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1`（**本来就没有 `init=`**） |

由此得到两条对历史结论的更正：

- **`init=` 在 CSV2 guest 里是死配置**（`/init` 存在 ⇒ 内核走 `ramdisk_execute_command` 成功后就
  不再看 `execute_command`）。v1 那套注入即使被部署过，也**不会**把 TAA 拉起来。§7 第 8 条据此关闭。
- 但 v1 也**从未被部署过**：`/opt/kata/share/kata-containers/taa-csv-20260901/`、
  `/etc/kata-containers/configuration-qemu-csv2-taa.toml`、containerd 里的 `kata-qemu-csv2-taa`、
  以及对应 RuntimeClass **全都不存在**。所以历史上"TAA 已在 kata csv2 里跑起来"的说法，
  失败原因是**注入方式错了**（这一条确定），而不是"部署过但没生效"。

**一条只读的复核命令**（该账号有 faillock，失败几次即锁，**不要连打**）：

```bash
ssh root@172.16.10.178 'bash -s' < deploy/guest-build/host-precheck.sh
ssh root@172.16.10.178 'bash -s' < deploy/guest-build/host-precheck2.sh
```

第二个脚本还回答了"当前谁在跑"：2 个 `kata-qemu-csv2` VM（`osr/taa-env-slim-v2-*`）+
1 个与 containerd 无关的 libvirt 常驻 `csv2-8c16g`。`launch` 会重启 containerd，执行前须先看它。

---

## 1. 目标与验收口径

**目标**：让 TAA 出现在 CSV2 的 `MEASUREMENT` 里，并且**在 TEE 内真正运行**。

| 项 | 要求 |
| :--- | :--- |
| TAA 运行位置 | VM 内（initramfs 阶段起，PID 1 交还 kata-agent 后持续运行） |
| 网络 | 应答 `:6001` |
| 证明 | 能出**真实**的 CSV 证明报告（非降级空报告），且由 pod Ready 自身保证 |
| LLM 扫描 | **不要求**在 VM 内，后续分开部署 |
| DCU | **本轮不涉及** |

---

## 2. 度量口径：为什么必须是 initrd

```
MEASUREMENT = SM3( OVMF || table{ cmdline, initrd, kernel } )
```

**容器镜像与 rootfs 磁盘不进度量。** 因此要让 TAA 出现在 `MEASUREMENT` 里，TAA 只能落在
initrd（或 kernel / cmdline）中——这是"注入 initrd"而不是"改镜像"或"改磁盘"的全部理由。

2026-09-30 已实测坐实这份口径：initramfs 尾部加一个字节，MEASUREMENT 即变为完全不同的值；
guest 内写 200 MB 文件则度量一字不变。

**路线 A 的注入点天然存在**，不需要回答"`image=` 与 `initrd=` 同时给是什么语义"（v1 §2 的未决项 2，关闭）：

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

**注意一个混淆项**：launch 步骤同时改了 initrd **和** cmdline（§4.6 要往 `kernel_params`
里塞 `rdinit=`）。两个度量输入一起变，值当然会变——所以 §5 的判据不能只写"两者不同"。

---

## 3. 实测事实基线

### 3.1 仓库侧（本机可复现，2026-10-10 复核）

| 事实 | 证据 |
| :--- | :--- |
| 仓库里的 base initrd **是坏的**（gzip 流截断） | `gzip -t` 报 `unexpected end of file`；`cpio -t` 只读到 **265** 条 |
| `out/kata-containers-initrd-taa-csv.initrd` 是 base 的**逐字节复制品** | 两者 git blob 同为 `c2861568`，`sha256 = 48da6bed…` |
| `out/initramfs.img` 连 gzip 都不是 | `gzip -t` 报 `not in gzip format`（v1 只把它当"过期复制品"，低估了） |
| base 里 `sbin -> usr/sbin`、`usr/sbin/init` = **19,024,912 B** | 截断归档前 265 条实测（与 v1 §3.1 一致） |
| **`bin/taa` 是动态链接的**（glibc） | `file`: `dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2`；`rootfs/usr/local/bin/taa` 同样 |
| 树里没有一处 `import "C"` | `grep -rn 'import "C"'` 零命中 → `CGO_ENABLED=0` 必然可行 |
| 生产镜像本来就是 `CGO_ENABLED=0` 构建 | `deploy/manifest/docker/Dockerfile:5` |

### 3.2 guest 的启动结构与 init 选择（v1 的关键更正）

| 事实 | 证据 |
| :--- | :--- |
| PID 1 是 **kata-agent** | `usr/sbin/init` = 普通文件 19,024,912 B，`strings` 命中 `kata-agent` |
| 没有 systemd 可执行文件，`etc/systemd` 是死物 | 发行版底包残留 |
| 根级 `init -> /sbin/init`（**v1 自述**，§0 待复核） | `initrd` 的根级条目 |
| `/sbin/init`、`bin/sh -> dash`、`usr/bin/mount`、`usr/bin/mknod` 均在 | manifest |
| 顶层 merged-usr，`/dev` 里上千个真实节点 | manifest |
| **内核先试 `rdinit=`/`/init`，再试 `init=`** | 见下 |

内核 `kernel_init()` 的取序（多版本一致，且 2025-01 有一次专门澄清文档的补丁）：

```
ramdisk_execute_command (rdinit=，默认 /init)  →  execute_command (init=)  →  /sbin/init → /etc/init → /bin/init → /bin/sh
```

**结论：initrd 里存在 `/init` 时，`init=` 是死配置。** v1 的 `init=/usr/local/bin/taa-init`
（以及现有脚本 `:603` 起就有的同一处）不会让 wrapper 运行，kata-agent 照旧直接当 PID 1；
而 pod 一切正常，失败只在"TAA 不应答"上暴露。v2 一律改用 `rdinit=`。

**两条硬结论**（v1 的两条，第 1 条改写）：

1. **只有一个挂点**：`kernel_params` 追加 `rdinit=/usr/local/bin/taa-init`。systemd unit 方案在本镜像里
   不成立（没有 systemd）；把 TAA 放进容器镜像或 rootfs 磁盘则**不进度量**。
2. **注入必须 append-only**。「解包 → 重打包」会丢设备节点（`/dev/console` 等）——这条写在
   `build-initrd.sh` 头部注释里，本次实测（上千个真实节点）再次确认。

### 3.3 目录与节点的在位情况

base initrd 里**已存在**：`/tmp` `/var/tmp` `/opt` `/etc` `/run` `/var` `/dev` `/proc` `/sys`。
**不存在**：`/dev/csv-guest`、`/etc/taa`。

`/proc`、`/sys` 这两个**目录**存在 ≠ **已挂载**：本 wrapper 在 kata-agent 之前运行，此刻两者都是空目录，
挂载是 init 的活儿（§4.4 第 1 步）。

### 3.4 TAA 的启动依赖（读代码得出）

`internal/app/taa/app.go` 的 `RunWithConfig` 顺序：

| 步 | 行为 | 对本设计的意义 |
| :--- | :--- | :--- |
| 1 | `if cfg.EnableLLM` → `probeInferenceService`，失败且 `failClosed` 时 **`return err`**（app.go:78-84） | 必须 `llm.enabled=false` |
| 2 | keys 目录 `MkdirAll 0o700`，生成 SM2 密钥对与 `state.sealed`（app.go:92-115） | rootfs 可写即可，**不要预建**（预建易踩 0700 权限校验） |
| 4 | `prepareAttestationReport`（app.go:542-571） | **完全降级安全**：生成失败 → `WARNING` + 写空报告 + `return false, nil`；自校验失败同样只 WARNING。**只有"连空报告都写不下去"才返回错误**（:549-551） |
| 5 | `registerPlatform` 失败只 warning（app.go:135-137） | 不需要管控平台在线，也不需要 `PLATFORM_IP`/`DOCKER_ID` |
| 6 | `buildSecurityConfig` → `codeaudit.NewEngine` | `regex` 走 `return regexEngine{...}, nil`（`internal/codeaudit/engine.go:121`），**无失败模式**；`semgrep` 会 `os.Stat` rules 路径（`engine.go:133`），缺失即启动失败 |
| 6 | `ensureSecurityDirectories` `MkdirAll 0o755`（app.go:666-688） | `/opt/taa/**`、`/root/taa/**` 自建 |
| — | config 是**硬依赖且不搜索路径**：`config.LoadStartupConfig` 读不到文件即返错（`internal/config/config.go:205-208`）→ `cmd/taa/main.go:24` `os.Exit(1)` | 必须 `-config` 且文件必须注入 |

设备路径常量：`pkg/csvattest/constants.go:60 defaultCSVGuestDevice = "/dev/csv-guest"`。

**第 4 步是本次最关键的一条**：证明失败**不会**阻止 TAA 启动，只会静默降级成空报告。
所以"pod 起来了"完全不能证明"证明是真的"。v2 不再把它交给人工看日志（v1 §5 判据 5 的日志在
guest 里根本读不到，见 §4.8），而是把它前移成**启动闸门**（§4.4 第 5 步）。

### 3.5 设备节点：2026-10-09 在 `dcu-tee-test` 里实测通过的配方

- `csv-guest` 是 misc 设备，内建（`CONFIG_CSV_GUEST=y`），开机即 `misc_register()`；
  缺的**只是节点**（那个 guest 的 `/dev` 是 tmpfs，没有 devtmpfs、没有 udev）。
- 取证路径是 **`/proc/misc`**（`256 csv-guest`），`/sys/class/misc/csv-guest` 也在。
- 实测配方：`mknod /dev/csv-guest c 10 "$(awk '$2=="csv-guest"{print $1}' /proc/misc)"`，
  得到 `crw------- root root 10, 256`，`open()` 成功。
- **主设备号固定 10**；**次设备号是动态分配的**，换内核就可能变（本内核 = 256）。
- 整条证明链（`pkg/csvattest` 生产路径）在该节点上三轮跑通，session-MAC 与 MNonce 均校验通过。

---

## 4. 设计

### 4.1 启动模型

```
kernel: rdinit=/usr/local/bin/taa-init
          │
          ├─ 挂 /proc、/sys（PID 1 在 kata-agent 之前，没人替我们挂）
          ├─ 读 /proc/misc 取 csv-guest 次设备号 → mknod /dev/csv-guest
          ├─ 后台起 TAA（-config /etc/taa/taa-config.json -addr 0.0.0.0:6001）
          ├─ sleep 2 探活
          ├─ 等 TAA 日志出现"自校验成功"，否则按 TAA_REQUIRED 决定是否继续
          └─ exec /sbin/init    ← 把 PID 1 原样交还 kata-agent
```

**PID 1 铁律（v2 新增）**：PID 1 一旦退出，内核直接 `panic("Attempted to kill init")`，
这不是"pod 失败"而是**整台 VM 崩掉**。因此 wrapper **不依赖 `set -e`**，任何一步失败都必须
自行吞掉（`|| true`）或显式处理；唯一允许"退出"的路径是最后那句 `exec /sbin/init`。
v1 的 `set -eu` + 新增 mknod 正是这条铁律的反面教材。

`exec /sbin/init` **不修改**：`sbin -> usr/sbin` 是符号链接，这条本来就对，落地即 kata-agent。
`TAA_REQUIRED=1`（默认）时 TAA 起不来就死循环、pod 不 Ready——这是有意的 fail-closed。

### 4.2 注入清单（6 个文件 + 2 个新目录）

| 路径 | 来源 | 缺失后果 |
| :--- | :--- | :--- |
| `usr/local/bin/taa` | `bin/taa`，**必须静态链接** | 动态链接版在 initramfs 内找不到 glibc，必崩（§3.1 实测现况如此） |
| `usr/local/bin/taa-init` | 仓库文件 `deploy/guest-build/taa-init.sh`（§4.4） | 无 init，pod 永远起不来 |
| `etc/taa/taa-config.json` | 新增仓库文件 `configs/taa-initrd.json` | TAA `os.Exit(1)` |
| `etc/taa/certs/hrk.cert` | `deploy/certs/hrk.cert`（832 B） | 证明**自校验失败**（报告退化为 false） |
| `etc/taa/certs/hsk_cek.cert` | `deploy/certs/hsk_cek.cert`（2916 B） | 同上 |
| `etc/default/taa.env` | 构建时 `TAA_PLATFORM_IP` / `TAA_DOCKER_ID` | 仅影响注册（§4.4 已不再以它作为起 TAA 的前提） |
| `etc/taa`、`etc/taa/certs` | 父目录，由 `queue_entry` 补 | cpio 里路径不全 |

注入方式不变（append-only）：

```
gzip -dc base > base.cpio
cpio -o -H newc -R 0:0 -A -F base.cpio --quiet   # 只追加新条目
gzip -n -9 < base.cpio > candidate
```

**`/opt/taa/**` 与 `/root/taa/**` 都不预建**——TAA 自己 `MkdirAll`，且 keys 目录要求 0700，
预建只会引入权限风险。

**条目数**：`4682 → 4682 + 8`（6 个文件 + 2 个新目录）。v1 §5 写的 `+6` 漏算了目录——
今天 `etc/default` 那一个目录就是这么算进去的。这个数字**不写进脚本**：脚本按
`base 条目数 + len(append_entries)` 现算，`usr/local/bin` 之类若在 base 里已存在就自动不追加
（本地合成 base 上实测：父目录全缺 → +11，父目录全在 → +5/+6）。

### 4.3 `configs/taa-initrd.json`（新增）

以 `configs/taa-production.json` 为基线，只有五处差异：

| 项 | 生产值 | initrd 值 | 理由 |
| :--- | :--- | :--- | :--- |
| `server.addr` | `:6001` | `:6001` | 不变，另外 wrapper 的 `-addr` 会再覆盖一次 |
| `security.codeScanEngine` | `semgrep` | **`regex`** | semgrep 构造时 `os.Stat` rules 路径，缺失即**启动失败**（engine.go:133）；regex 无失败模式、无外部依赖（engine.go:121） |
| `security.semgrepRulesPath` | `/opt/taa/semgrep/rules` | **删除** | regex 引擎不读它；config 层只校验引擎名（config.go:285），不会因缺字段报错 |
| `llm` | 一大段 | **`{"enabled": false}`** | 关掉 `probeInferenceService`；它 fail-closed，会直接终止启动 |
| `attestation.*CertPath` | `/root/taa/certs/*` | **`/etc/taa/certs/*`** | 与注入路径一致 |

其余保持生产值，但要看清它们**不在同一个前缀下**（v1 把它们笼统写成 `/opt/taa/**`）：

```
storage.model  = /root/taa/models      storage.data   = /root/taa/data
storage.result = /root/taa/results     storage.keys   = /opt/taa/keys
model.input    = /opt/taa/input        model.checkpoint = /opt/taa/checkpoint
model.output.* = /opt/taa/output/**
```

`/root` 大概率不在 base initrd 里（§0 可顺带查），由 `ensureSecurityDirectories` 的
`MkdirAll 0o755` 建出来，不致命。

### 4.4 wrapper 的交付方式与契约

**交付方式（相对设计稿的改动）：wrapper 是仓库文件 `deploy/guest-build/taa-init.sh`，
由构建期 `install -m 0755` 落进 initrd，不再是 heredoc。**

改成独立文件的三条理由：

1. 原方案的 heredoc 是**非引号** `<<EOF`：运行时变量写 `\$`、构建期变量写 `$`。一份 60 多行的
   shell 里转义写错，出错方式是**静默的**（变量在构建期就被展开成字面量），只有真机启动才暴露。
2. 独立文件能直接 `sh -n` 检查、能被 `deploy/guest-build/test-taa-init.sh` 单测。
3. 它同时是注入清单里的一项，`git blame` 能回答"这个 initrd 里的 init 是哪一版"。

对应地，`build-initrd.sh` 的输入全部改成可用环境变量覆盖（`TAA_INIT_SRC` / `TAA_CONFIG_SRC` /
`TAA_HRK_CERT_SRC` / `TAA_HSK_CEK_CERT_SRC` / `BASE_INITRD` / `INITRD_OUT`），
于是整条构建路径能在本机用小号合成 base 端到端跑通——构建期自检本身因此是可测的。

**契约（`taa-init.sh` 必须满足的性质）**：

| 性质 | 落地形式 |
| :--- | :--- |
| 由 `rdinit=` 选中 | 根级路径 `/usr/local/bin/taa-init`；`/sbin/init` 仍是 kata-agent |
| PID 1 不退出 | 无 `set -e`；失败路径一律 `\|\| true` 或显式处理；唯一出口是最后 `exec /sbin/init "$@"` |
| 先挂 proc/sys 再建设备节点 | `mkdir -p /proc /sys` + `mount -t proc` / `mount -t sysfs`（本脚本先于 init 运行，这两个目录此刻是空的） |
| 设备节点次号现读 | 先 `/proc/misc`（2026-10-09 实测口径），退回 `/sys/class/misc/csv-guest/dev`；主号固定 10 |
| TAA 启动门槛 = config 可读 | 与 `LoadStartupConfig` 的硬依赖一致；`PLATFORM_IP` / `DOCKER_ID` 不参与判断 |
| 证明闸门 | 默认等 `attestation report verified successfully` 至多 60 s；命中 `continuing with empty report` 或超时即 fail-closed（`TAA_REQUIRED=1` 时死循环，Pod 停在 NotReady） |
| 无未绑定变量 | `TAA_PID=""` 先置空再判空（v1 在 `TAA_REQUIRED=0` 且缺环境变量时会踩 `set -u`） |

**可测的两个纯函数**（由 `test-taa-init.sh` 覆盖；`# ===== main flow` 标记行**以上必须无副作用**，
否则 source 它就会在测试进程里起 TAA 并 exec kata-agent）：

- `resolve_csv_minor`：从两个来源取次设备号；都读不到时**不打印且返回 0**；
  设备名按字段精确比较（`not-csv-guest` 不匹配）。
- `wait_for_attestation_verdict`：`0` 自校验通过 / `1` 已降级 / `2` 超时。

**与设计稿逐字稿的差异**（均为落地时的有意偏离）：

| 差异 | 理由 |
| :--- | :--- |
| 注释改英文 | 仓库规则：代码注释只用英文 |
| 抽出上述两个函数 + `# ===== main flow` 分隔行 | 让判定逻辑可单测 |
| `ATTESTATION_TIMEOUT` 可被 env 覆盖（默认仍 60） | 与其它开关一致，真机调参不必改镜像 |
| 增加 `mkdir -p /proc /sys` | base initrd 若没有这两个目录，`mount` 失败会导致次设备号取不到 |
| `TAA_LOG=/tmp/taa.log` 不变 | `/tmp` 在 base initrd 里存在；TAA 的 `attestation.report` 因 `cd /` 落在 `/attestation.report` |

第 5 步的等待上限 60 s 的依据：TAA 的证明在 `startServer` 之前完成，正常是亚秒级；
60 s 只是给慢盘/慢密钥生成的余量。代价是 pod 就绪被推迟约 2–3 s。

### 4.5 `build-initrd.sh` 的改动（精确到行）

| 位置 | 现状 | 改成 |
| :--- | :--- | :--- |
| `:19` `TAA_SRC` | `$ROOT_DIR/bin/taa` | 路径不变；在 `check_build_inputs` 里**断言静态链接**（`file "$TAA_SRC"` 含 `statically linked`），并把 `file` 加进 `require_cmd` |
| `:23` `ROOT_DIR` | `$SCRIPT_DIR/..`（guest-build 曾在仓库根下，恰好对；搬到 `deploy/` 之后解析成 `deploy/`） | 改成 `$SCRIPT_DIR/../..`，并断言 `$ROOT_DIR/go.mod` 存在。**这是落地期发现的真 bug**：不修的话 `TAA_SRC` / `TAA_CONFIG_SRC` / 两份证书的默认值全部指向不存在的路径，报出来的是「缺 build input」而不是「路径写错了」 |
| 输入路径 | 全部写死 | `TAA_SRC` / `TAA_INIT_SRC` / `TAA_CONFIG_SRC` / `TAA_HRK_CERT_SRC` / `TAA_HSK_CEK_CERT_SRC` / `BASE_INITRD` / `OUT_DIR` / `INITRD_OUT` 全部 `${VAR:-默认}`，默认值不变（§4.4 的可测性前提） |
| `:142` `check_build_inputs` | 只查可执行 | 增加：① 静态链接断言；② **`gzip -t "$BASE_INITRD"` 必须通过**（这一条就能拦住今天这份被静默截断的 base）；③ `taa-init.sh`、`configs/taa-initrd.json` 与两份证书存在；④ `require_cmd` 移到本函数之前，否则缺 `gzip` 时会报成"base 被截断" |
| `:222-257` wrapper heredoc | 无 `-config`、无 mount、无 mknod、无证明闸门 | 整段删除，改为 `install -m 0755 "$TAA_INIT_SRC" …/extra/usr/local/bin/taa-init`（§4.4） |
| 新增 | — | `install -m 0644` 把 config 落到 `extra/etc/taa/taa-config.json`、两份证书落到 `extra/etc/taa/certs/` |
| `:263-272` env 文件 | 写 `TAA_ADDR`/`PLATFORM_IP`/`DOCKER_ID`/`TAA_REQUIRED` | 不变，另加 `TAA_REQUIRE_ATTESTATION`；触发条件从"两个身份都给"扩成 `taa_env_file_needed()`——**任何一个开关偏离默认值也要写**，否则构建期覆盖静默失效 |
| 新增 | — | 追加前归一化元数据：`find extra -type d -exec chmod 0755 {} +` 且 `chmod 0644` env 文件。`mkdir` 与 shell 重定向会继承 umask，同一个脚本在两台机器上会产出**不同的度量** |
| `:277-282` `append_entries` | 只有 `taa`、`taa-init` | 增加 `etc/taa/taa-config.json`、`etc/taa/certs/hrk.cert`、`etc/taa/certs/hsk_cek.cert` |
| `:283-300` `append_missing_parent_dirs` | 只对 `base_manifest` 去重；且父目录排在文件之后 | 改成 `queue_entry()`：**同时检查 `append_entries`**（`in_append_entries()`），并把**父目录排在文件之前**。否则按 §4.2 逐文件调用会把 `etc/taa`、`etc/taa/certs` 重复追加 2–3 次——正是 `:281` 注释警告的"后出现的目录条目覆盖前面的" |
| `:316-322` 校验循环 | **硬编码** `usr/local/bin/taa usr/local/bin/taa-init` | 改成遍历 `append_entries`；并断言候选条目数 **== base 条目数 + `${#append_entries[@]}`**（重复/丢失都能当场发现） |
| `:331` 发布 | `mv candidate → INITRD_OUT` | 不变（失败不覆盖旧产物，这个设计是对的） |
| `:334-349` 摘要 | 只打印两个 payload | 打印 base 的 **sha256 + 条目数**、全部 `append_entries`、候选条目数 |
| 新增子命令 | — | `fetch-base`（§4.9）：scp 三个 base 资产到 `base/`，先落 `.part` 再 `mv`，对 initrd 跑 `gzip -t`，打印 sha256/字节数/条目数 |

**构建不可 bit 复现（已知且接受）**：newc 会写入每条目的 inode 号与 mtime，所以同样的输入
两次构建的 initrd 字节不同，度量也就不同。这不影响 §5.1 第 2 条——那条比的是**同一个产物文件**
的宿主预测值与 guest 报告值；产物的身份由摘要里打印的 sha256 承载（`deploy_remote` 也是靠它
在上传后 `sha256sum -c` 校验，而不是靠本地重建）。真要复现，需要 `cpio` 补齐 ino/mtime 归一化，
本轮不做，记在 §7。

`deploy_remote` 的隔离（新 bundle 目录、新 kata 配置文件、新 handler、新 RuntimeClass）
**不需要改动**；`launch_remote` 需要改一处，见 §4.6。

### 4.6 launch 侧：`init=` → `rdinit=`

`launch_remote` 已经做了"切 bundle、注 initrd/firmware、写 `kernel_params`"（`:558-660`），
只需把注入的键换掉：

| 位置 | 现状 | 改成 |
| :--- | :--- | :--- |
| `:558` 注释 | `设置 init=/usr/local/bin/taa-init` | `设置 rdinit=/usr/local/bin/taa-init` |
| `:603` 兜底 | `kernel_params = "init=/usr/local/bin/taa-init"` | `kernel_params = "rdinit=/usr/local/bin/taa-init"` |
| `:636-645` 改写既有 `kernel_params` | 过滤 `init=` 前缀后 `insert(0, "init=…")` | 过滤 `rdinit=` 前缀后 `insert(0, "rdinit=…")`；**不要**继续塞 `init=`（会让人以为它有用） |
| `:784` 校验 | 断言含 `init=/usr/local/bin/taa-init` | 断言含 `rdinit=/usr/local/bin/taa-init` |

### 4.7 静态构建与文档同步（v2 新增，v1 缺这一块）

v1 只写了"断言静态链接"，但没有产出静态二进制的路径——而 `CLAUDE.md:8` 与 `README.md:482`
里那条 `go build -o bin/taa ./cmd/taa` 产出的**正是会被断言拒绝的动态链接版本**。

改动：

- `CLAUDE.md` 与 `README.md:482` 的构建命令统一为
  `CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa`
  ——与生产镜像 `deploy/manifest/docker/Dockerfile:5` 一致。树里没有 `import "C"`，
  唯一的差别只是 net 解析器从 cgo 换成纯 Go。
  （注意：`CLAUDE.md` 已被 `.gitignore` 且由 `6b0bcff` 移出版本库，所以这一处**只是本机改动**，
  不会随提交分发；`README.md` 那处会。）
- initrd 体积（实测，§5.4）：`CGO_ENABLED=0` 的 `bin/taa` **18.9 MB**，而树里现存的
  `bin/taa` 是**动态链接**的 21.1 MB。v1 写的 19.8 MB 是 §3.1 那个 kata-agent 的大小，串了行。
  initrd 55 MB → 约 74 MB，且 initramfs 是**常驻 guest 内存**的。若要把体积降下来，
  构建加 `-trimpath -ldflags="-s -w"`（约 −7 MB）——本轮不做，记在 §7。

### 4.8 证据通道（v2 新增）

v1 §5 判据 5 说"TAA 日志出现 `attestation report verified successfully`"，但这条日志写在
**VM initramfs 根的 `/tmp/taa.log`**，而 `kubectl exec` 进的是**容器的 mount namespace**
（镜像 rootfs），两者不是同一个根——按 v1 的写法这条证据**取不到**；wrapper 也只在 TAA
两秒内退出时才 dump 到 `/dev/console`。

v2 的三条通道，按可靠性排序：

1. **启动闸门**（§4.4 第 5 步）：`TAA_REQUIRE_ATTESTATION=1` 时，pod Ready **本身就意味着**
   自校验通过。这是唯一不依赖运维动作的通道。
2. **`POST /v1/taa/getAttestation`**（`internal/controller/router.go:22`，POST-only）：
   从容器内打一发，它会用 `pkg/csvattest` 现场重出一份报告并返回——同时证明"TAA 在跑"
   和"`/dev/csv-guest` 真的能用"。
3. **`/dev/console`**：`fail_taa_required` 会把 `/tmp/taa.log` 倒到 console。这条要**先确认
   kata 侧捕获了 guest console**（`enable_debug` / debug console），否则失败时运维看到的现象
   只是"pod 一直不 Ready"。本轮不强制，但排查前先打开。

### 4.9 base 资产的治理

**决策：从 git 移除 base 的大文件，新增 `fetch-base` 子命令从宿主拉真身。**

理由：base 的权威在宿主机（kata 装什么就是什么），入库的副本只会**静默过期**——今天这份假的
`out/` 就是这么来的（git blob 与 base 完全相同，§3.1）。

| 动作 | 对象 |
| :--- | :--- |
| `git rm --cached` | `base/kata-containers-initrd-confidential-csv.img`、`base/vmlinuz-confidential-csv.container`、`base/OVMFCSV.fd`、`out/initramfs.img`、`out/kata-containers-initrd-taa-csv.initrd` |
| 新增 `.gitignore` | `deploy/guest-build/base/*.img`、`base/*.container`、`base/*.fd`、`out/` |
| 保留在 git | `base/source-paths.txt`、`build-initrd.sh`、`csv2-deploy-command-template.md`（`rootfs/usr/local/bin/taa` 已被 `.gitignore` 的 `bin/` 规则挡在库外，无需额外动作） |
| 新增子命令 | `fetch-base`：从 `$REMOTE_BASE_INITRD_SRC` / `$REMOTE_KERNEL_SRC` / `$REMOTE_OVMF_SRC` scp 到 `base/`，并打印 SHA-256 与条目数 |
| 打印校验 | `build_initrd` 开头打印 base 的 SHA-256 与条目数，作为"这份 base 是什么"的现场记录 |

`fetch-base` 复用脚本已有的 `REMOTE_*` 变量与 ssh 惯用法。`REMOTE_USER` 原先默认 `osr`，本次实操一路用
`root`（与凭据来源一致）；事后已把**默认值改成 `root`**——流程全程要在远端改 kata/containerd 配置并重启
服务，非 root 账号必须先配好免密 sudo，否则会在改配置的中途失败。同时给 deploy / launch / delete 三步
都加了**免密提权前置检查**（`id -u` 为 0，或 `sudo -n true` 成功），在任何写入之前就报错并给出提示。

注册身份（`PLATFORM_IP` / `DOCKER_ID`）在生产里由平台注入容器环境，CSV2 guest 没有这条注入路径，
只能构建期焊进 `/etc/default/taa.env`。**默认值放在驱动 `deploy-taa-vm.sh` 里**（
`${REMOTE_HOST}:${PLATFORM_PORT:-18080}` 与 `kata-csv2-taa-test-0001`），不放 `build-initrd.sh`：
后者里"空值"是有含义的（表示操作者没要求注册）并驱动自己的 `taa_env_file_needed()` 判定，
给默认值会让那个判定永远为真、静默产出一份想注册却注册不上的 initrd。驱动另外提供
`print-config` 打印解析后的实际取值（`KEY=%q`，可直接 eval），便于确认这一次会用到什么。

---

## 5. 验证

### 5.1 判据

| # | 验证项 | 判据 |
| :--- | :--- | :--- |
| 1 | 构建完整性（**构建期自动**） | `gzip -t base` 通过；候选条目数 == base + `len(append_entries)`；`append_entries` 每条都在候选 manifest 里；无重复条目 |
| 2 | **度量确实覆盖 initrd（最强）** | 宿主 `csv-measure.py` 对**同一条 cmdline + taa 版 initrd** 算出的 MEASUREMENT，必须与 guest 内 `getAttestation` 取回报告**解掩码后**的 MEASUREMENT **逐位相同**。预测值 == 实测值，同时证明"initrd 进度量"与"报告的度量字段不是垃圾" |
| 3 | 变量隔离对照 | 固定 cmdline，只换 initrd（base ↔ taa）→ 必须不同；固定 initrd，只换 cmdline → 也必须不同。否则 §2 的混淆项会把 cmdline 的效应记到 initrd 头上 |
| 4 | QEMU 真的用了新 initrd | pod 起来后宿主 `ps -eo args=` 里 `-initrd` 指向 taa 版路径 |
| 5 | TAA 真的在跑 | 容器内 `curl -s -X POST localhost:6001/v1/taa/health`（kata 的 pod netns 即 guest netns）有应答。**必须是 POST**：`/v1/taa/*` 全部经 `postOnly` 包装（`internal/controller/router.go`），GET 得到 405；容器内只有 `curl`，没有 `wget`（v2 初稿写成 `wget -qO-` 是错的，真机执行时更正） |
| 6 | **证明是真的** | `POST /v1/taa/getAttestation` 返回非空报告；且 pod Ready 与 `TAA_REQUIRE_ATTESTATION=1` 同时成立（即 §4.4 第 5 步的闸门放行） |
| 7 | 回归 | 原 `kata-qemu-csv2` handler 与其配置文件零改动；新 handler `kata-qemu-csv2-taa`、新配置文件 `configuration-qemu-csv2-taa.toml`。逐层证据见 §5.3 |
| 8 | 不撞共享 pod | 测试 pod 名 `test-kata-csv2-taa`（默认值），与共享的 `dcu-tee-test` 无交集 |

第 2 条取代了 v1 的"两者必须不同"：v1 那条会因为**错误的原因通过**（cmdline 也变了）。

宿主判据工具的四个坑（真机实测）：

- `csv-measure.py` 的 shebang 指向本机不存在的 `/usr/libexec/platform-python`，必须 `python3 <脚本>` 调用；
- `--cmdline` 收的是**文件**（内容为命令串 + 末尾换行，脚本会去掉末字节再补 `\0`）；基准必须是 QEMU 实际收到的
  那条 `-append`，不是 kata 配置里 `kernel_params` 的字面值；
- **输出是 base64，不是 hex**。拿 hex 正则去比对会得到"三个预测全空"，看起来像三条判据全挂；
- `--smp` 必填，且 `--vcpumodel host` 会去读 `lscpu`——两者都要与真机 pod 的 QEMU 参数一致，否则预测的是另一台机器。

### 5.2 证明链的失败模式对照

| 现象 | 含义 |
| :--- | :--- |
| pod 一直不 Ready，console 有 `taa-init: attestation degraded…` | 闸门生效：`/dev/csv-guest` 或证书有问题（这才是我们要的失败方式） |
| pod Ready，但 `getAttestation` 报错 | 说明闸门被设成 0（或 `TAA_REQUIRED=0`），属于配置失误，不是环境问题 |
| pod Ready，`getAttestation` 正常，但判据 2 对不上 | 度量口径或 cmdline 对不上，回去查 §5.1 第 3 条 |

### 5.3 爆炸半径：哪些 pod 会拿到含 TAA 的 initrd

**结论：只有显式声明 `runtimeClassName: kata-qemu-csv2-taa` 的 pod。** 四条隔离各自独立，逐行核过：

| 隔离层 | 新 | 原（只读，不写） | 证据 |
| :--- | :--- | :--- | :--- |
| initrd 文件 | `<bundle>/initramfs.img`（`taa-csv-20260901/`，新目录） | `/opt/kata/share/kata-containers/kata-containers-initrd-confidential-csv.img` | `:445` 装进新目录，原文件未被触碰 |
| kata 配置 | `/etc/kata-containers/configuration-qemu-csv2-taa.toml` | `/opt/kata/share/defaults/…/configuration-qemu-csv2.toml` | `:560` 先 `cp` 成副本再改；`:660` 装到新路径 |
| containerd handler | `kata-qemu-csv2-taa` | `kata-qemu-csv2` | `:679` target 为该 handler；`:724-731` 只删它自己的块 |
| RuntimeClass | 新建 `kata-qemu-csv2-taa` | 现有 14 个 | `:848-858` |

`dcu-tee-test` 走 `kata-qemu-hygon-dcu-csv2` → `configuration-qemu-hygon-dcu-csv2.toml`，与本流程零交集。

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

### 5.4 本机已完成的验证（落地证据，2026-10-10）

真机（172.16.10.178）尚未执行 §5.1；下面是**本机能做的全部**，用来把"构建期自检"和
"wrapper 判定逻辑"从"读起来对"变成"跑过了"。合成 base 是小号 cpio（rootfs 形状近似，
无设备节点），TAA 用 `CGO_ENABLED=0` 编的最小 Go 程序顶替。

| # | 验证 | 结果 |
| :--- | :--- | :--- |
| 1 | `deploy/guest-build/test-taa-init.sh`（9 项：次设备号两个来源、都读不到时"不打印且 rc=0"、`not-csv-guest` 不误匹配、证明三种结论、日志缺失） | 全部通过 |
| 2 | 合成 base 端到端构建（父目录全缺） | `14 → 25`，追加 11 条，顺序为父目录在文件之前 |
| 3 | 合成 base 端到端构建（父目录全在 base 里，`usr/local/bin`、`etc/taa/certs`、`etc/default` 预建） | `17 → 22`（无 env）/ `17 → 23`（有 env），只追加文件本身，**目录零重复** |
| 4 | 产物核对 | `usr/local/bin/taa-init` 与 `taa-init.sh` 逐字节相同；`init -> sbin/init` 符号链接与 base 文件均未被破坏；manifest 无重复条目 |
| 5 | 负例 8 项：动态链接 TAA、截断 base、已注入 base、缺 wrapper/config/hrk/taa 二进制、只给 `PLATFORM_IP` | 全部 `rc=1` 并有明确 `error:`，且**没有任何一次发布出产物**（旧产物不被覆盖） |
| 6 | umask 归一化 | `umask 0002` 与 `umask 0022` 下产物条目元数据一致（目录 `0755`、文件 `0644`） |
| 7 | 仓库里那份 base | `gzip -t` **失败**（`unexpected end of file`），`cpio -t` 只列 265 条 → 新增的自检确实拦得住它；sha256 `48da6bed…` |
| 8 | 仓库里那份 `out/kata-containers-initrd-taa-csv.initrd` | 与 base **逐字节相同**（再次确认 §3.1：它是复制品，不是构建产物） |
| 9 | `CGO_ENABLED=0 GOOS=linux go build -o bin/taa ./cmd/taa`（§4.7 写进文档的那条） | 2.5 s 建成，`file` 判为 `statically linked`，**18.9 MB**；同时确认树里现存的 `bin/taa` 是 `dynamically linked` 的 21.1 MB——即新断言确实拦得住它 |
| 10 | 用真 `bin/taa`（静态版）跑一遍合成 base 构建 | 通过，追加条目与用最小 fixture 时一致 |
| 11 | **不覆盖任何默认路径**的构建（只给 `BASE_INITRD` / `INITRD_OUT` / `TAA_SRC`） | 通过 → 证明 `ROOT_DIR` 修好后，`TAA_INIT_SRC`、`TAA_CONFIG_SRC`、两份证书的默认值确实都解析到了文件。第 2–4 条当时全绿，恰恰是因为它们把每条路径都显式覆盖了；**这条默认路径用例才是抓到 `ROOT_DIR` 那个 bug 的** |

第 5 条的 8 个负例是本轮唯一能证明"构建期自检真的会拦"的方式——因为它们全部在**写产物之前**
退出，所以顺带证明了"失败不覆盖上一次可用输出"这条性质。

### 5.5 真机验证记录（2026-10-10，172.16.10.178）

`fetch-base → build → deploy → launch` 全流程实跑，§5.1 八条判据逐条落地：

| # | 判据 | 实测结果 |
| :--- | :--- | :--- |
| 1 | 构建完整性 | base `a19d387c…` **4682** 条 → 候选 **4690** 条（+8，§4.2 的 6 文件 + 2 目录），`gzip -t` 通过，manifest 无重复 |
| 2 | **度量覆盖 initrd（逐位相同）** | 宿主预测 `8408bf9603b006c9b36b8819bb086ecb03c58625b23be99b7a39ab0da318a56d` == guest 报告解掩码后的 MEASUREMENT，**逐位相同** |
| 3 | 变量隔离对照 | 固定 cmdline 换 initrd（base）：`b8ad1d1168b5e1367c3acebc39adfdd4b8559a8845db6e9818c9c2f2d54a8d26`；固定 initrd 去掉 `rdinit=`：`edef46ae5de3acba91a42d7432d6adf86273ab869ed894b6d6dc52b94aeabf83` —— 两个对照都与判据 2 的值**不同** |
| 4 | QEMU 真的用了新 initrd | 宿主 `ps -eo args=`：`verified QEMU is using: /opt/kata/share/kata-containers/taa-csv-20260901/initramfs.img` |
| 5 | TAA 真的在跑 | `POST /v1/taa/health` → 200，body `ok` |
| 6 | 证明是真的 | `getAttestation` 返回 `verifiedPass: true`、报告 2548 B、chipId `SRYUY22080405`；**且** pod 在 `TAA_REQUIRE_ATTESTATION=1` 下达到 `1/1 Running`（42 s），即 §4.4 第 5 步的闸门确实放行 |
| 7 | 回归 | 原 handler 块逐字节未变、kata 配置 sha256 `30d722ca01e476affccf633a2e3eb4ce3b33b2aa3f0fe6d81d657470a9c8781d`、base initrd `a19d387c…` 均未改动 |
| 8 | 不撞共享 pod | 测试 pod 名与共享 pod 无交集 |

**一条意外的强证据**：首次 `launch` 失败时 pod 停在 `StartError`（exitCode 128），报错来自
**guest 内的 CDH 镜像拉取**（`[CDH] … tls`）。这条错误本身不可伪造地证明了链路已经走到很远：
CDH 与 attestation-agent 是**我们的 initrd 带进去的**（§4.2 清单），所以"guest 从新 initrd 启动 →
wrapper 执行 → `TAA_REQUIRE_ATTESTATION=1` 的闸门通过 → kata-agent 起来 → 才开始拉容器镜像"这一段
在执行失败之前就已经成立。

**真机新发现的环境前提（不在 v2 设计里，但不满足就跑不通）**：CoCo pod 的 `cc_init_data`
注解不能省。CDH 在 guest 内拉镜像，注册表 CA 必须经
`io.katacontainers.config.runtime.cc_init_data`（gzip+base64 的 TOML bundle，内含 `cdh.toml` 的
`[image] extra_root_certificates`）投递，否则 CDH 报 TLS 错误、pod 落在 `StartError`。

**注解不能整份照抄**：`io.containerd.cri.runtime-handler: kata-qemu-csv2` 会把 runtime 劫持回原
handler，空的 `io.katacontainers.config.hypervisor.kernel_params` 会**覆盖并抹掉**我们的 `rdinit=`
——两者都会让验证静默失效。为此 `build-initrd.sh` 新增 `TEST_POD_ANNOTATIONS`，只注入 `cc_init_data` 一个键。

**爆炸半径实测**：重启 containerd 的当时，在跑的两个 `osr/taa-env-slim-v2-*` pod 都还活着（QEMU 7067/7068
存活），journal 只清掉一个过期 shim。重启后复查更能说明问题的是**存活 pod 自身的启动时间**：
`taa-env-slim-v2-20260916-…-gw5kc` 的容器 `startedAt=2026-10-09T05:03:45Z`、`restartCount=2`——
都早于本次重启（2026-10-10），即重启**没有**打扰到它。

（同日稍后复查时 `osr` 下只剩这一个 pod，第二个已经不在了。本流程只按名字删自己的测试 pod，
从没删过别人的，所以这不是本流程造成的；但**具体原因未知**，不要写成"两个都一直活着"。）

另外 `build-initrd.sh` 现在会先 `cmp` 配置：**配置没变就跳过重启**，
把这一步的动效降到零（本次 launch 走的就是这条路径，输出 `containerd 配置未变化，跳过重启`）。

至此 §5.4 末尾列的"仍待真机回答"三项（§0 三问、§5.1 第 2–8 条、§7 第 1/3/4 条风险）**全部关闭**。

---

## 6. 非目标

- **不做 DCU 透传**。本轮用 `kata-qemu-csv2`（非 DCU handler），**完全不碰那张卡**，
  因此前序 spec 记录的"不复位换手"缺陷不阻塞本设计。
- 不把 LLM 扫描放进 VM（用户已明确后续分开部署）。
- 不改 `pkg/csvattest`、不改 `internal/app/taa`、不改 `configs/taa-production.json`。
- 不做路线 B（`csv2-vm.sh`）——那是本设计完成后的下一轮。
- 不把 `:6001` 暴露到集群外（NodePort/Service 另议）。
- 不做二进制瘦身（`-s -w`）与 initrd 裁剪，见 §7。

---

## 7. 风险与未决

1. ~~**`/proc/misc` 与 `/sys/class/misc/csv-guest/dev` 在 wrapper 阶段是否可读**~~ ——
   **已关闭（2026-10-10 真机）**：`/proc/misc` 这条路走通了，wrapper 拿到了 csv-guest 的次设备号并
   `mknod` 出 `/dev/csv-guest`，闸门放行。写死 `10, 256` 的退路**没有用上**，不必启用。
2. **静态二进制体积**实测 18.9 MB，initrd 55 → 约 74 MB，且 initramfs 常驻 guest 内存。
   QEMU 与 pod 启动时间会受影响。需要时可加 `-trimpath -ldflags="-s -w"`（约 −7 MB），
   本轮不做。
3. **TAA 起在 kata-agent 之前** ⇒ 它不在任何容器的 namespace/cgroup 里，没有监督：
   跑起来之后崩了，pod 仍然 Ready（启动闸门只覆盖启动时刻）。若需要持续可用性，
   得在 wrapper 里加一条重启循环，或在容器侧做存活探测——本轮不做，但要写进运维须知。
4. **`registerPlatform` 是启动时的一次性动作**，而 guest 网卡是 kata-agent 起来之后才配的
   （wrapper 阶段只有内核自己枚举到的 virtio 设备，没有地址）。因此**注册大概率失败**，
   现象只是 `WARNING: platform register failed`（app.go:136）。本轮验收不要求注册；
   若后续要求，把起 TAA 的时机改到"轮询到默认路由"之后（`/proc/net/route`，有界等待）。
   此条为推理，未实测。
5. **`fetch-base` 之后 base 与宿主再次漂移**——这是把资产移出 git 的固有代价，由
   "每次 build 打印 SHA + 条目数"与 `gzip -t` 自检来暴露。
6. **`regex` 引擎与生产 `semgrep` 不同**——本轮只要求 TAA 起来并出证明，不要求扫描等价。
   扫描能力的等价性属于另一条线（见 semgrep 相关 spec）。
7. **历史里的假产物仍可被 checkout 出来**（`out/` 从 git 移除后，旧提交里那份 = base 的复制品
   还在）——在 `build-initrd.sh` 文件头点名，避免后来者把它当成真的构建产物。
8. ~~**v1 那套 `init=` 是否曾经生效过**~~ —— **已关闭（2026-10-10 真机）**：`/init` 存在（§0），
   所以 `init=` 是死配置，v1 那套注入**不可能**把 TAA 拉起来。且真机上 v1 的产物（bundle / kata 配置 /
   handler / RuntimeClass）**从未被安装过**，"部署过但没生效"这一分支也不存在。历史上任何声称
   "TAA 已在 kata csv2 里跑起来"的结论都需要重新取证。
9. **构建不可 bit 复现**（§4.5 末）——newc 记录 inode 与 mtime，两次构建的 initrd 字节不同、
   度量也就不同。判据 2 不受影响（比的是同一个产物文件），但"同一份输入 ⇒ 同一份度量"这种
   说法在本流程里**不成立**，写文档时不要这么写。要复现需自行归一化 ino/mtime，本轮不做。
10. **CoCo pod 必须带 `cc_init_data` 注解**（真机新发现，§5.5）——否则 guest 内的 CDH 没有注册表 CA，
    镜像拉取 TLS 失败、pod 停在 `StartError`。这条与 initrd 注入无关，是**该宿主上所有 CoCo pod 的
    共同前提**，但很容易在"只照抄镜像和 command"时漏掉。
11. **被测 initrd 的度量依赖 cmdline 与 QEMU 参数**——宿主预测必须与 pod 实际收到的 `-append`、
    `-smp`、`-cpu` 一致才可能逐位相同（§5.1 工具坑）。换节点/换机型时预测值会变，别把
    `8408bf96…` 当成"TAA 版 initrd 的固定度量"。

---

## 8. v1 → v2 修订记录

| # | v1 | v2 | 依据 |
| :--- | :--- | :--- | :--- |
| 1 | `kernel_params` 追加 `init=/usr/local/bin/taa-init` | 改用 `rdinit=` | 内核先试 `rdinit=`/`/init`，成功即不再看 `init=`；而 v1 §3.1 自述 `/init` 存在 |
| 2 | mknod 读 `/sys/class/misc/csv-guest/dev` | 先 `mount -t proc`/`-t sysfs`；**优先 `/proc/misc`**，sysfs 备选 | PID 1 在 kata-agent 之前，两者都没挂载；`/proc/misc` 是 2026-10-09 实测取证的路径 |
| 3 | 验收 5 靠人工读 TAA 日志 | 新增 `TAA_REQUIRE_ATTESTATION` 启动闸门 + `getAttestation` 通道 | TAA 日志在 VM initramfs 根，`kubectl exec` 看不到（§4.8） |
| 4 | 起 TAA 的前提是 `PLATFORM_IP`/`DOCKER_ID` 两个环境变量 | 前提改为"config 可读" | 注册本就只是 warning（app.go:135）；旧门槛会让缺 env 的 pod 无限吊死 |
| 5 | `set -eu`，mknod 失败即 wrapper 退出 | 去掉 `set -e`，每步自吞；`TAA_PID` 置空再判空 | PID 1 退出 = kernel panic；v1 在 `TAA_REQUIRED=0` 时有未绑定变量路径 |
| 6 | `append_missing_parent_dirs` 按现状调用；条目数 `+6` | 去重同时看 `append_entries`；条目数 `+8`（6 文件 + 2 目录）；构建期加 `gzip -t` 与条目数自检 | 该函数只对 `base_manifest` 去重，调三次会重复追加目录；今天这份静默截断的 base 说明缺少完整性自检 |
| 7 | "断言静态链接"但没给构建配方 | `CLAUDE.md`/`README.md:482` 改为 `CGO_ENABLED=0`，对齐 Dockerfile:5 | 实测 `bin/taa` 当前是动态链接，v1 的断言会把构建直接卡死 |
| 8 | 验收 2 = "度量必须不同" | 改为"宿主预测值 == guest 实测值"，另加变量隔离对照 | launch 同时改 initrd 与 cmdline，旧判据会因错误原因通过 |
| 9 | base 治理的理由是"55 MB 浪费" | 补上 git blob 相同的硬证据，并新增 `gzip -t` 自检 | `out/…initrd` 与 base 的 git blob 同为 `c2861568` |
| 10 | wrapper 以 heredoc 内联进 `build-initrd.sh` | 改为仓库文件 `deploy/guest-build/taa-init.sh` + `install -m 0755` | 非引号 heredoc 里 `\$` 与 `$` 写错是静默的；独立文件可 `sh -n`、可单测（`test-taa-init.sh`）、可 blame |
| 11 | 只归一化文件权限（未提及） | 追加前 `chmod 0755` 目录 + `chmod 0644` env 文件 | `mkdir` 与 shell 重定向继承 umask，同一脚本在不同宿主上产出不同度量 |
| 12 | `ROOT_DIR = $SCRIPT_DIR/..`（未提及） | 改成 `$SCRIPT_DIR/../..`，并断言 `go.mod` 存在 | guest-build 已不在仓库根下；不改则默认输入路径全错，且错误信息误导 |
| 13 | `gzip -t` 自检只在 `check_build_inputs` | 同左，另加：静态链接断言用 `file`（新增依赖）、`fetch-base` 子命令、摘要打印 base sha256 | 落地时补齐 §4.9 的 `fetch-base`，并把 `file` 写进 `require_cmd` |
