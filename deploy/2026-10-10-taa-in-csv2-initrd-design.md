> 权威副本在 `.claude/specs/2026-10-10-taa-in-csv2-initrd-design.md`；本文件是随 `deploy/` 分发的副本。

# 把 TAA 放进 Kata CSV2 initrd，使 MEASUREMENT 覆盖 TAA（2026-10-10，v2）

- **状态**：设计已定，待实现；**§0 的宿主判定实验先跑**（不阻塞开工，但决定 v1 那条 `init=` 到底有没有生效过）
- **日期**：2026-10-10（v2 修订同日）
- **宿主**：`root@172.16.10.178`（`hygon-master`），kata CSV2 机密容器
- **目标路线**：**先路线 A**（`kata-qemu-csv2`，**不涉及 DCU**），完成后再做路线 B
- **相关文件**：`deploy/guest-build/build-initrd.sh`、`configs/taa-production.json`、`configs/taa-initrd.json`（新增）、`pkg/csvattest/constants.go`、`CLAUDE.md`、`README.md:482`
- **前序**：`.claude/specs/2026-10-10-dcu-passthrough-route-evaluation-design.md`
- **v1 → v2 改了什么**：见 §8。v2 修掉两处会让 TAA 根本不启动/悄悄降级的问题（`init=` 无效、`/sys` 未挂载），并把两条站不住的验收判据换成可机器判定的形式。

---

## 0. 先决条件：宿主上一条判定实验

v1 §3.1 自己写着 initrd **根级存在 `init -> /sbin/init`**；而内核 `kernel_init()` 的顺序是
**先试 `rdinit=`（默认 `/init`），成功了就不再理会 `init=`**（见 §3.2）。两者不能同时成立：
要么 v1 的事实有误，要么 v1 §4.1 的 `init=/usr/local/bin/taa-init` 从来没生效过。

**这不阻塞实现**——`rdinit=` 在两种情况下都优先，§4 一律用 `rdinit=`。但答案决定了
"v1 那套注入为何从未把 TAA 拉起来"的解释，也决定 §7 里要不要清理历史结论。

**一次 ssh 问完，不要连打**（该账号有 faillock，失败几次即锁）：

```bash
ssh root@172.16.10.178 'bash -s' <<'EOS'
set -u
B=/opt/kata/share/kata-containers/kata-containers-initrd-confidential-csv.img
C=/opt/kata/share/defaults/kata-containers/configuration-qemu-csv2.toml
echo "== base initrd =="; ls -l "$B"; sha256sum "$B"
gzip -t "$B" && echo "gzip: OK" || echo "gzip: BROKEN"
echo -n "entries: "; gzip -dc "$B" | cpio -t 2>/dev/null | wc -l
echo "== root-level init =="; gzip -dc "$B" | cpio -tv 2>/dev/null | grep -E ' (init|rdinit)( ->|$)'
echo "== kata config =="; grep -nE '^[[:space:]]*(kernel|initrd|image|firmware|kernel_params)[[:space:]]*=' "$C"
echo "== measure tool =="; ls -l /opt/hygon/csv/confidential-containers/scripts/csv-measure.py
EOS
```

要回答的三件事：

| # | 问题 | 影响 |
| :--- | :--- | :--- |
| 1 | 真实 base initrd 的 `init` 条目是否存在、是不是 `-> /sbin/init` 的符号链接 | 解释 v1 的空转；`rdinit=` 的取值不受影响 |
| 2 | 真实 base 的 size / sha256 / 条目数（预期 57,258,203 B / `a19d387c…` / 4682） | §4.9 `fetch-base` 的期望值 |
| 3 | `configuration-qemu-csv2.toml` 的 `kernel_params` 现值 | §4.6 的补丁落点 |

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
| `usr/local/bin/taa-init` | 脚本内 heredoc（§4.4） | 无 init，pod 永远起不来 |
| `etc/taa/taa-config.json` | 新增仓库文件 `configs/taa-initrd.json` | TAA `os.Exit(1)` |
| `etc/taa/certs/hrk.cert` | `deploy/certs/hrk.cert`（832 B） | 证明**自校验失败**（报告退化为 false） |
| `etc/taa/certs/hsk_cek.cert` | `deploy/certs/hsk_cek.cert`（2916 B） | 同上 |
| `etc/default/taa.env` | 构建时 `TAA_PLATFORM_IP` / `TAA_DOCKER_ID` | 仅影响注册（§4.4 已不再以它作为起 TAA 的前提） |
| `etc/taa`、`etc/taa/certs` | 父目录，由 `append_missing_parent_dirs` 补 | cpio 里路径不全 |

注入方式不变（append-only）：

```
gzip -dc base > base.cpio
cpio -o -H newc -R 0:0 -A -F base.cpio --quiet   # 只追加新条目
gzip -n -9 < base.cpio > candidate
```

**`/opt/taa/**` 与 `/root/taa/**` 都不预建**——TAA 自己 `MkdirAll`，且 keys 目录要求 0700，
预建只会引入权限风险。

**条目数**：`4682 → 4682 + 8`（6 个文件 + 2 个新目录）。v1 §5 写的 `+6` 漏算了目录——
今天 `etc/default` 那一个目录就是这么算进去的。

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

### 4.4 wrapper 全文（`usr/local/bin/taa-init`）

落进 `build-initrd.sh` 的 heredoc 时注意：该 heredoc 是**非引号** `<<EOF`，运行时变量要写 `\$`，
构建期变量写 `$`。以下是**最终文件内容**。

```sh
#!/bin/sh
# taa-init — kata CSV2 initrd 的首个用户态进程（rdinit=）。
#
# PID 1 退出等于 kernel panic，所以本脚本不依赖 set -e：
# 每一步失败都必须自行吞掉或显式处理，唯一允许的退出路径是最后那句 exec。
set -u

CONSOLE=/dev/console
TAA_BIN=/usr/local/bin/taa
TAA_CONFIG=/etc/taa/taa-config.json
TAA_LOG=/tmp/taa.log
ENV_FILE=/etc/default/taa.env

log() { echo "taa-init: $*" >"$CONSOLE" 2>/dev/null || true; }

[ -r "$ENV_FILE" ] && . "$ENV_FILE"
cd / || true

TAA_ADDR="${TAA_ADDR:-0.0.0.0:6001}"
TAA_REQUIRED="${TAA_REQUIRED:-1}"
TAA_REQUIRE_ATTESTATION="${TAA_REQUIRE_ATTESTATION:-1}"

fail_taa_required() {
  log "$1"
  if [ "$TAA_REQUIRED" = "1" ]; then
    [ -r "$TAA_LOG" ] && cat "$TAA_LOG" >"$CONSOLE" 2>&1
    log "TAA_REQUIRED=1; not starting kata-agent"
    while true; do sleep 3600; done
  fi
}

# 1) 挂 proc/sys。本脚本在 kata-agent 之前运行，这两个目录此刻是空的，
#    而下一步取 csv-guest 次设备号要读 /proc/misc 或 /sys/class/misc/…。
mount -t proc  proc  /proc >/dev/null 2>&1 || true
mount -t sysfs sysfs /sys  >/dev/null 2>&1 || true

# 2) 建 /dev/csv-guest。驱动内建且已 misc_register()，缺的只是节点；
#    主设备号固定 10，次设备号动态分配，必须现读（2026-10-09 实测配方）。
if [ ! -e /dev/csv-guest ]; then
  csv_minor=""
  if [ -r /proc/misc ]; then
    while read -r minor name; do
      if [ "$name" = "csv-guest" ]; then csv_minor="$minor"; break; fi
    done < /proc/misc
  fi
  if [ -z "$csv_minor" ] && [ -r /sys/class/misc/csv-guest/dev ]; then
    IFS=: read -r csv_major csv_minor < /sys/class/misc/csv-guest/dev || true
  fi
  if [ -n "$csv_minor" ]; then
    if mknod /dev/csv-guest c 10 "$csv_minor" 2>/dev/null; then
      chmod 600 /dev/csv-guest 2>/dev/null || true
      log "created /dev/csv-guest (10, $csv_minor)"
    else
      log "WARNING: mknod /dev/csv-guest c 10 $csv_minor failed"
    fi
  else
    log "WARNING: csv-guest minor unreadable; attestation will degrade to an empty report"
  fi
fi

# 3) 起 TAA。门槛是"config 可读"——它是 TAA 的硬依赖；
#    PLATFORM_IP/DOCKER_ID 只影响注册，而注册本来就只是 warning（app.go:135）。
TAA_PID=""
if [ -r "$TAA_CONFIG" ]; then
  "$TAA_BIN" -config "$TAA_CONFIG" -addr "$TAA_ADDR" >"$TAA_LOG" 2>&1 &
  TAA_PID="$!"
else
  fail_taa_required "missing $TAA_CONFIG; not starting TAA"
fi

# 4) 探活（进程活着 ≠ 服务可用，这里只证明它没立刻退出）
if [ -n "$TAA_PID" ]; then
  sleep 2
  kill -0 "$TAA_PID" >/dev/null 2>&1 || fail_taa_required "TAA exited immediately"
fi

# 5) 证明闸门。上面两步都不构成"证明是真的"：证明失败时 TAA 会
#    WARNING + 写空报告继续跑（app.go:548），pod 照样 Ready。
#    这里把验收判据前移：等到自校验成功那一行为止。
if [ -n "$TAA_PID" ] && [ "$TAA_REQUIRE_ATTESTATION" = "1" ]; then
  i=0
  while [ "$i" -lt 60 ]; do
    if [ -r "$TAA_LOG" ]; then
      grep -q "attestation report verified successfully" "$TAA_LOG" 2>/dev/null && break
      grep -q "continuing with empty report" "$TAA_LOG" 2>/dev/null &&
        fail_taa_required "attestation degraded to an empty report (see log above)"
    fi
    sleep 1
    i=$((i + 1))
  done
  [ "$i" -ge 60 ] && fail_taa_required "attestation verdict not found in $TAA_LOG within 60s"
fi

exec /sbin/init "$@"
```

两处 v1 没有的防护值得点名：

- `TAA_PID` 先置空再判空。v1 在 `TAA_REQUIRED=0` 且缺环境变量时会走到
  `kill -0 "$TAA_PID"`（未绑定变量）——`set -u` 下 shell 退出 = **PID 1 退出 = kernel panic**。
- 第 5 步的等待上限 60 s：TAA 的证明在 `startServer` 之前完成，正常是亚秒级；
  60 s 只是给慢盘/慢密钥生成的余量。代价是 pod 就绪被推迟约 2–3 s。

### 4.5 `build-initrd.sh` 的改动（精确到行）

| 位置 | 现状 | 改成 |
| :--- | :--- | :--- |
| `:19` `TAA_SRC` | `$ROOT_DIR/bin/taa` | 路径不变；在 `check_build_inputs` 里**断言静态链接**（`file "$TAA_SRC"` 含 `statically linked`），并把 `file` 加进 `require_cmd` |
| `:142` `check_build_inputs` | 只查可执行 | 增加：① 静态链接断言；② **`gzip -t "$BASE_INITRD"` 必须通过**（这一条就能拦住今天这份被静默截断的 base）；③ `configs/taa-initrd.json` 与两份证书存在 |
| `:222-257` wrapper heredoc | 无 `-config`、无 mount、无 mknod、无证明闸门 | 整段替换为 §4.4 |
| `:263-272` env 文件 | 写 `TAA_ADDR`/`PLATFORM_IP`/`DOCKER_ID`/`TAA_REQUIRED` | 不变，另加 `TAA_REQUIRE_ATTESTATION` |
| `:277-282` `append_entries` | 只有 `taa`、`taa-init` | 增加 `etc/taa/taa-config.json`、`etc/taa/certs/hrk.cert`、`etc/taa/certs/hsk_cek.cert`；构建时 `install -m 0644` 落到 `extra/etc/taa/certs/` |
| `:283-300` `append_missing_parent_dirs` | 只对 `base_manifest` 去重 | **先去重再加**：同时检查 `append_entries`（新增 `in_append_entries()` 辅助函数）。否则按 §4.2 调三次会把 `etc/taa`、`etc/taa/certs` 重复追加 2–3 次——正是 `:281` 注释警告的"后出现的目录条目覆盖前面的" |
| `:316-322` 校验循环 | **硬编码** `usr/local/bin/taa usr/local/bin/taa-init` | 改成遍历 `append_entries`；并断言候选条目数 **== base 条目数 + `${#append_entries[@]}`**（重复/丢失都能当场发现） |
| `:331` 发布 | `mv candidate → INITRD_OUT` | 不变（失败不覆盖旧产物，这个设计是对的） |
| `:334-349` 摘要 | 只打印两个 payload | 打印 base 的 **sha256 + 条目数**、全部 `append_entries`、候选条目数 |

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
- initrd 体积：静态 `bin/taa` 约 21 MB（v1 写的 19.8 MB 是 §3.1 那个 kata-agent 的大小，
  串了行）。initrd 55 MB → 约 76 MB，且 initramfs 是**常驻 guest 内存**的。若要把体积降下来，
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

`fetch-base` 复用脚本已有的 `REMOTE_*` 变量与 ssh 惯用法；`REMOTE_USER` 默认 `osr`，
本次实操用 `root`（与凭据来源一致），通过环境变量覆盖。

---

## 5. 验证

### 5.1 判据

| # | 验证项 | 判据 |
| :--- | :--- | :--- |
| 1 | 构建完整性（**构建期自动**） | `gzip -t base` 通过；候选条目数 == base + `len(append_entries)`；`append_entries` 每条都在候选 manifest 里；无重复条目 |
| 2 | **度量确实覆盖 initrd（最强）** | 宿主 `csv-measure.py` 对**同一条 cmdline + taa 版 initrd** 算出的 MEASUREMENT，必须与 guest 内 `getAttestation` 取回报告**解掩码后**的 MEASUREMENT **逐位相同**。预测值 == 实测值，同时证明"initrd 进度量"与"报告的度量字段不是垃圾" |
| 3 | 变量隔离对照 | 固定 cmdline，只换 initrd（base ↔ taa）→ 必须不同；固定 initrd，只换 cmdline → 也必须不同。否则 §2 的混淆项会把 cmdline 的效应记到 initrd 头上 |
| 4 | QEMU 真的用了新 initrd | pod 起来后宿主 `ps -eo args=` 里 `-initrd` 指向 taa 版路径 |
| 5 | TAA 真的在跑 | 容器内 `wget -qO- localhost:6001/v1/taa/health`（kata 的 pod netns 即 guest netns）有应答 |
| 6 | **证明是真的** | `POST /v1/taa/getAttestation` 返回非空报告；且 pod Ready 与 `TAA_REQUIRE_ATTESTATION=1` 同时成立（即 §4.4 第 5 步的闸门放行） |
| 7 | 回归 | 原 `kata-qemu-csv2` handler 与其配置文件零改动；新 handler `kata-qemu-csv2-taa`、新配置文件 `configuration-qemu-csv2-taa.toml`。逐层证据见 §5.3 |
| 8 | 不撞共享 pod | 测试 pod 名 `test-kata-csv2-taa`（默认值），与共享的 `dcu-tee-test` 无交集 |

第 2 条取代了 v1 的"两者必须不同"：v1 那条会因为**错误的原因通过**（cmdline 也变了）。

宿主判据工具的两个坑（实测）：`csv-measure.py` 的 shebang 指向本机不存在的
`/usr/libexec/platform-python`，必须 `python3 <脚本>` 调用；`--cmdline` 收的是**文件**
（内容为命令串 + 末尾换行，脚本会去掉末字节再补 `\0`）。

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

1. **`/proc/misc` 与 `/sys/class/misc/csv-guest/dev` 在 wrapper 阶段是否可读**——先挂
   `/proc`、`/sys` 就是为了这个。若两者都读不到，报告会降级，而 §4.4 第 5 步的闸门会让
   pod 不 Ready（**这是有意的**）。退路：写死 `10, 256`（§3.5 实测值，同内核下稳定，
   换内核可能变）。
2. **静态二进制体积**约 21 MB，initrd 55 → 约 76 MB，且 initramfs 常驻 guest 内存。
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
8. **v1 那套 `init=` 是否曾经生效过**——§0 的实验给答案。若确认 `/init` 存在，则历史上任何
   声称"TAA 已在 kata csv2 里跑起来"的结论都需要重新取证。

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
