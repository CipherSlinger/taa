# Pod 内 semgrep 验证：无网环境下不能调 --validate

日期：2026-10-14
状态：已实现

## 背景

`./deploy.sh remote taa` 在上一轮修复后走到了新加的「provisioning code scan engine inside container」，
注入与规则拷贝都成功，但最后一步验证失败：

```
command terminated with exit code 2
 ✗ code scan engine verification failed inside the container (semgrep --validate --config /opt/taa/semgrep/rules)
```

同一份 payload（同一个镜像 `taa-env:slim-v2`）在宿主 docker 容器里工作正常：
`semgrep --validate --config /opt/taa/semgrep/rules` → `Configuration is valid - found 0
configuration error(s), and 24 rule(s).`，`semgrep --version` → `1.177.0`。差别只在环境：
**Pod 里没有出网路由**，容器在宿主上有。

## 实测证据（全部在 172.16.10.178 的 kata CSV2 Pod `taa-env-slim-v2-20260916-…-rmjwc` 内，逐条 bounded）

| 命令（Pod 内） | 结果 |
| --- | --- |
| `semgrep --version` | 打印 `1.177.0` 后**不退出**；60s 内被 timeout 杀掉（rc=124），离线环境中约 **98s** 后才自己 rc=0 |
| `SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off semgrep --version --disable-version-check` | `1.177.0`，**rc=0**，秒回 |
| 同上但只加 `--disable-version-check`、不带环境变量（在 `--network none` 容器里对照） | 同样 **rc=0**（2.4s）：**开关才是承重的，环境变量是保险** |
| 部署脚本原来那行：`semgrep --validate --config /opt/taa/semgrep/rules >/dev/null 2>&1 && …` | **rc=2，约 200s 后**——这就是日志里的 `command terminated with exit code 2` |
| `semgrep --validate … --disable-version-check`（带全部离线开关） | 仍然失败/卡住：**任何开关都救不了** |
| 生产 argv：`semgrep scan --config /opt/taa/semgrep/rules --json --quiet --disable-version-check --no-git-ignore --max-memory 1024 <probe>` | **rc=0，4 秒**，1783 字节 JSON，stderr 为空 |
| 同一生产 argv，但**不带**任何 `SEMGREP_*` 环境变量（模拟引擎自身调用） | 同样 **rc=0，4 秒** |

机制（进程内实测，不是推断）：卡住的进程是 `/usr/bin/python3 …/pylib/bin/pysemgrep`，
`wchan=do_sys_poll`，fd 指向 `10.244.0.20 → 10.96.0.10:53` 的 UDP socket（**查询发出，永无应答**）。
Pod 的 `/etc/resolv.conf` 指向集群 DNS `10.96.0.10`，guest **完全没有出网**（到 `1.1.1.1:443` 也是超时，
只有 `172.16.10.178:22` 通）。DNS 解析不受 HTTP 超时约束，而 `AppSession` 在此之上还有
`Retry(total=3, backoff_factor=16)` 的退避（16/32/64s），所以一次不带开关的调用要一分半以上才放弃。

`--validate` 为什么救不了：它在验证用户规则之前，**无条件**加载 semgrep 官方托管的 metacheck
规则包 `p/semgrep-rule-lints`（`core_runner.validate_configs()`），没有任何 flag / 环境变量能跳过；
离线时这次下载抛出未被 `SemgrepError` 捕获的 `ConnectionError`，直接把进程带走（rc=2）。这是
**结构性**的，不是缺一个开关。

## 设计

1. **验证改用生产 argv**（`semgrep scan`），不再是 `--validate`：
   - 参数与 `internal/codeaudit/semgrep_engine.go` 的 `semgrepArgs` 对齐（`--config` / `--json` /
     `--quiet` / `--disable-version-check` / `--no-git-ignore` / `--max-memory`，后者与
     `DefaultSemgrepMaxMemoryMB`=1024 保持一致）；
   - 探针是两行 `os.system(1)`，被随仓库发布的 CMD_001 规则命中；
   - 判定条件与引擎在审计路径上的判定一致：退出码 0、`errors` 为空、目标文件确实被读、**且至少有一个
     finding**。最后一条是新增的：规则能加载但匹配不到任何东西，正是「审计悄悄查不出问题」的静默失败。
2. **所有 semgrep 调用离线 + 有界**：`SEMGREP_SEND_METRICS=off` + `SEMGREP_ENABLE_VERSION_CHECK=0`
   + `--disable-version-check`，并套 `timeout`（默认 90s，可用 `SEMGREP_OFFLINE_TIMEOUT` 覆盖）。
   - 离线开关让检查**根本不发起**；有界是给「开关之前构建出来的 payload」兜底——正在运行的 Pod 里装的
     就是老 wrapper，没有它有界，部署会永远挂住而不是报错。
   - `timeout` 是 coreutils，极简镜像可能没有，所以用 `bounded()` 包装函数降级为不设界，而不是误判成
     「引擎缺失」去重装。
3. **验证每次部署都跑**，不再依赖「探测到引擎已存在就跳过」：探测只能证明文件在，证明不了它在这个容器里
   能跑——这次故障正是把「在」当成了「能用」。
4. **失败必须可诊断**：保留 semgrep 自己的 stderr（原来是 `>/dev/null 2>&1` 丢掉的），并说明离线与有界的
   原因；上一次失败只留下 kubectl 的 `exit code 2`，无从判断。
5. **payload wrapper 内置离线开关**（`build-semgrep-payload-container.sh`）：让部署脚本、TAA 自己的审计
   路径、人手敲的 `semgrep` 都不必各自记得加开关。

## 被否掉的方案

- **保留 `--validate`，只加开关**：实测带全部开关仍然卡死，方案不成立。
- **把「打印了输出后卡住」判成成功**：等于把引擎在审计路径上会卡死这件事吞掉，且掩盖真实故障。
- **只加 `timeout` 不加开关**：每次部署白等 90s，且审计路径的问题（若存在）被隐藏。
- **在 Pod 里手改 wrapper 环境变量**：修的是现象不是来源；改为在 payload 构建配方里落定。

## 影响面与未做

- 生产审计路径**实测无碍**：Pod 内裸跑引擎 argv（不带任何 `SEMGREP_*` 环境变量，只有
  `--disable-version-check`）rc=0、4 秒、JSON 正常，所以不需要改 `semgrep_engine.go`。附带结论：
  引擎那行若丢了 `--disable-version-check`，结果**仍然正确**（JSON 照出，`errors: []`），只是退出前要多等
  约 100s 的退避——5 分钟的扫描死线兜得住，但会白等。
- **其余裸 `semgrep --version` 调用点未改**：`deploy-docker.sh:330`、
  `deploy/guest-build/test-semgrep-payload.sh:122`。它们落在有出网的宿主/容器里，今天不会出问题；
  在没有出网的环境里最多是白等约 100s 后退避结束（rc 仍为 0），不是新故障。`build-semgrep-payload-container.sh`
  自己的验证步骤已因 wrapper 内置开关而随之安全。
- **没有能让 Pod 具备解析能力的改动**：Pod 完全没有出网（TCP 到 `1.1.1.1:443` 也超时），这是部署环境的
  事实，本设计只让引擎不依赖网络，不去打通网络。
- initrd 配方（`build-semgrep-payload.sh`）的 wrapper 未加这两个环境变量：guest 同样无网，
  `SEMGREP_SEND_METRICS=off` 在测试脚本里是显式传的（`test-semgrep-payload.sh`）。本次未改，因为
  initrd 内容进 MEASURED 摘要，属于另一条链路的决定。
- 正在运行的 Pod 里装的是老 wrapper（无这两个环境变量），**不需要重装**：部署脚本自带开关，审计路径
  也实测正常。
