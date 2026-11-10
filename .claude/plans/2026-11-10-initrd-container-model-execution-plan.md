# 方案：initrd 形态下将模型执行搬进容器

日期：2026-11-10
状态：待评审
关联：`internal/runtime`、`internal/controller/import_processing.go`、`deploy/guest-build/taa-init.sh`

## 0. 结论摘要

1. 用**显式标记**区分形态，零推断：initrd 侧由 `taa-init.sh` 在启动 TAA 前
   `export TAA_DEPLOYMENT=initrd`；容器侧由 `taa-supervisor.sh` 设置
   `TAA_DEPLOYMENT=container`。标记缺失时用 `/proc/self/mountinfo` 根 fstype
   (`rootfs` ⇒ initrd) 兜底推断并打 WARNING。
2. 新增执行目标抽象 `internal/execenv`：`LocalTarget`（现状）与
   `ContainerTarget`（把模型/数据拷进容器根、用 `nsenter` 借容器运行时执行、
   产物拷回）。
3. `auto` 模式：initrd 形态且能唯一发现容器时走容器；否则保持现状并告警。
   容器形态永远走本地，行为与今天字节一致。

## 1. 目标与非目标

目标：

- initrd 形态下，模型 `runtimeConfig` 在 CDH 拉起的容器里执行，使用镜像自带的
  Python/依赖（实测镜像自带 numpy/pandas/sklearn/torch，模型可自带 wheels）。
- TAA 自己的职责（导入解密、审计、结果比对、平台上报）仍全部在 init 根完成。
- 容器形态与现有部署零行为变化。

非目标：

- 不把代码审计搬进容器。
- 不支持把任意宿主路径映射进容器。
- 不改 FHE 分支（`Runner != nil` 的路径不动）。
- 不做多容器调度，只做唯一性判定与可选的 ID 消歧。

## 2. 设计前提（均已实测）

- guest init 根：`1 1 0:2 / / rw - rootfs rootfs ...`；容器根：
  `76 63 0:29 / / rw - overlay overlay ... lowerdir/upperdir=...`。
- 容器根的 overlay 超级块在 init ns 里以 `/run/kata-containers/<id>/rootfs`
  挂载，两侧 major:minor 相同（实测均为 `0:29`）——这是**不依赖路径约定**的
  发现依据。
- init ns 可读写该挂载点，写入对容器立即可见（实测：写 `/tmp/x`，容器内可读）。
- 直接在 init ns 执行镜像里的解释器会因 glibc 版本不匹配失败（2.38 vs 2.35），
  必须换 mount ns（`nsenter -m`）或 `chroot`。
- `crictl exec` 的 stdin 只是调试通道，生产 TAA 不依赖宿主 CRI。

## 3. 总体设计

### 3.1 部署标记

- `deploy/guest-build/taa-init.sh`：在启动 TAA 之前
  `export TAA_DEPLOYMENT=initrd`（放在 `PATH` 扩展处附近，不进入任何条件分支）。
- `deploy/taa-supervisor.sh`、`deploy/fhe/taa-supervisor.sh`、
  `deploy/dataanaylsis/taa-supervisor.sh`：在 `TAA_LOOP` 块**之外**
  `export TAA_DEPLOYMENT=container`（`tests/taa_supervisor_uniform_test.sh`
  依赖块内逐字节一致，不能动块内）。
- 新增 `internal/deployment/deployment.go`：
  - `type Shape int`：`Initrd` / `Container`。
  - `Detect() (Shape, bool /*explicit*/, error)`：
    读 `TAA_DEPLOYMENT`；`initrd|container` 为显式；空值走 fstype 兜底；
    其他值返回错误（与“未知扫描引擎拒绝启动”同一风格）。
  - 兜底：解析 `/proc/self/mountinfo` 第一行，`- ` 之后的 fstype 为 `rootfs`
    ⇒ `Initrd`，否则 `Container`。
- 启动日志打印形态与来源（explicit / inferred），供部署核对。

### 3.2 执行目标抽象

新增 `internal/execenv` 包：

```go
type Target interface {
    Name() string                       // "local" | "container"
    // Resolve 把 TAA 视角的目录映射为被执行进程视角的目录。
    Resolve(initPath string) string
    // Visible 把执行视角路径映射回 init ns 可读写的真实路径。
    Visible(targetPath string) string
    Prepare(ctx context.Context, spec Spec) error
    Cleanup(ctx context.Context, spec Spec)
    // Command 构造受控命令；cmd.Dir 由 target 负责。
    Command(ctx context.Context, commandLine, workDir string) *exec.Cmd
}
```

- `LocalTarget`：恒等映射；`/bin/sh -c <cmd>`；`cmd.Dir = workDir`。
- `ContainerTarget`：
  - 字段：`pid`（ns 锚点）、`rootfs`（init ns 可见路径）、`paths`（容器侧目录约定）。
  - `Resolve`：只做**白名单三元组**映射（模型目录、输入目录、输出目录/日志/
    进度），不做任意前缀重写，避免模型内容影响路径。
  - `Visible`：`filepath.Join(rootfs, targetPath)`，逐段 `lstat` 校验不是符号链接。
  - `Command`：`/usr/bin/nsenter -t <pid> -m -r -- /bin/sh -c 'cd <workDir> && <cmd>'`
    （需要 PID 视图时追加 `-p`；联机实测用的是 `-m -p -r`），
    `SysProcAttr{Setpgid:true}`（沿用现有整组 SIGKILL 语义）。
  - `Prepare`：见 3.4。
- `runtime.RunRuntimeConfigWithControl` 保留原签名（内部委托 LocalTarget），
  新增 `RunRuntimeConfigWithTarget(control, target, ...)`。目录参数由调用方先用
  `target.Resolve` 解析，env 注入同样使用解析后的值。

### 3.3 容器发现

`execenv.Discover(ctx, opts) (*ContainerTarget, error)`：

1. 扫描 `/proc/[0-9]+/ns/mnt`，按 inode 去重，排除自身 mnt ns。
2. 对每个候选，取其根挂载行（`mountpoint == "/"`，`root == "/"`），要求
   fstype 不是 `rootfs`。
3. 用该行的 `major:minor` 在**自己的** `/proc/self/mountinfo` 里找同设备号的
   mount，其挂载点即容器根的 init ns 路径（实测 init ns 侧与容器侧均为 `0:29`）。
   找不到时退回“挂载点以 `/rootfs` 结尾”的匹配，并记录 WARNING。
4. 候选唯一 ⇒ 选中；多于一个 ⇒ 若配置了 `runtime.execution.containerId`，
   用 `/run/kata-containers/<id>/` 前缀或 upperdir 包含关系消歧；仍不唯一 ⇒
   返回错误，**绝不猜测**。
5. 探测：`nsenter -t <pid> -m -r -- /bin/sh -c 'exit 0'` 成功，且在
   `<rootfs>/opt/taa/.taa-probe-<rand>` 可写可删。
6. 每个任务开始时发现一次并缓存；任务中容器消失 ⇒ 任务失败，不重试。

### 3.4 目录约定与路径映射

容器侧（模型视角，沿用并扩展现有契约）：

| 用途 | 容器路径 | TAA init 根路径 |
|---|---|---|
| 模型代码（cwd） | `/opt/taa/model` | `s.Security.ModelDir` |
| 数据集（只读语义） | `/opt/taa/input` | `modelInputDir`（现 `GetModelInputDir()`） |
| 结果 | `/opt/taa/output/result` | `modelOutputDir`（现 `GetModelOutputDir()`） |
| 日志 | `/opt/taa/output/log` | `GetModelLogDir()` |
| 进度 | `/opt/taa/output/progress/progress.json` | `GetModelProgressDir()` |

`Prepare` 步骤：

1. 校验容器侧目标路径**不是容器内的挂载点**（解析 `/proc/<pid>/mountinfo`）；
   是挂载点则拒绝容器模式（直接写 overlay 会丢失或绕过 volume 语义）。
2. 只清空并重建上述目录的**内容**；`/opt/taa/semgrep` 等镜像内容永不触碰。
3. 模型目录从 `ModelDir` 拷入，数据集从 `trainDataDir` 直接拷入（跳过 init 根
   的中间副本，节省一次大文件复制；`modelInputDir` 仅作为记录值不再落盘）。
4. 拷贝使用现有 zip-slip 风格的防逃逸实现：逐段 `lstat`、拒绝符号链接、
   拒绝越界路径；目标空间不足时在拷贝前失败并给出明确错误。
5. 记录本次 staging 清单，供 `Cleanup` 精确删除。

### 3.5 执行流程（时序）

```
executeTraining
 ├─ target := execenv.Select(deployment, cfg.Runtime.Execution, s.Security)
 ├─ target.Prepare(modelDir, dataDir)          // 拷模型/数据进容器
 ├─ inputPath  := target.Resolve(container input)
 ├─ outputPath := target.Resolve(container result)
 ├─ env["TAA_LOG_DIR"|"TAA_PROGRESS_DIR"|...] = target 路径
 ├─ mirror := startLogMirror(target, initRootDirs)   // 见 3.6
 ├─ cmd := target.Command(ctx, commandLine, target modelDir)
 ├─ control.StartCommand(cmd) / cmd.Wait()
 ├─ mirror.Stop()                                   // 末次同步
 ├─ 失败：保留日志，跳过产物回拷，报错（与现状一致）
 └─ 成功：copyDir(modelOutputDir, target.Visible(result)) // 产物拷回 init 根
          target.Cleanup()                               // 删除容器侧 staging
          继续现有 copyDir(trainOutputDir, modelOutputDir) / resultcheck / 上报
```

- `runtimeConfig` 的 `commands` 与 `env` 宏用**容器路径**解析后再交给 target。
- `training_result.json` 由模型写入 `TAA_OUTPUT_DIR`（容器路径），随产物回拷。

### 3.6 日志/进度镜像

TAA 的 `reportWatcher` 读 init 根的 `ModelLogDir` / `ModelProgressDir`，不改它：

- 新增 `logMirror` goroutine（`internal/controller/model_log_mirror.go`）：
  - 每 500ms 增量复制 `<rootfs><logDir>` 下新增字节到 init 根日志目录
    （按文件 offset，append-only，保持 JSONL 语义）；
  - `progress.json` 原子替换（临时文件 + rename）；
  - 结束时做一次无间隔同步；镜像失败只记 WARNING，不中断训练。
- 镜像路径来自 `target.Visible(...)`，即 init ns 直接可读的 overlay 路径。

### 3.7 停止与清理

- stop 沿用 `control.RequestStop()` → ctx 取消 → `exec.CommandContext` 杀
  nsenter；`Setpgid` 保证连带容器里的子进程（实测 nsenter 会 fork 出真正的
  python 进程，同进程组）。
- `Cleanup` 在成功、失败、取消、进程崩溃四条路径都执行（`defer`）：
  删除容器侧 `/opt/taa/model|input|output/{result,log,progress}` 内容与 probe 文件。
- 容器侧 staging 位于 guest 内存 tmpfs；清理失败只记 WARNING 并留待下次
  `Prepare` 开头清理。

## 4. 配置

`taa-config.json` 新增（全部可选，默认值即现状）：

```json
"runtime": {
  "execution": {
    "mode": "auto",                 // auto | local | container
    "containerId": "",              // 可选，多容器消歧
    "modelDir": "/opt/taa/model",
    "inputDir": "/opt/taa/input",
    "outputDir": "/opt/taa/output/result",
    "logDir": "/opt/taa/output/log",
    "progressPath": "/opt/taa/output/progress/progress.json"
  }
}
```

- `mode=local`：强制现状（回滚开关）。
- `mode=container`：发现失败即任务失败（fail-closed），启动日志说明原因。
- `mode=auto`：`deployment==Initrd` 且发现成功才走容器，其余情况走本地，
  启动/任务日志各打一次 WARNING。
- 校验：`mode` 枚举、路径必须为绝对路径且不得为 `/`、不得包含 `..`。
- `buildSecurityConfig` 是唯一生产构造点，新增字段必须在此初始化。

## 5. 代码改动清单

| 文件 | 改动 |
|---|---|
| `deploy/guest-build/taa-init.sh` | 启动 TAA 前 `export TAA_DEPLOYMENT=initrd` |
| `deploy/taa-supervisor.sh` 及 fhe/dataanaylsis 两份 | 循环块外 `export TAA_DEPLOYMENT=container` |
| `internal/deployment/deployment.go`（新） | `Shape`、`Detect()`、mountinfo fstype 兜底 |
| `internal/execenv/target.go`（新） | `Target` 接口、`LocalTarget` |
| `internal/execenv/container.go`（新） | `ContainerTarget`：Resolve/Visible/Prepare/Cleanup/Command |
| `internal/execenv/discover.go`（新） | ns 扫描、major:minor 匹配、探测、消歧 |
| `internal/execenv/copy.go`（新） | 防符号链接/越界的目录拷贝与空间检查 |
| `internal/runtime/executor.go` | 抽出 `RunRuntimeConfigWithTarget`，原函数委托 LocalTarget |
| `internal/controller/import_processing.go` | 选择 target、Prepare/镜像/回拷/Cleanup 接线 |
| `internal/controller/model_log_mirror.go`（新） | 日志与进度镜像 |
| `internal/controller/route.go` | `SecurityConfig` 增加 `Execution` 字段与 getter |
| `internal/app/taa/app.go` / `buildSecurityConfig` | 传入 deployment 与 execution 配置 |
| `internal/config/config.go` | `runtime.execution` 解析、默认值、校验 |
| `configs/taa-production.json` 等模板 | 增加默认块（`mode: auto`） |
| `CHANGELOG.md` | 记录为什么引入（initrd 形态下镜像自带运行时） |
| `deploy.md` | 说明容器执行模式与路径契约 |

## 6. 安全与边界

- 结果只用于执行策略，**不做安全判定**；`TAA_DEPLOYMENT` 是部署事实，
  不是信任根。
- 目标路径白名单固定，模型内容不能影响容器选择或路径映射。
- 容器根的写入使用 init ns 的 overlay 挂载点；`shared_fs=none` 下明文不出
  guest 内存，与今天在 init 根执行同一信任域；若未来启用 `shared_fs`，
  必须在文档中重新评估。
- 容器内目标路径是挂载点（volume）时拒绝容器模式，避免写错层。
- 拷贝回产物前做空间检查，避免把 guest tmpfs 写满导致 kata-agent 异常。

## 7. 测试与验证

单元测试：

- `internal/deployment`：显式值、空值兜底两种 fstype、非法值报错。
- `internal/execenv`：mountinfo 解析（真实两行 fixture）、major:minor 匹配、
  多候选消歧、路径白名单、符号链接拒绝、拷贝越界拒绝。
- `internal/controller`：mirror 增量与原子替换；Prepare/Cleanup 幂等。
- 现有测试：`go test ./cmd/... ./internal/... ./pkg/...`；
  `test-taa-init.sh`、`test-render.sh`、`test-deploy-taa-vm.sh` 需同步断言
  新增的 `export TAA_DEPLOYMENT=...`。

联机验证（172.16.10.178，一次 ssh 合并执行）：

1. 容器形态 Pod：确认 `TAA_DEPLOYMENT=container` 生效、行为与今天一致，
   日志打印 `execution target: local`。
2. initrd 形态 Pod（`deploy-taa-vm.sh`）：确认打印 `execution target:
   container (pid=…, root=…)`，导入-训练-导出全链路跑通；日志/进度/产物
   与本地模式一致。
3. 停止测试：训练中调用 stop，确认容器内进程组被清理、staging 被删除。
4. 负向测试：容器不可发现且 `mode=container` 时任务失败且信息明确；
   `mode=local` 可回滚。

## 8. 分阶段实施

1. **阶段 A**：部署标记 + 形态检测 + 启动日志（无行为变化）。
2. **阶段 B**：`execenv` 抽象 + LocalTarget 重构（纯重构，测试全绿）。
3. **阶段 C**：容器发现 + Prepare/Cleanup + Command（先只支持小模型验证）。
4. **阶段 D**：日志/进度镜像 + 产物回拷 + 停止/取消路径。
5. **阶段 E**：配置、模板、文档、CHANGELOG、联机验证。

## 9. 风险与回滚

| 风险 | 处置 |
|---|---|
| 多容器导致发现歧义 | 默认 fail，配置 `containerId` 消歧；`auto` 下退回本地并告警 |
| Kata 内部布局变化 | 用 major:minor 匹配而非路径前缀；探测失败即退回本地 |
| 大模型/大数据拷贝耗时与空间 | 拷贝前检查空间；文档标注成本；保留 `mode=local` |
| 容器重启/退出导致 nsenter 失败 | 任务失败，下次任务重新发现；不自动重试 |
| 镜像缺少模型依赖 | 这是本方案要解决的问题；失败信息原样透传（与本地一致） |
| 行为差异引入回归 | `auto` 默认 + `mode` 开关 + 阶段 A/B 零行为变化先行 |
