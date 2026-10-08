# 模型依赖的下发、落盘与生效（2026-10-08）

## 1. 触发

`/v1/taa/importModel` 只负责把模型代码包（`tar.gz`/`zip`，内含代码 + `.pth` 权重 + config）
送进 TAA，**没有任何通道承载模型代码依赖的 Python 第三方库**。当前依赖是带外（out-of-band）
解决的：`models/examples/install_deps.sh` 手工维护一份针对 Retina-DKD 与 TEE-test 的硬编码清单，
在镜像/容器里 apt 装 `python3-numpy`/`python3-opencv`/`python3-torch`，再用 `pip3 download`
把 `torchvision`/`tensorboardX`/`xlutils` 的 wheel 解压进 `~/.local`。

这条路径有三个不可接受之处：

1. **不是平台能力**：换一个模型就要改脚本、重做镜像；与"平台下发资源、TAA 机密执行"的
   产品语义不符。
2. **接口层不可知**：TAA 不知道"当前模型需要哪些依赖"，`StatusData` 里没有任何相关状态位，
   失败只能等到训练阶段以 `ImportError` 暴露。
3. **不可追溯**：`reportModelImport` / `reportRes` 只上报模型与数据的 SM3，无法回答
   "这一轮训练到底跑在哪套依赖上"。

本方案新增一条依赖包下发通道，把依赖变成平台可下发、TAA 可校验、结果可追溯的一等对象。

## 2. 现状事实（已核对）

### 2.1 相关接口盘点

| 路径 | handler | 用途 |
| :--- | :--- | :--- |
| `/v1/taa/importModel` | `internal/controller/handler_task.go:153` | 模型下发 |
| `/v1/taa/import` | `internal/controller/handler_task.go:79` | 数据下发 |
| `/v1/taa/getResourceInfo` | `internal/controller/handler_system.go:205` | 只下载解密出目录树，不导入 |
| `/v1/taa/status` | `internal/controller/handler_system.go:57` | 回 `model_imported` 等状态位 |

路由表 `internal/controller/router.go:8-27`，全部经 `postOnly` 包装（POST-only + CORS）。
`api/proto/taa.proto` 定义了 `ImportModel` 等 rpc，但仓库内**没有 gRPC server**
（`cmd/` 下只有 `main.go`），该文件是设计稿，实际对外只有 HTTP JSON。

### 2.2 训练执行方式

`internal/runtime/executor.go`：把 `commands` 用 ` && ` 拼成一行交给 `/bin/sh -c`（`:44`），
`cwd` 设为模型目录（`:49`），环境变量经 `MergedRuntimeEnv` 合并（`:95-114`），
覆盖顺序为 **进程环境 → `runtimeConfig.env` → TAA 系统变量**，即系统变量最后写入、优先生效。
TAA 系统变量目前注入 `TAA_TASK_ID`/`TAA_DATA_DIR`/`TAA_MODEL_OUTPUT_DIR`/`TAA_CHECKPOINT_DIR` 等（`:50-77`）。

### 2.3 模型目录是"整体重建"的

`resource.ExtractArchiveToDir`（`internal/resource/archive.go:41-66`）是**原子替换**语义：
解包进 `MkdirTemp` 临时目录 → `os.RemoveAll(dst)`（`:62`）→ `os.Rename`。
模型导入正是走这条路（`internal/controller/import_processing.go:62`）。

**因此 `ModelDir` 在每次模型下发时被整个删除重建。** 这个事实否决了"依赖解包到模型目录内"
的落点方案——它会让依赖变成瞬时的，与"依赖独立下发、可复用"直接矛盾。此外还有三处会连带
踩到依赖：

| # | 位置 | 若依赖在 `ModelDir` 内会怎样 |
| :--- | :--- | :--- |
| a | `GenerateAuditReport(s.Security.ModelDir, ...)`（`import_processing.go:634`） | 模型审计连带扫描 GB 级第三方 wheel |
| b | `BuildDirectoryChecksum(s.Security.ModelDir, "sm3")`（`import_processing.go:682`、`:961`、`resource/checksum.go:25-70`） | 依赖被算进模型完整性 SM3，哈希随依赖漂移 |
| c | 审计失败/LLM 不可用时的 `cleanDirContents(s.Security.ModelDir)`（`import_processing.go:627`、`:637`、`:650`） | 依赖被连带清空 |
| d | `ExtractArchiveToDir` 的 `os.RemoveAll(dst)`（`archive.go:62`） | **每次模型下发都删除依赖** |

把依赖放在 `ModelDir` **同级**的内容寻址目录，a/b/c/d 四者同时消失：无需改审计范围、
无需改校验和、无需改解包流程。

### 2.4 无路径排除能力

`internal/codeaudit` 没有任何"忽略路径/前缀"机制，只有按扩展名的 `UnsupportedExts`
跳过（`internal/codeaudit/rules.go:90`）。这是 §2.3 中选择"同级目录"而非"目录内 + 排除"
的第二个理由——目录内方案必须新增排除能力才能落地。

### 2.5 磁盘约束

容器根分区约 28G、镜像占约 25G（见历史记录）。torch 系 wheel 动辄 GB 级，
`--target` 安装还会展开 `.dist-info`。依赖目录必须可配置到外部卷。

## 3. 决策摘要

| # | 决策项 | 取值 | 理由 |
| :--- | :--- | :--- | :--- |
| 1 | 下发形态 | 新增独立接口 `importDeps`，不动 `importModel` 字段 | 依赖与模型是两个可独立演进的生命周期 |
| 2 | 覆盖范围 | 仅 Python wheel，非 root，不动系统 | 缩小 TEE 内攻击面；apt 级需求归镜像基线 |
| 3 | 落点 | `depsDir/<sm3>`，与 `ModelDir` 同级 | §2.3 的 a/b/c/d 全部规避 |
| 4 | 绑定语义 | 全局单例 + 状态位，`DepsHash` 持久化 | 与既有 `ModelImported`/`CurrentDataRecord` 单活模型同构 |
| 5 | 审计策略 | 与模型代码同引擎、同策略、fail-closed | 与既有安全姿态一致 |
| 6 | 生效机制 | 训练子进程注入 `TAA_DEPS_DIR` + `PYTHONPATH` | 不侵入 `runtimeConfig` 契约 |

## 4. 接口契约

### 4.1 新增入向接口 `POST /v1/taa/importDeps`

在 `internal/controller/router.go:9-22` 的路由表新增一行，沿用 `postOnly`。

请求体使用**独立结构**，不复用 `importRequest`（`handler_task.go:14-20`）——后者的
`publicKey` 与 `runtimeConfig` 对依赖包没有意义，接受它们只会制造歧义：

```json
{
  "resourceUrl": "https://platform/files/deps-retina-1.2.tar.gz.enc",
  "requestId": "req-9",
  "taskId": "task-9"
}
```

| 字段 | 必填 | 说明 |
| :--- | :--- | :--- |
| `resourceUrl` | 是 | 必须显式给出。**不支持为空复用**：依赖是内容寻址的，允许复用会让"当前生效的是哪一套依赖"不可推断 |
| `requestId` / `taskId` | 二者至少一个 | 沿用既有校验与报错文案 |

校验与约束：

校验分**同步**与**异步**两段，界线是"是否需要读到归档内容"：

**同步（写响应之前，可返回 4xx）**

- `resourceUrl` 非空；`requestId` 与 `taskId` 不能同时为空。
- 并发控制复用 `tryAcquireTask`（`route.go:575`），任务类型标记为 `deps_importing`。

**异步（下载解包之后，经 `reportDeps` 上报，不能返回 4xx）**

- 包内**必须含 `requirements.txt` 且至少一个 `*.whl`**，否则判定失败并回滚。
- 下载大小沿用 `Security.GetMaxFileBytes()`（默认 `3GB`，`config.DefaultMaxFileBytes`）。
- 解密沿用 `resolvePlaintextResource`（`import_processing.go:867`）的 `.enc` 自动判定 +
  明文压缩包头探测 + SM2/SM4-GCM 解密，与模型/数据完全一致。

这里必须区分的原因：**下载是同步的，下载之后的处理是异步的**。`modelImportHandler`
（`handler_task.go:263-295`）的真实顺序是 `tryAcquireTask` → `downloadToTempFile`（失败即
500）→ 写 200 → `runAsyncSafe`，因此下载失败可以返回 5xx（本方案的 handler 与它逐字同构）；
但**下载之后**的解包与归档内容校验发生在 200 已写出之后，无法再返回 4xx，其结果只能通过
`reportDeps` 的 `code`/`msg` 回传平台。

> 订正记录（2026-10-08）：本节初稿写的是"响应体在下载**之前**就已写出"，方向说反了。结论
> （内容校验只能经 `reportDeps` 异步上报）不变，但照初稿理解会得出"下载失败也走 `reportDeps`"
> 的错误时序模型。已按 `importModel` 的真实实现改正。

响应沿用 `writeEnvelope`：`{"msg":"依赖包已接收，处理中","result":null,"error":0}`，异步处理。

### 4.2 依赖包格式约定（对平台侧的硬约束）

一个 `tar.gz`/`zip`，内含**平铺的 `*.whl` 闭包 + `requirements.txt`**。TAA 以非 root 执行：

```
pip3 install --no-index --no-cache-dir \
     --find-links <wheelhouse> \
     --target <depsDir>/<sm3> \
     -r requirements.txt
```

选 `pip --target` 而非手工把 wheel 当 zip 解包，理由：

- wheel 的 `.dist-info` 元数据必须正确——torch 系生态存在运行期 `importlib.metadata` 查询；
- wheel 的 `*.data/` 布局（scripts、headers）需要按规范安置；
- `--no-index` 保证**零网络**，闭包不完整会立即报错，而不是拖到训练阶段才炸
  （这是 fail-closed 的一部分）；
- pip 已在镜像中（`install_deps.sh` 本就使用 `pip3`），不引入新依赖。

## 5. 状态模型

新增状态位，与 `ModelImported`/`CurrentDataRecord` 同构，纳入 state store 并支持
`RestoreFromPersistentState`（`route.go:208`）重启恢复：

- `DepsImported bool`
- `DepsHash string`（当前生效依赖包的 SM3）
- `DepsChecksum map[string]any`（形状 `{size, algorithm:"sm3", value}`，对齐
  `setModelChecksum`/`setDataChecksum`）

**依赖是可选的，不是训练的前置门槛。** 未导入依赖时训练照常执行、不注入任何东西，
既有"模型 + 数据 → 训练"流程与全部既有测试不受影响。代价是模型实际缺依赖时只能在训练阶段
以 `ImportError` 暴露，并经 `reportRes` 走失败上报——该失败模式报错清晰，可以接受。

绑定是**单例**：新依赖导入成功即覆盖 `DepsHash`。旧版本目录按内容寻址保留在
`depsDir/<old-sm3>`，可人工回滚。

`StatusData` 增加 `deps_imported` 与 `deps_hash`；`current_op` 增加取值 `deps_importing`。

## 6. 处理流水线

复用现有能力，不新造轮子：

```
downloadToTempFile                    resource.DownloadToTempFile（沿用限流）
  → resolvePlaintextResource          .enc 自动判定 + SM2/SM4-GCM 解密
  → SM3 内容寻址                       得到 depsHash
  → 幂等检查                          depsDir/<sm3>/.taa_audit_ok 存在 ⇒ 直接置状态并返回
  → 解包外层归档到临时 wheelhouse      以临时目录为 base 做 zip-slip 校验
  → 包内容校验                         requirements.txt + 至少一个 *.whl
  → pip3 --no-index --find-links <临时 wheelhouse> --target depsDir/<sm3> -r requirements.txt
  → 依赖包审计                         与模型同引擎、同策略、fail-closed
  → 落 .taa_audit_ok 标记
  → 置 DepsImported/DepsHash/DepsChecksum → 持久化 → 上报
```

`--find-links` 指向解包出来的临时 wheelhouse，`--target` 才是内容寻址目录；二者分离使得
外层归档的解包（需要 zip-slip 防护）与 wheel 的展开（交给 pip，wheel 规范本身不允许路径
穿越，pip 亦做校验）各由合适的组件负责。临时 wheelhouse 在处理结束后删除。

幂等标记 `.taa_audit_ok` 的意义：审计通过后重复下发同一 hash 不再重扫 GB 级内容。

失败路径：`DepsImported=false`、`rm -rf depsDir/<sm3>`（不留半成品目录）、
经 `reportDeps` 上报 `code=1`，并在审计失败时经 `reportAudit`（`scope=deps`）上报报告。

## 7. 训练时生效

在 `internal/runtime/executor.go` 的 `RunRuntimeConfigWithControl` 中注入：

- `TAA_DEPS_DIR=<depsDir>/<hash>` 加入 `systemEnv`（`:50-77` 那组 TAA 系统变量）。
- **`PYTHONPATH` 必须单独处理。** `MergedRuntimeEnv`（`:95-114`）的覆盖顺序使
  `systemEnv` 最后写入；若把 `PYTHONPATH` 放进 `systemEnv`，平台在 `runtimeConfig.env`
  里设置的 `PYTHONPATH` 会被**静默覆盖**。做法是在合并**之后**前置拼接：

```
PYTHONPATH=<depsDir>/<hash>:<合并后的原 PYTHONPATH>
```

仅当 `DepsImported == true` 时注入，否则完全不改动环境。

## 8. 审计、上报与协议同步

- **依赖审计**复用 `/v1/taa/reportAudit`，在该接口新增可选字段 `scope`（`model` | `deps`，
  缺省 `model`，向后兼容），平台侧据此区分两类报告，不必新开审计回调。
- **新增平台回调 `POST /v1/taa/reportDeps`**：`requestId`/`taskId`/`code`/`msg`/`checksum`，
  形状对齐 `reportModelImport`（`internal/controller/model_reporting.go`）。
- **`reportRes` 的 `training_task` 增加 `deps_checksum`**，与既有 `model_checksum`/
  `data_checksum` 并列，保证"这一轮跑在哪套依赖上"可追溯。
- `api/proto/taa.proto` 同步补 `ImportDeps` / `ReportDeps` 消息与服务方法，保持设计稿一致
  （无 gRPC 实现，仅文档意义）。

## 9. 安全要求

- **zip-slip 防护（本方案最关键的一条）**：外层归档解包到临时 wheelhouse 时，必须以该
  临时目录为 base 经 `SafeJoinWithBase`（`internal/resource`）校验，禁止 `../` 越界写入
  模型代码目录或系统路径。依赖包是平台投递、在 TEE 内解包的归档，与模型包同等对待。
  随后 `--target` 的 wheel 展开交给 pip（wheel 规范不允许路径穿越，pip 亦做校验）。
- **非 root**：全程非特权用户；不改全局 `site-packages`，不改系统级 `sys.path` 位置。
- **零网络**：`--no-index` 强制；不引入任何外网拉取路径。
- **已知盲区（需在实现与交付中明示）**：fail-closed 静态扫描对 wheel 内的 `.so`/`.pyd`
  二进制无效（引擎按扩展名跳过，`internal/codeaudit/rules.go:90`），二进制层面的供应链
  风险未被覆盖；完整性上只有 SM3，无签名验签。

## 10. 配置

仅新增一项：

| 键 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `storage.depsDir` | `/opt/taa/model-deps` | 依赖包内容寻址根目录，与 `ModelDir`（默认 `/opt/taa/models`，`config.go:288`）同级 |

审计策略沿用现有 `security.codeScan` 配置，不新增开关。

⚠️ 结合 §2.5 的磁盘约束：多套依赖 hash 并存会持续占用空间，且**清理是人工动作**
（自动清理会破坏复用与按 hash 回滚的能力）。部署时应把 `depsDir` 指向外部卷。

## 11. 分阶段实施

1. **TAA 侧**：状态位与持久化 → `importDeps` handler → 处理流水线 → 训练注入 →
   `reportAudit.scope` / `reportDeps` / `deps_checksum` → 单测。
2. **platform-mock**：上传依赖包、触发 `importDeps`、展示依赖状态与依赖审计报告、
   `reportDeps` 接收端与看板。
3. **文档**：`docs/api-design.md` 新增 4.6（`importDeps`）与 4.7（`reportDeps`）章节；
   把 `models/examples/install_deps.sh` 的角色降级并改写为"镜像基线依赖"说明。

## 12. 测试策略

沿用仓库既有风格（表驱动 handler 测试，参照 `import_param_validation_test.go`；
流水线测试参照 `import_processing_test.go`）：

- 接口参数校验矩阵（`resourceUrl` 空、`requestId`/`taskId` 双空）——同步 4xx。
- 归档内容校验（包内缺 `requirements.txt`、包内无 `.whl`）——异步失败，经 `reportDeps`
  上报 `code=1`，并断言未留下半成品目录。
- 幂等复用：同 hash 二次导入不重新解包与审计。
- `pip --target` 安装：正常闭包成功；闭包缺失时立即失败且不留半成品目录。
- zip-slip：构造含 `../` 条目的恶意依赖包，断言被拒且未写出 `depsDir/<sm3>`。
- 训练注入：子进程环境含 `TAA_DEPS_DIR` 与前置的 `PYTHONPATH`，且平台在
  `runtimeConfig.env` 中给出的 `PYTHONPATH` **被保留**而非覆盖。
- fail-closed 回滚：依赖审计失败 ⇒ `DepsImported=false`、目录被清、`reportDeps` 收到 `code=1`。
- 未导入依赖时训练环境与改动前逐字节一致（回归保护）。
- 端到端：经 platform-mock 上传 wheelhouse → `importDeps` → `importModel` → `import`
  → 训练进程能 `import` 到目标包。

## 13. 风险与已知盲区

| # | 风险 | 说明与建议 |
| :--- | :--- | :--- |
| 1 | **fail-closed 审计第三方 wheel 可能永久不可用** | 依赖包内容是第三方代码，用与模型同一套 fail-closed 规则扫描，误报导致"永远无法通过"的概率不低。本轮按既定决策实现为同策略 fail-closed；操作上要求平台侧精简 wheelhouse。**后续若实践中确认不可用，需要补依赖审计的豁免/白名单机制**，届时另开 spec |
| 2 | 磁盘占用 | 见 §2.5 与 §10；`depsDir` 指外部卷 + 人工清理 |
| 3 | 二进制盲区 | 见 §9；`--target` 安装的 `.so` 不在静态扫描范围 |
| 4 | 与系统 site-packages 的同名遮蔽 | `PYTHONPATH` 前置会让依赖目录内的包优先于系统包，可能引入版本/ABI 冲突（例如 numpy）。需在文档中明确该优先级语义 |
| 5 | 依赖与模型时序分离 | 两个独立接口，平台需保证"先 `importDeps` 后 `import`"；单例语义下，若依赖下发晚于数据，本轮训练会以缺依赖失败 |

## 14. 明确不做（YAGNI）

- apt / 系统级库的依赖下发（归镜像基线）。
- 依赖包内允许自定义安装脚本（等于把任意代码执行权交给平台，放弃审计与可复现性）。
- 依赖包的签名验签（平台侧信任模型本轮不变，只做 SM3 完整性）。
- 多版本依赖并存的选择机制（单例语义，其余版本仅作人工回滚用）。
- 依赖目录的自动清理策略。
