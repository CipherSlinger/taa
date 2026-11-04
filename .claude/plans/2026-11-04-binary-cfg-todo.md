# TODO — 二进制审计通道：控制流分析

> 状态：**未开始**。二进制通道已于 2026-11-04 在配置模板中关闭（`codeAudit.binaryAudit.enabled: false`），
> 本条目是重新打开它之前必须先解决的问题。

## 1. 问题是什么

二进制通道目前**完全没有控制流图（CFG）或数据流分析**。它对一个 ELF 能说的只有：

- `.dynsym` 里的符号名（是否引用了 `socket`、`system` 等）
- `DT_NEEDED` 依赖列表
- 各节的名字、大小、可执行标志、Shannon 熵
- 可打印字符串

也就是说，它回答的是「**这个 .so 里出现了 socket 这个名字**」，而不是
「**这个 .so 的控制流能不能真的走到 socket**」。

后果是双向的：

- **误报**：合法库（libtorch、libllama、libggml 等）链接了全网络的符号，
  却从不调用。`internal/codeaudit/binary_rules.go:47-58` 记录了实测：
  `libllama-common` 里 socket 的调用者本身就是导出入口点，
  所以按调用图（call graph）读也清不掉这九个库。
- **漏报**：把 `socket` 名字从 `.dynsym` 去掉、改用 `dlopen` + 字符串拼接，
  当前的证据模型看不见。

`binary_rules.go:55` 明确记录了当时的判断：
> *Nor is a disassembler available to do it differently: the guest rootfs's
> `usr/bin` holds a single python3.10, and `golang.org/x/arch` is not available offline.*

## 2. 为什么现在关掉

2026-11-04 的实测（DPN 系列模型包，`wheels/` 下 12 个 wheel）：
4 个文件被标记为「二进制可执行文件未完整扫描」，全部由
`MaxEvidenceLines = 50000` 的**证据行上限**触发，
其中最轻的 `lightgbm` wheel 只有 3.4 MB。

这个上限是内存防护，不是覆盖开关，但在真实模型包的 `wheels/` 目录里几乎必然触发，
导致每次导入都带一条「建议后续优化」的噪音提示。在 CFG 问题解决之前，
这条通道提供的证据粒度不足以为它付出这份成本。

关闭方式：`configs/taa-{production,initrd,docker}.json` 中
`codeAudit.binaryAudit.enabled` 置 `false`。
**未在 config 模板里显式设置的部署（如 `fhe`、`data-anaylsis`）仍吃
`internal/config/config.go:863` 的默认值 `true`，如需一并关闭要显式配置。**

## 3. 待办事项

### 3.1 决策：是否引入反汇编

- [ ] 确认目标部署环境能否携带一个反汇编器（`golang.org/x/arch` 需 vendor 进镜像，
      或 capstone 需 cgo — 后者与 `CGO_ENABLED=0` 静态构建冲突）。
- [ ] 若不可行，明确记录「二进制通道只做符号级证据」是**产品决定**而非技术债，
      并从 `binary_rules.go` 的注释里移除「暂不可行」的临时语气。

### 3.2 若引入 CFG，需要覆盖的分析

- [ ] **基本块 + 函数边界识别**（从 `.text` 起始符号 + 直接跳转目标切分）。
- [ ] **调用图**：区分「导入了符号」与「从某个可达函数调用了该符号」。
      这一步直接消解 §1 的误报。
- [ ] **数据流**：追踪 `dlopen` 的字符串参数，覆盖 §1 的漏报。
- [ ] 把 CFG 结论落成**新的 EvidenceSource**（例如 `SourceReachable`），
      而不是推翻现有 `SourceDynsym` 证据 — 两者是不同强度的证据，报告要能区分。

### 3.3 顺带要解决的问题（与 CFG 独立，但重开通道前必须处理）

- [ ] **证据行预算按成员分配**：当前 `MaxEvidenceLines` 是「一个文件」的上限，
      而一个 wheel 有几百个成员，共用一份 5 万行预算。
      至少应改为按成员计，或让全文件裸扫描（抓尾部夹带）只占一小份。
- [ ] **`Bound.Reason` 进报告**：目前只在内存里，报告只留一个计数
      （`internal/codeaudit/binary_scanner.go:248`），
      运维看到「4 个」无从判断是 zip bomb 还是行数上限。
      应把每文件的 bound 原因写进 `scan_metadata.binary`。

## 4. 验收标准

重新打开 `binaryAudit.enabled` 时，下面三条必须同时成立：

1. DPN 系列包（`models/examples/DPN.zip` 等）扫描结果为
   `bounded_executable == 0`。
2. 构造一个「合法库 + 只导入不调用 socket」的夹具，判定为干净；
   构造一个「dlopen + 拼接字符串」的夹具，判定为 HIGH。
3. `scan_metadata.binary` 里能看到每个 bounded 文件的具体原因。