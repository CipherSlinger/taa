# 生产代码全域 CPG 图引擎与多语言规则矩阵接入规范

- **状态**：APPROVED
- **日期**：2026-09-30
- **目标**：在生产 Go 守护进程（`cmd/taa`、`internal/codeaudit/`）中全量接入 CPG 6 层图引擎（纯 Go 重写）、AST 作用域感知闭包切片、跨微服务缺陷合成及多语言 Semgrep 规则矩阵，彻底消解设计文档（`taa-audit-design.html`）中的工程未接入项。

---

## 1. 背景与工程目标

设计文档 `models/audit/research/taa-audit-design.html` 规划了“全域多语言源码纳管 + Semgrep 静态初筛 + 跨仓库 CPG 6 层图分析 + TEE-LLM 强类型仲裁”的闭环架构。经核查，生产运行时此前仅接入了 Semgrep Python 单语言规则与行号物理滑窗，而 CPG 各层（Layer 1~6）、AST 闭包切片、跨微服务漏洞合成与多语言规则矩阵均未在生产代码中落地。

本项目将完成以下四大核心工程目标的全面生产交付：
1. **纯 Go 重写 CPG 6 层全域图拓扑与污点分析引擎**（`internal/codeaudit/cpg`，零 CGO，通过轻量原生 AST Bridge 抽取语法树）。
2. **AST 作用域感知闭包切片器**（替换生产硬编码的行号物理滑窗，按需提取函数/类语义块）。
3. **深度因果证据注入与全局跨微服务漏洞合成**（激活 `f.CPGEvidence` 契约，自动合成 `engine="cpg"` 全局高危后门缺陷）。
4. **全域多语言 Semgrep 规则矩阵扩充与目录化自动加载**（建立 `python/`、`go/`、`c/`、`java/`、`shell/` 规则包体系）。

---

## 2. 整体架构与执行时序

```text
待审源码包 (工作区 /opt/taa/input)
   │
   ▼
[Step 1: 多语言 Semgrep 静态扫描 (Tier 1)]
   │ 扫描配置: --config /opt/taa/semgrep/rules/ (自动加载 python/go/c/java/shell)
   │
   ├─► [分支 A: 0 Findings] (占比 50%+)
   │     └─► 极速旁路 (Fast-Path Bypass) ➔ 直接判放行 (Passed=true) ➔ 毫秒级交付
   │
   └─► [分支 B: 存��静态疑点 (Findings > 0)]
         │
         ▼
[Step 2: Go 原生按需 CPG 图引擎 (Tier 1.5 - internal/codeaudit/cpg)]
   │ 1. 原生 AST 桥接: 调用系统内置 Python AST JSON Dump 获得涉事文件语法树
   │ 2. Layer 1-3: 构建涉事模块的 AST/CFG/DFG 并在内存中建立符号解析表 (Resolver)
   │ 3. Layer 4: 提取 HTTP Client (requests/httpx) 与 Web Route (@app.post)，缝合跨服务边界边
   │ 4. Layer 5: 运行 Worklist 不动点污点引擎 (max_hops=50)，计算 Source 到 Sink 连通性
   │ 5. Layer 6: 执行程序依赖图 (PDG) 剪枝，生成 <300 Token 的结构化因果轨迹 Trajectory
   │
   ▼
[Step 3: 深度证据融合与全局漏洞合成 (Deep Evidence Fusion)]
   │ 1. 证据注入: 将 AST 闭包切片与因果轨迹注入 Finding.CPGEvidence (替换物理滑窗)
   │ 2. 缺陷合成: 若存在跨微服务/跨模块穿透，自动合成 engine="cpg" 的全局 Finding (IsCrossFile=true)
   │
   ▼
[Step 4: TEE-LLM 强类型交互仲裁 (Tier 2)]
   │ 1. ActionVerifyFinding: 逐项定点判定 (带完整因果轨迹证据)
   │ 2. ActionAnalyzeFile: 文件级宏观攻击链研判
   │ 3. Fail-Closed 状态机门禁拦截与综合审计报告出具
```

---

## 3. Go 原生 CPG 6 层图引擎设计 (`internal/codeaudit/cpg`)

在 `internal/codeaudit/cpg/` 目录下构建纯 Go 语言图分析模块：

### 3.1 核心组件划分
* `models.go`：图模型容器，定义 `CPGNode`、`CPGEdge`、`NodeType`、`EdgeType` 与多维倒排索引；
* `ast_bridge.go`：基于标准命令抽取 Python 语法树并反序列化为 Go 强类型 AST 结构体（零 CGO 依赖）；
* `builder.go`：Layer 1 统一 AST 节点建模 + Layer 3 过程内控制流（CFG）与到达定值数据流（`DFG_DEF_USE`）；
* `resolver.go`：Layer 2 跨文件模块与符号消歧（SymbolResolver），解析相对/绝对 import 并生成 FQN；
* `microservice.go`：Layer 4 微服务边界穿透桥，匹配 HTTP 客户端与服务端路由，合成跨服务边；
* `taint_engine.go`：Layer 5 有限跳步（`MaxHops=50`）Worklist 不动点污点引擎，支持净化器阻断；
* `slicer.go`：Layer 6 程序依赖图（PDG）剪枝，输出压缩后的 `<300 Token` 因果轨迹。

### 3.2 节点与边类型体系
* **NodeType**：`AST_STMT`, `AST_EXPR`, `AST_CALL`, `AST_ASSIGN`, `AST_FUNC_DEF`, `AST_CLASS_DEF`, `AST_RETURN`, `AST_PARAM`, `MICROSERVICE_CLIENT`, `MICROSERVICE_ENDPOINT`。
* **EdgeType**：
  * AST 层：`AST_CHILD`
  * CFG 控制流层：`CFG_NEXT`, `CFG_BRANCH_TRUE`, `CFG_BRANCH_FALSE`, `CFG_LOOP_EXIT`, `CFG_EXCEPT`
  * DFG 数据流层：`DFG_DEF_USE`
  * 过程间调用层：`CALL`, `CALL_ARG`, `CALL_RET`
  * 微服务边界层：`MICROSERVICE_HTTP`, `MICROSERVICE_PAYLOAD`, `MICROSERVICE_RESPONSE`

---

## 4. AST 作用域感知闭包切片与证据融合合成

### 4.1 作用域闭包切片器 (`scope_slicer.go`)
* 遍历语法树定位包裹告警行号 `targetLine` 的最小最深封闭函数体（`FunctionDef`、`AsyncFunctionDef` 或 `ClassDef`）；
* 提取 `[Lineno, EndLineno]` 完整范围代码，保留完整控制流与闭包语义；
* **平滑降级**：若语法解析失败或位于顶级全局范围，自动回退至前后各 7 行的物理滑窗，确保高可靠性。

### 4.2 单点 Finding 深度因果证据注入
* 当检测到跨文件或跨微服务污点流经某 Finding 时：
  * 将格式化的 `[Deep Audit Inter-Procedural Taint Trajectory]` 存入 `f.CPGEvidence`；
  * 将结构化轨迹存入 `f.TaintTrace`；
  * `f.IsCrossFile = true` / `f.IsMicroservice = true`；
* `internal/codeaudit/verifier.go` 中自动将 `ctxAfter` 替换为 `f.CPGEvidence`，供 TEE-LLM 进行精准语义仲裁。

### 4.3 跨微服务漏洞全局合成机制
* 当微服务边界穿透分析发现客户端出站敏感载荷（`ENV_001`）被服务端接收并通过 `subprocess.run(shell=True)` 执行时：
* 自动合成一条系统级全局缺陷：
  * `RuleID: "taa-cross-service-rce"`
  * `Severity: SeverityCritical`
  * `Engine: "cpg"`
  * `IsCrossFile: true, IsMicroservice: true`
  * `ContextAfter: cpgTrajectory`
* 该缺陷直接激活安全门禁（Gate）拦截逻辑。

---

## 5. 多语言规则矩阵与目录化自动加载

### 5.1 目录组织结构
```text
models/audit/semgrep/rules/
├── python/rules.yaml        # 13 项标准 Python 安全规范
├── go/rules.yaml            # Go 语言安全规范 (exec.Command, http, unsafe)
├── c/rules.yaml             # C/C++/CUDA 语言安全规范 (system, socket, shadow)
├── java/rules.yaml          # Java 语言安全规范 (ProcessBuilder, HttpClient)
└── shell/rules.yaml         # Shell 脚本安全规范 (eval, bash -c, curl)
```

### 5.2 引擎自动发现支持
* 修改 `internal/codeaudit/semgrep_engine.go`：
  * 支持 `semgrepRulesPath` 传入目录；
  * 扩展文件遍历纳管后缀：`*.py`, `*.go`, `*.c`, `*.cpp`, `*.cu`, `*.h`, `*.hpp`, `*.java`, `*.sh`；
  * 严格忽略构建依赖目录（`.git/`, `vendor/`, `node_modules/`, `target/`）与大型二进制权重文件（`*.pt`, `*.bin`, `*.safetensors`, `*.onnx`）。

---

## 6. 容错降级与验证规范

### 6.1 防御性降级
* AST 解析失败或超时（单文件 5s 上限）自动退化为安全物理滑窗；
* 全局图节点设置 50,000 硬上限，超限停止扩散并输出局部拓扑，防止内存耗尽（OOM）。

### 6.2 验收测试
1. **单元测试**：针对 `internal/codeaudit/cpg` 的 6 层构建、污点遍历、切片格式化与 AST 闭包切片编写完整测试用例；
2. **多语言单测**：针对 Semgrep 多语言规则扫描添加覆盖测试；
3. **跨微服务模拟测试**：验证跨服务漏洞合成与 `CPGEvidence` 注入；
4. **容器端到端联调**：部署至 `taa-env-slim-v2` 容器，验证良性模型快速放行与跨微服务恶意模型阻断清空。
