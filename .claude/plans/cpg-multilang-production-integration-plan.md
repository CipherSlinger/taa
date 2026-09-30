# 全域 CPG 图引擎与多语言规则矩阵生产接入实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 Go 生产守护进程（`cmd/taa` 与 `internal/codeaudit/`）中全量重写并接入 CPG 6 层图分析引擎（零 CGO）、AST 作用域闭包切片器、跨微服务漏洞合成机制，并将静态规则库升级为全域多语言（Python/Go/C/Java/Shell）目录化自动加载体系。

**Architecture:** 
1. 建立纯 Go 的 `internal/codeaudit/cpg` 包，通过标准 Python AST JSON Dump 桥接语法树，内部实现完整的 AST/CFG/DFG 融合图、符号消歧、微服务边界穿透、Worklist 污点算法与因果切片；
2. 升级 `internal/codeaudit/semgrep_engine.go`，支持加载规则目录 `--config /opt/taa/semgrep/rules`，纳管多语言源文件，并用 AST 闭包切片取代物理滑窗；
3. 在告警处理热路径中按需触发 CPG 引擎，注入 `CPGEvidence` / `TaintTrace` 并自动合成 `engine="cpg"` 全局微服务缺陷；
4. 容器内多语言规则同步与生产端到端验收。

**Tech Stack:** Go 1.22 (标准库 `os/exec`, `encoding/json`, `regexp`), Python 3 AST Bridge (只读命令行标准库), Semgrep CLI native。

---

## 阶段规划概览

| 阶段 | 任务目标 | 核心输出文件 |
| :--- | :--- | :--- |
| **Phase 1: 多语言规则矩阵** | 建立多语言规则目录树，升级 Go 引擎规则自动发现与文件纳管 | `models/audit/semgrep/rules/*/rules.yaml`, `semgrep_engine.go` |
| **Phase 2: Go 原生 CPG 基础** | CPG 数据模型、倒排索引与原生 Python AST JSON Bridge | `internal/codeaudit/cpg/models.go`, `ast_bridge.go` |
| **Phase 3: 过程间与微服务图** | Layer 1~3 (AST/CFG/DFG)、Layer 2 (符号解析) 与 Layer 4 (微服务穿透) | `builder.go`, `resolver.go`, `microservice.go` |
| **Phase 4: 污点与切片算法** | Layer 5 (Worklist 污点引擎) 与 Layer 6 (PDG 切片 + AST 作用域闭包切片) | `taint_engine.go`, `slicer.go`, `scope_slicer.go` |
| **Phase 5: 生产热路径深度融合** | 疑点触发式建图、因果证据回填、全局微服务缺陷自动合成 | `semgrep_engine.go`, `verifier.go`, `engine.go` |
| **Phase 6: 容器同步与 E2E 交付** | 同步多语言规则至容器、重新编译 `bin/taa`、完成端到端联调 | `configs/`, 容器部署与测试实测 |

---

## Task 1: 建立多语言 Semgrep 规则包体系并升级 Go 引擎目录加载

**Files:**
- Create: `models/audit/semgrep/rules/go/rules.yaml`
- Create: `models/audit/semgrep/rules/c/rules.yaml`
- Create: `models/audit/semgrep/rules/java/rules.yaml`
- Create: `models/audit/semgrep/rules/shell/rules.yaml`
- Modify: `internal/codeaudit/semgrep_engine.go`
- Test: `internal/codeaudit/semgrep_multilang_test.go`

- [ ] **Step 1: 编写多语言规则扫描的失败单测**

在 `internal/codeaudit/semgrep_multilang_test.go` 中编写针对 Go、C、Java、Shell 源码的多语言扫描测试，验证引擎能够扫描这些语言并触发对应规则家族。

```go
package codeaudit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSemgrepEngine_MultiLanguageRules(t *testing.T) {
	if _, err := os.Stat("/usr/bin/semgrep"); err != nil {
		if _, err := os.Stat("/usr/local/bin/semgrep"); err != nil {
			t.Skip("semgrep binary not installed on host, skipping CLI test")
		}
	}

	rulesDir, err := filepath.Abs("../../models/audit/semgrep/rules")
	if err != nil {
		t.Fatalf("failed to get rules dir: %v", err)
	}

	engine := NewSemgrepEngine(rulesDir)

	tmpDir := t.TempDir()
	// Go sample (CMD_001)
	goCode := `package main
import "os/exec"
func run(c string) { exec.Command("sh", "-c", c).Run() }`
	if err := os.WriteFile(filepath.Join(tmpDir, "test.go"), []byte(goCode), 0644); err != nil {
		t.Fatal(err)
	}

	// Shell sample (CMD_001)
	shCode := `#!/bin/bash
eval "$1"`
	if err := os.WriteFile(filepath.Join(tmpDir, "test.sh"), []byte(shCode), 0644); err != nil {
		t.Fatal(err)
	}

	report, err := engine.ScanDirectory(context.Background(), tmpDir)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if len(report.Findings) < 2 {
		t.Fatalf("expected at least 2 multi-language findings, got %d", len(report.Findings))
	}
}
```

- [ ] **Step 2: 运行测试验证失败**

运行：`go test -v ./internal/codeaudit -run TestSemgrepEngine_MultiLanguageRules`
预期：FAIL（缺少多语言规则文件或未支持目录加载扩展后缀）。

- [ ] **Step 3: 创建 Go, C, Java, Shell 规范规则集**

在 `models/audit/semgrep/rules/go/rules.yaml` 中实现 Go 规则：
```yaml
rules:
  - id: taa-cmd-exec-go
    languages: [go]
    severity: ERROR
    message: "Arbitrary command execution via exec.Command in Go"
    metadata:
      category: execution
      rule_family: CMD_001
    pattern-either:
      - pattern: exec.Command(...)
      - pattern: exec.CommandContext(...)

  - id: taa-net-general-go
    languages: [go]
    severity: ERROR
    message: "Outbound HTTP network call in Go"
    metadata:
      category: network
      rule_family: NET_001
    pattern-either:
      - pattern: http.Get(...)
      - pattern: http.Post(...)
      - pattern: http.DefaultClient.Do(...)
      - pattern: $CLIENT.Do(...)
```

在 `models/audit/semgrep/rules/c/rules.yaml` 中实现 C/C++/CUDA 规则：
```yaml
rules:
  - id: taa-cmd-exec-c
    languages: [c, cpp]
    severity: ERROR
    message: "System command execution in C/C++"
    metadata:
      category: execution
      rule_family: CMD_001
    pattern-either:
      - pattern: system(...)
      - pattern: popen(...)
      - pattern: execve(...)
```

在 `models/audit/semgrep/rules/java/rules.yaml` 中实现 Java 规则：
```yaml
rules:
  - id: taa-cmd-exec-java
    languages: [java]
    severity: ERROR
    message: "Process execution detected in Java"
    metadata:
      category: execution
      rule_family: CMD_001
    pattern-either:
      - pattern: Runtime.getRuntime().exec(...)
      - pattern: new ProcessBuilder(...)
```

在 `models/audit/semgrep/rules/shell/rules.yaml` 中实现 Shell 规则：
```yaml
rules:
  - id: taa-cmd-exec-shell
    languages: [bash, sh]
    severity: ERROR
    message: "Dynamic shell script execution detected"
    metadata:
      category: execution
      rule_family: CMD_001
    pattern-either:
      - pattern: eval ...
      - pattern: bash -c ...
      - pattern: sh -c ...
```

- [ ] **Step 4: 修改 `semgrep_engine.go` 支持纳管多语言文件扩展名**

在 `internal/codeaudit/semgrep_engine.go` 的 `walkSourceFiles` 中扩充纳入扫描的文件后缀：
```go
ext := strings.ToLower(filepath.Ext(path))
switch ext {
case ".py", ".go", ".c", ".cpp", ".cu", ".h", ".hpp", ".java", ".sh":
    // Included in multi-language scan
    files = append(files, path)
}
```

- [ ] **Step 5: 运行单测并验证通过**

运行：`go test -v ./internal/codeaudit -run TestSemgrepEngine_MultiLanguageRules`
预期：PASS。

- [ ] **Step 6: 提交代码**

```bash
git add models/audit/semgrep/rules/ internal/codeaudit/semgrep_engine.go internal/codeaudit/semgrep_multilang_test.go
git commit -m "feat(codeaudit): implement multi-language semgrep rules and directory scanner"
```

---

## Task 2: 实现 Go 原生 CPG 数据模型与轻量 Python AST JSON 桥接

**Files:**
- Create: `internal/codeaudit/cpg/models.go`
- Create: `internal/codeaudit/cpg/ast_bridge.go`
- Test: `internal/codeaudit/cpg/ast_bridge_test.go`

- [ ] **Step 1: 编写 AST 桥接与图容器单测**

在 `internal/codeaudit/cpg/ast_bridge_test.go` 中测试通过 AST JSON Bridge 抽取代码语法树并转为 Go AST 结构体，以及 CPG 内存图的节点索引查询能力。

- [ ] **Step 2: 运行测试验证失败**

运行：`go test -v ./internal/codeaudit/cpg -run TestASTBridge`
预期：编译失败或找不到包 `cpg`。

- [ ] **Step 3: 编写 `models.go`**

实现 `NodeType`, `EdgeType`, `CPGNode`, `CPGEdge`, `CodePropertyGraph` 及其倒排索引 `findNodesAtLine`, `findNodesByType`, `findNodesBySymbol` 等。

- [ ] **Step 4: 编写 `ast_bridge.go`**

实现 Go 语言调用 `python3 -c "import ast, json, sys; ..."` 进行紧凑 AST 转 JSON 的标准提取器，反序列化为 Go 强类型对象，包含错误捕获与单文件 5 秒超时保护。

- [ ] **Step 5: 运行测试并验证通过**

运行：`go test -v ./internal/codeaudit/cpg -run TestASTBridge`
预期：PASS。

- [ ] **Step 6: 提交代码**

```bash
git add internal/codeaudit/cpg/models.go internal/codeaudit/cpg/ast_bridge.go internal/codeaudit/cpg/ast_bridge_test.go
git commit -m "feat(cpg): implement CPG graph models and native python AST bridge"
```

---

## Task 3: 实现 Layer 1~3 (AST/CFG/DFG) 与 Layer 2 (跨文件符号解析器)

**Files:**
- Create: `internal/codeaudit/cpg/resolver.go`
- Create: `internal/codeaudit/cpg/builder.go`
- Test: `internal/codeaudit/cpg/builder_test.go`

- [ ] **Step 1: 编写过程内 CFG/DFG 与跨文件 SymbolResolver 测试**

在 `internal/codeaudit/cpg/builder_test.go` 中：
* 验证函数内基本块控制流边 (`CFG_NEXT`, `CFG_BRANCH`)；
* 验证变量到达定值流 (`DFG_DEF_USE`)；
* 验证跨模块导入符号解析（如 `from .utils import helper`）的 FQN 生成。

- [ ] **Step 2: 运行测试验证失败**

运行：`go test -v ./internal/codeaudit/cpg -run TestBuilder_CFG_DFG`
预期：FAIL。

- [ ] **Step 3: 实现 `resolver.go` (SymbolResolver)**

构建 `SymbolResolver`：
* 递归扫描工作区工程，构建模块树；
* 解析相对导入与绝对导入；
* 类定义与全局函数 FQN 注册。

- [ ] **Step 4: 实现 `builder.go` (CPGBuilder)**

构建 `CPGBuilder`：
* 将 AST 节点转换为 `CPGNode`；
* 递归构建函数体内的顺序流、分支流与循环流边；
* 计算定义与使用链，构建 `DFG_DEF_USE` 边；
* 连通调用点参数 `CALL_ARG` 与返回值 `CALL_RET`。

- [ ] **Step 5: 运行测试并验证通过**

运行：`go test -v ./internal/codeaudit/cpg -run TestBuilder_CFG_DFG`
预期：PASS。

- [ ] **Step 6: 提交代码**

```bash
git add internal/codeaudit/cpg/resolver.go internal/codeaudit/cpg/builder.go internal/codeaudit/cpg/builder_test.go
git commit -m "feat(cpg): implement intra-procedural CFG/DFG and cross-file symbol resolver"
```

---

## Task 4: 实现 Layer 4 (微服务边界穿透桥)

**Files:**
- Create: `internal/codeaudit/cpg/microservice.go`
- Test: `internal/codeaudit/cpg/microservice_test.go`

- [ ] **Step 1: 编写微服务边界穿透单测**

在 `internal/codeaudit/cpg/microservice_test.go` 中构造微服务 A（`requests.post("http://api/v1/task", json=payload)`）与微服务 B（`@app.post("/v1/task")` 中 `request.get_json()`），验证跨服务边 `MICROSERVICE_HTTP` 与 `MICROSERVICE_PAYLOAD` 正确合成。

- [ ] **Step 2: 运行测试验证失败**

运行：`go test -v ./internal/codeaudit/cpg -run TestMicroserviceBridge`
预期：FAIL。

- [ ] **Step 3: 实现 `microservice.go` (MicroserviceBoundaryBridge)**

实现：
* `ExtractClientCalls`：提取 `requests`, `httpx`, `urllib` 调用，解析 URL 与 payload 参数；
* `ExtractServerRoutes`：提取 Flask/FastAPI 路由装饰器及入参解析节点；
* `BridgeBoundaries`：归一化路径模式（如 `:param`），匹配成功后插入 `MICROSERVICE_HTTP`、`MICROSERVICE_PAYLOAD` 边。

- [ ] **Step 4: 运行测试并验证通过**

运行：`go test -v ./internal/codeaudit/cpg -run TestMicroserviceBridge`
预期：PASS。

- [ ] **Step 5: 提交代码**

```bash
git add internal/codeaudit/cpg/microservice.go internal/codeaudit/cpg/microservice_test.go
git commit -m "feat(cpg): implement microservice boundary bridge and cross-service edges"
```

---

## Task 5: 实现 Layer 5 (Worklist 污点引擎)、Layer 6 (因果切片) 与 AST 闭包切片器

**Files:**
- Create: `internal/codeaudit/cpg/taint_engine.go`
- Create: `internal/codeaudit/cpg/slicer.go`
- Create: `internal/codeaudit/cpg/scope_slicer.go`
- Test: `internal/codeaudit/cpg/taint_slicer_test.go`

- [ ] **Step 1: 编写污点追踪、因果切片与 AST 闭包切片测试**

在 `internal/codeaudit/cpg/taint_slicer_test.go` 中验证：
* 污点从 Source 穿透微服务边直达 Sink，能够被 Worklist 算法检出并阻断环路；
* `CPGEvidenceSlicer` 成功生成 `<300 Token` 的 `[Deep Audit Inter-Procedural Taint Trajectory]`；
* `ScopeSlicer` 针对给定行号能够完整抽取封闭函数定义（`def func(): ...`），并且具备降级滑窗兜底能力。

- [ ] **Step 2: 运行测试验证失败**

运行：`go test -v ./internal/codeaudit/cpg -run TestTaintAndSlicer`
预期：FAIL。

- [ ] **Step 3: 实现 `taint_engine.go` (InterProceduralTaintEngine)**

实现有限跳步（`MaxHops=50`）队列与已访问集合，遍历 `DFG_DEF_USE`、`CALL_ARG`、`MICROSERVICE_PAYLOAD`，输出 `TaintViolation`。

- [ ] **Step 4: 实现 `slicer.go` (CPGEvidenceSlicer)**

实现依据污点轨迹剪枝并生成标准文本因果树：
`[Deep Audit Inter-Procedural Taint Trajectory]`。

- [ ] **Step 5: 实现 `scope_slicer.go` (ASTScopeSlicer)**

实现通过 AST 定位行号所在的最小外层闭包（`FunctionDef` 或 `ClassDef`），若解析失败则回退至前后 7 行的物理安全滑窗。

- [ ] **Step 6: 运行测试并验证通过**

运行：`go test -v ./internal/codeaudit/cpg -run TestTaintAndSlicer`
预期：PASS。

- [ ] **Step 7: 提交代码**

```bash
git add internal/codeaudit/cpg/taint_engine.go internal/codeaudit/cpg/slicer.go internal/codeaudit/cpg/scope_slicer.go internal/codeaudit/cpg/taint_slicer_test.go
git commit -m "feat(cpg): implement worklist taint engine, evidence slicer and AST scope slicer"
```

---

## Task 6: 生产热路径深度集成（按需建图、证据注入与全局微服务缺陷合成）

**Files:**
- Modify: `internal/codeaudit/semgrep_engine.go`
- Modify: `internal/codeaudit/verifier.go`
- Test: `internal/codeaudit/cpg_integration_test.go`

- [ ] **Step 1: 编写生产全链路集成测试**

在 `internal/codeaudit/cpg_integration_test.go` 中构造包含微服务客户端和服务端的测试目录，验证：
1. Semgrep 产生 Findings 后自动激活 CPG；
2. 现有 Finding 的 `ContextAfter` / `CPGEvidence` 被成功替换为 AST 闭包切片与 CPG 因果树；
3. 成功合成了 `engine="cpg"` 且 `IsCrossFile=true, IsMicroservice=true` 的全局系统缺陷。

- [ ] **Step 2: 运行测试验证失败**

运行：`go test -v ./internal/codeaudit -run TestCPGIntegration`
预期：FAIL。

- [ ] **Step 3: 在 `semgrep_engine.go` 中集成 AST 闭包切片与 CPG 按需穿透分析**

修改 `semgrep_engine.go`：
* 用 `scopeSlicer.ExtractEnclosingScope` 替换物理滑窗 `extractContext`；
* 若 `len(findings) > 0`，调用 CPG 引擎对涉及目录进行跨文件/微服务拓扑分析；
* 回填 `f.CPGEvidence` 与 `f.TaintTrace`；
* 将检测到的微服务穿透后门作为新型 `engine="cpg"` Finding 追加至报告。

- [ ] **Step 4: 运行所有单测并验证全绿**

运行：`go test -v ./internal/codeaudit/... -p 1`
预期：全部 PASS。

- [ ] **Step 5: 提交代码**

```bash
git add internal/codeaudit/semgrep_engine.go internal/codeaudit/verifier.go internal/codeaudit/cpg_integration_test.go
git commit -m "feat(codeaudit): integrate CPG engine and evidence fusion into production scan pipeline"
```

---

## Task 7: 容器多语言规则同步、重新编译与端到端交付验证

**Files:**
- Modify: `configs/taa-production.json`
- Modify: `configs/taa-docker.json`
- Modify: 容器内 `/opt/taa/semgrep/rules/` 与 `/root/taa/bin/taa`
- Modify: `models/audit/research/taa-audit-design.html`（更新架构状态）

- [ ] **Step 1: 更新配置文件规则路径支持目录化**

将 `configs/taa-production.json` 与 `configs/taa-docker.json` 中的 `semgrepRulesPath` 配置项设置为目录：
```json
"semgrepRulesPath": "/opt/taa/semgrep/rules"
```

- [ ] **Step 2: 编译生产二进制 `bin/taa`**

运行：`go build -o bin/taa ./cmd/taa`
预期：编译成功，零 Cgo 警告。

- [ ] **Step 3: 将多语言规则与新二进制同步入运行容器**

```bash
docker exec taa-env-slim-v2 mkdir -p /opt/taa/semgrep/rules
docker cp models/audit/semgrep/rules/. taa-env-slim-v2:/opt/taa/semgrep/rules/
docker cp bin/taa taa-env-slim-v2:/root/taa/bin/taa
docker cp configs/taa-docker.json taa-env-slim-v2:/root/taa/configs/taa-docker.json
```

- [ ] **Step 4: 容器内端到端联调测试 (E2E Verification)**

1. 重启容器内 TAA 服务；
2. 注入纯净测试包 `pkg-clean.zip`，验证零告警快速旁路放行（Platform Mock 收到 `code=0`）；
3. 注入跨微服务恶意测试包，验证 CPG 证据成功生成、微服务缺陷合成、LLM 判定拦截，Platform Mock 收到 `code=1` 阻断，`/root/taa/models` 自动抹除。

- [ ] **Step 5: 同步更新设计文档 `models/audit/research/taa-audit-design.html`**

将文档中各层状态勋章由“离线原型”全部升级为“★ 生产已就绪 · 全量纯 Go 原生接入”。

- [ ] **Step 6: 提交交付代码与文档**

```bash
git add configs/ models/audit/research/taa-audit-design.html
git commit -m "docs(audit): finalize production CPG engine and multi-language rules delivery"
```
