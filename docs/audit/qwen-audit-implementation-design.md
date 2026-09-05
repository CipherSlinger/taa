# 基于 Qwen 模型的训练代码安全审计实现方案

> 版本: v1.0 | 日期: 2026-08-26
> 状态: 已实现
> 关联文档: `audit/audit-rules-design.md`, `final-training-report-template.md`, `taa接口设计文档.md`

---

## 1. 方案概述

### 1.1 背景与目标

在 TEE（可信执行环境）中，模型提供方提交的训练代码可能包含恶意行为——数据窃取、网络外传、隐写嵌入等。TAA（Trusted Attestation Agent）需要在训练代码执行前对其进行自动化安全审计，确保训练过程的可信性。

本方案采用 **静态规则扫描 + Qwen 小模型语义判断** 的两阶段审计架构，在资源受限的 TEE 环境中实现高精度、低误报的代码安全审计。

### 1.2 设计目标

| 目标 | 说明 |
|------|------|
| **高精度** | 宁可漏报也不误报，避免用户忽略真正的安全问题 |
| **低资源** | CPU-only 推理，无需 GPU，适配 TEE 受限环境 |
| **离线运行** | 全部推理在本地完成，无需联网 |
| **结构化输出** | 生成标准 JSON 审计报告，可嵌入训练报告上报平台 |
| **可配置策略** | 支持 `gate`（阻断/放行）和 `assist`（仅标注）两种审计策略 |

### 1.3 推荐模型

| 模型 | 量化 | 体积 | 适用场景 |
|------|------|------|----------|
| **Qwen2.5-Coder-0.5B-Instruct** (推荐) | Q4_K_M | ~400 MB | TEE 内审计，资源受限环境 |
| Qwen2.5-Coder-1.5B-Instruct | Q4_K_M | ~1 GB | 精度要求更高时使用 |
| DeepSeek-Coder-1.3B-Instruct | — | ~1.3 GB | 备选方案 |

---

## 2. 系统架构

### 2.1 整体架构

```
平台下发模型包（SM2 信封加密）
         ↓
    TAA 解密 → 解压到 MODEL_DIR
         ↓
    执行 debug.sh（模型验证脚本）
         ↓
┌───────────────────────────────────────┐
│        代码安全审计（两阶段）           │
│                                       │
│  Phase 1: 静态规则扫描                 │
│    Scanner (Go) / StaticScanner (Py)  │
│    ├── 正则匹配 13 条安全规则           │
│    ├── 排除注释行                      │
│    └── 输出 Findings 列表              │
│         ↓                             │
│  Phase 2: Qwen LLM 语义分析            │
│    OllamaClient → Ollama REST API     │
│    ├── Finding 级判断（逐条分析）       │
│    ├── 文件级综合分析（攻击链/外传）     │
│    └── 输出 LLM verdict/reason/risk   │
│         ↓                             │
│  Phase 3: Go 端聚合                    │
│    ├── 统计汇总                        │
│    ├── 风险等级判定                     │
│    ├── 结论与建议生成                   │
│    └── 输出 AuditReport JSON           │
└───────────────────────────────────────┘
         ↓
    审计通过 → 生成训练报告 → 上报平台
    审计不通过 → 生成失败报告 → 上报平台
```

### 2.2 组件关系

```
main.go
  ├── security.LLMConfig          # LLM 配置（模型、端点、策略、超时）
  ├── controller.SecurityConfig   # 安全扫描配置（开关、目录）
  └── controller.TAAState         # TAA 全局状态
        ↓
controller/import_processing.go
  └── processImportedResource()   # 资源导入主流程
        ├── 解密 → 解压 → debug.sh
        ├── security.GenerateAuditReport()   ← 审计入口
        │     ├── DefaultScanner().ScanDirectoryWithLines()   # Phase 1
        │     ├── VerifyReport()                               # Phase 2a
        │     │     └── OllamaClient.VerifyFinding()           # Qwen 推理
        │     ├── analyzeFileWithLLM()                         # Phase 2b
        │     │     └── OllamaClient.AnalyzeFile()             # Qwen 推理
        │     └── AssembleAuditReport()                        # Phase 3
        └── buildTrainingReport()  # 嵌入审计报告
              └── reportTrainingAsync()  # 异步上报平台
```

### 2.3 双语言实现

本方案同时提供 **Go**（生产环境，集成于 TAA HTTP 服务）和 **Python**（独立工具/CI，`code_security_analyzer.py`）两套实现，共享报告格式。Go 端规则库包含 13 条规则（含 EMB_001–004 结果嵌入检测），Python 端包含 9 条规则（不含 EMB 系列）。文件清单见附录 A。

---

## 3. 静态规则扫描引擎

### 3.1 规则体系

规则按 **严重度** 分为 HIGH 和 MEDIUM 两级，按 **类别** 覆盖 6 大安全域：

| 类别 | 规则 ID | 严重度 | 描述 | 修复建议 |
|------|---------|--------|------|----------|
| **网络外传** | `NET_001` | HIGH | HTTP/HTTPS 网络请求 | 移除网络请求，或限制为仅发送模型指标 |
| | `NET_002` | HIGH | 原始 Socket 连接 | 移除原始 Socket 连接 |
| **命令执行** | `CMD_001` | HIGH | 子进程/系统命令调用 | 移除子进程调用，使用安全的替代方案 |
| **代码混淆** | `OBF_001` | HIGH | 编码/反序列化操作 | 移除编码/反序列化操作 |
| **动态执行** | `DYN_001` | MEDIUM | eval/exec 动态代码执行 | 移除 eval/exec，使用安全的替代方案 |
| **敏感数据访问** | `FIL_001` | MEDIUM | 读取 SSH/密钥/凭证文件 | 移除敏感文件读取 |
| | `ENV_001` | MEDIUM | 读取环境变量 | 使用配置文件替代环境变量读取 |
| **持久化后门** | `PER_001` | HIGH | crontab/systemd/启动脚本 | 移除持久化机制 |
| **数据外传** | `EXF_001` | HIGH | 编码后发送（典型窃取模式） | 移除数据编码和发送操作 |
| **结果嵌入** | `EMB_001` | HIGH | 将训练数据写入输出文件 | 不要将原始数据写入输出文件 |
| | `EMB_002` | HIGH | 将数据复制到输出目录 | 不要将数据复制到输出目录 |
| | `EMB_003` | MEDIUM | 在日志中打印原始数据 | 避免在日志中打印原始数据 |
| | `EMB_004` | HIGH | 将数据编码后嵌入模型权重 | 不要将数据编码后嵌入模型权重 |

> 修复建议硬编码在 Go 端 `ruleSuggestionMap` 中，不依赖 LLM 生成，确保可靠性。

### 3.2 误报消除策略

静态扫描的核心挑战是区分 **框架 API 调用** 与 **恶意代码**。以 `DYN_001` 规则为例：

**问题**：PyTorch 代码中 `model.eval()` 极为常见，简单使用 `\beval\s*\(` 会产生大量误报。

**解决方案**：

| 语言 | 正则表达式 | 说明 |
|------|-----------|------|
| Go | `(?:^|[^.\w])eval\s*\(` | 非捕获组，确保 `eval` 前不是 `.` 或单词字符 |
| Python | `(?<!\.)\beval\s*\(` | 负向后行断言，排除 `.eval()` 方法调用 |

修复后两个测试模型（Retina-DKD 48 文件、TEE-test 6 文件）的误报全部消除，详见 §9.2。

### 3.3 扫描流程

```
ScanDirectory(dir)
  ├── filepath.Walk 遍历目录
  │   ├── 跳过: .git, __pycache__, venv, node_modules 等
  │   ├── 过滤: 仅扫描 .py 文件（可配置扩展名）
  │   └── 上限: MaxFindings=200 条后停止
  ├── ScanFile(path)
  │   ├── 逐行读取
  │   ├── 跳过注释行（# 开头）
  │   ├── 对每行匹配所有规则的编译后正则
  │   ├── 首条匹配即记录 Finding（含上下文 ±3 行）
  │   └── 每条 Finding 关联 SuggestionForRule() 修复建议
  └── 返回 Report{Findings, FilesCount, HighCount, MediumCount, Passed}
```

### 3.4 配置参数（Go 端）

- `Extensions`: `[".py"]` — 扫描的文件扩展名
- `MaxFindings`: `200` — 最大 Finding 数量上限
- `SkipDirs`: `.git`, `__pycache__`, `.idea`, `.vscode`, `node_modules`, `venv`, `.venv` — 跳过的目录名

---

## 4. Qwen LLM 语义分析引擎

### 4.1 推理后端

使用 **Ollama** 作为本地推理服务端。TAA 通过 `POST http://127.0.0.1:11434/api/generate` 调用 Qwen 推理。

**部署架构**（Ollama 与 TAA 同容器部署）：

```
TEE 容器
├── TAA 服务 (Go, :6001)
├── Ollama 服务 (ollama serve, :11434)
│   └── models/qwen2.5-coder:0.5b
└── attestation helpers
```

### 4.2 OllamaClient 实现

OllamaClient 封装了 Ollama REST API 调用，核心配置为 `endpoint`、`model`、`timeout`。

**推理参数**：

| 参数 | Finding 级 | 文件级 | 说明 |
|------|-----------|--------|------|
| `temperature` | 0.1 | 0.1 | 低温度确保输出稳定性和 JSON 格式一致性 |
| `num_predict` | 200 | 300 | 限制输出 token 数 |
| `stream` | false | false | 同步返回完整结果 |

### 4.3 Finding 级分析 Prompt

对每个静态扫描发现的 Finding，构造以下 Prompt 交由 Qwen 判断：

```
你是一个代码安全审计专家。请分析以下代码片段是否存在窃取数据、外传数据或其他恶意行为。

## 代码片段
文件: {file} (第 {line} 行)
```python
{context_before}
>>> {code_snippet}   ← 触发规则的代码
{context_after}
```

## 触发的规则
规则ID: {rule_id}
类别: {category}
严重度: {severity}
规则说明: {description}

## 请回答
1. verdict: MALICIOUS(恶意) / SUSPICIOUS(可疑) / BENIGN(正常) / UNCERTAIN(不确定)
2. reason: 一句话说明理由（中文）
3. risk: 如果恶意，数据会怎样被利用

请严格按以下 JSON 格式回答，不要包含其他内容:
{"verdict": "...", "reason": "...", "risk": "..."}
```

**LLM 输出解析**：从模型原始文本中提取第一个 `{...}` JSON 块，解析为 `LLMDecision` 结构体。无法解析时返回 `UNCERTAIN`。

### 4.4 文件级综合分析 Prompt

对每个包含 Finding 的文件，构造整体分析 Prompt：

```
分析此 Python 文件的安全性。

文件: {file} ({line_count} 行)
发现 {findings_count} 个可疑点: {findings_summary}

```python
{full_code}  // 最多 80 行
```

判断:
1. risk_level: HIGH/MEDIUM/LOW
2. summary: 一句话安全结论(中文)
3. chained: 多个可疑点是否构成攻击链(true/false)
4. exfiltration: 是否有数据外传(true/false)

严格按 JSON 回答:
{"risk_level":"...","summary":"...","chained":true,"exfiltration":true}
```

文件级分析的核心价值：
- **攻击链检测** (`chained`)：识别多个独立 Finding 组合成的攻击模式（如读文件→编码→网络发送）
- **数据外传检测** (`exfiltration`)：判断代码是否整体构成数据外传行为

### 4.5 LLM 策略模式

| 策略 | 环境变量 | 行为 |
|------|----------|------|
| `assist` (默认) | `SECURITY_LLM_POLICY=assist` | LLM 结果仅标注在报告中，不改变阻断决策；静态扫描的 HIGH 仍阻断 |
| `gate` | `SECURITY_LLM_POLICY=gate` | LLM 判定 BENIGN 的 HIGH Finding 可降级放行；仅 MALICIOUS/SUSPICIOUS 阻断 |

**策略决策逻辑**：`assist` 模式下 `passed` 仅由静态扫描决定；`gate` 模式下仅 `MALICIOUS`/`SUSPICIOUS` 阻断，`BENIGN` 的 HIGH Finding 可降级放行。

### 4.6 容错与 Fail-Closed

容错设计详见 §10.2（统一的 Fail-Closed 表格）。LLM 推理单次超时为 60s，超时或异常时该 Finding 标记为 `UNCERTAIN` 并继续分析下一个。

---

## 5. 审计报告聚合

### 5.1 报告生成流程

审计三阶段流程（静态扫描 → LLM 语义分析 → 聚合）详见 §2.1 架构图。此处描述聚合阶段（Phase 4）的具体逻辑：

1. **按风险排序**：文件报告按 CRITICAL → HIGH → MEDIUM → LOW 排序
2. **聚合统计**：`ComputeStatistics` 汇总各严重度和 verdict 的计数
3. **计算结论**：`ComputeConclusion` 根据统计和策略判定 `passed` 和 `risk_level`
4. **生成建议**：`buildRecommendation` 从 MALICIOUS/SUSPICIOUS Finding 的规则 ID 生成修复建议

### 5.2 风险等级判定

```
MALICIOUS > 0                    → CRITICAL
HIGH > 0 && SUSPICIOUS > 0      → HIGH
HIGH > 0 (LLM 判定 BENIGN)      → MEDIUM
MEDIUM > 0                      → LOW
无 Finding                       → NONE
```

### 5.3 报告数据结构

审计报告的完整 JSON Schema 定义见 `final-training-report-template.md` §4（`validation.code_audit` 部分）。Go 端通过 `AssembleAuditReport()` 函数聚合生成，报告嵌入训练报告的 `validation.code_audit` 字段，通过 `/v1/taa/reportRes` 上报平台。

---

## 6. 结果导出检查

除代码审计外，TAA 还对训练结果导出执行安全检查，防止明文数据泄露：

### 6.1 检查项目

| 检查项 | 说明 | 严重度 |
|--------|------|--------|
| **体积异常** | 结果文件超过 500MB 上限 | MEDIUM |
| **明文段检测** | 结果二进制中包含 CSV header、JSON 数据、PEM 密钥等明文特征 | HIGH |
| **数据指纹匹配** | 结果文件与训练数据文件的前 64 字节匹配 | HIGH |

### 6.2 明文特征库

```
CSV header (training data): "id,label,image"
CSV header (patient data):  "patient_id"
JSON data array:            "data":[
JSON samples array:         "samples":[
PEM private key:            "-----BEGIN"
AWS credentials:            "aws_secret_access_key"
Database connection:        "postgresql://" / "mysql://"
Environment dump:           "SECRET_KEY=" / "API_KEY="
```

---

## 7. TAA 集成流程

### 7.1 资源导入与审计触发

资源导入的完整接口规范见 `taa接口设计文档.md` §4.2。此处仅描述审计集成点：

当 `type=1`（模型包）且资源类型与当前阶段匹配时，TAA 在解压和执行 `debug.sh` 之后调用 `security.GenerateAuditReport()` 审计 `MODEL_DIR`；当 `type=2`（测试数据）且处于 phase 2 时，TAA 在解压到 `DATA_DIR` 并执行 `train.sh` 后同样审计 `MODEL_DIR`。审计结论 `passed=true` 时生成成功训练报告，`passed=false` 时生成失败报告，均通过 `/v1/taa/reportRes` 异步上报平台。

### 7.2 阶段控制

阶段切换规则详见 `taa接口设计文档.md` §4.3。各阶段下资源导入的触发行为：

| 阶段 | type=1 (模型) | type=2 (测试数据) | type=3 (训练数据) |
|------|-------------|-----------------|-----------------|
| 1 调试 | 触发训练 + 审计 | 仅记录 | 仅记录 |
| 2 测试 | 仅记录 | 执行 train.sh + 审计 MODEL_DIR | 仅记录 |
| 3 正式训练 | 仅记录 | 仅记录 | 触发训练 |

### 7.3 结果导出检查

导出接口规范见 `taa接口设计文档.md` §4.4。导出前执行 `CheckExport(resultDir, dataDir)`，检查项详见 §6。

---

## 8. 部署配置

### 8.1 TAA 启动参数

| 参数 | 环境变量 | 默认值 | 说明 |
|------|----------|--------|------|
| `-security-scan` | `SECURITY_SCAN` | `true` | 启用代码安全扫描 |
| `-security-llm-verify` | `SECURITY_LLM_VERIFY` | `true` | 启用 LLM 语义验证 |
| `-security-llm-endpoint` | `SECURITY_LLM_ENDPOINT` | `http://127.0.0.1:11434` | Ollama 端点 |
| `-security-llm-model` | `SECURITY_LLM_MODEL` | `qwen2.5-coder:0.5b` | Qwen 模型名 |
| `-security-llm-policy` | `SECURITY_LLM_POLICY` | `assist` | LLM 策略 |
| `-security-llm-fail-closed` | `SECURITY_LLM_FAIL_CLOSED` | `true` | LLM 不可用时阻断 |
| `-result-check` | `RESULT_CHECK` | `true` | 启用结果导出检查 |
| `-model-dir` | `MODEL_DIR` | `/opt/taa/models` | 模型代码目录 |
| `-data-dir` | `DATA_DIR` | `/opt/taa/data` | 数据目录 |
| `-result-dir` | `RESULT_DIR` | `/opt/taa/results` | 结果目录 |

### 8.2 Ollama 部署

Ollama 以独立进程运行在 TAA 同一容器内：

```sh
# 启动 Ollama（离线包部署）
DIR=/taatest/ollama-qwen2.5-coder-0.5b
export OLLAMA_HOST=127.0.0.1:11434
export OLLAMA_MODELS=$DIR/models/models
export OLLAMA_LIBRARY_PATH=$DIR/lib/ollama
$DIR/ollama serve
```

**健康检查**：TAA 启动后通过 `GET http://127.0.0.1:11434/` 检查 Ollama 是否就绪，最长等待 120 秒。

### 8.3 Kubernetes 部署

通过 `deploy_taa.sh` 一键部署三个组件：

```sh
# 部署全部组件
./deploy_taa.sh platform-mock taa qwen

# 仅部署 Qwen
./deploy_taa.sh qwen

# 环境变量覆盖
TARGET_POD=xxx TARGET_NAMESPACE=osr ./deploy_taa.sh
```

部署流程：
1. 交叉编译 TAA / Platform Mock 二进制
2. SCP 上传到远程宿主机
3. kubectl cp 复制到 Pod 容器
4. 启动 Ollama 并等待就绪
5. 启动 TAA 服务

---

## 9. 测试验证

### 9.1 测试覆盖

| 测试文件 | 测试内容 |
|----------|----------|
| `security/scanner_test.go` | 静态扫描器单元测试 |
| `security/llm_test.go` | LLM 客户端和 JSON 解析测试 |
| `security/audit_test.go` | 审计报告聚合测试（24 个用例） |
| `security/result_checker_test.go` | 结果导出检查测试 |
| `controller/handler_test.go` | HTTP 路由和集成测试 |
| `controller/import_flow_new_test.go` | 导入流程集成测试 |
| `controller/report_test.go` | 报告生成测试 |

**全部 68 个测试用例通过。**

### 9.2 真实模型验证

| 模型 | Python 文件数 | 修复前 Findings | 修复后 Findings | 误报率 |
|------|-------------|----------------|----------------|--------|
| Retina-DKD | 48 | 13 (11 误报) | 2 (0 误报) | 0% |
| TEE-test | 6 | 2 (2 误报) | 0 (0 误报) | 0% |

### 9.3 Python 独立工具

`code_security_analyzer.py` 支持 `--backend none`（仅静态扫描）和 `--backend ollama`（含 LLM 分析）两种模式，通过 `--policy gate/assist` 控制策略，`--output` 指定报告输出路径。完整参数见 `--help`。

---

## 10. 安全考量

### 10.1 审计绕过防护

- **非 `.py` 扩展名**：通过 `Extensions` 配置覆盖更多文件类型
- **注释隐藏恶意代码**：跳过注释行但保留上下文窗口供 LLM 分析
- **base64/pickle 混淆**：`OBF_001` 规则覆盖
- **动态下载恶意代码**：`NET_001` + `CMD_001` 规则覆盖
- **数据嵌入模型权重**：`EMB_004` 规则覆盖
- **结果文件含明文数据**：`ResultChecker` 数据指纹检测（§6）

### 10.2 Fail-Closed 设计原则

所有安全检查点遵循 **Fail-Closed** 原则——当组件不可用或出错时，默认拒绝而非放行：

| 组件 | 故障行为 | 处理方式 |
|------|----------|----------|
| 静态扫描器 | 扫描报错 | 拒绝导入 |
| Ollama 服务 | 连接失败 | `FailClosed=true` 时拒绝导入；`false` 时跳过 LLM，仅用静态扫描 |
| LLM 推理 | 超时 (60s) / 异常 | 该 Finding 标记 `UNCERTAIN`，继续分析下一个 |
| LLM 输出 | JSON 解析失败 / 非法 verdict | 归一化为 `UNCERTAIN` |
| LLM 能力限制 | 0.5B 模型对 PyTorch API 可能幻觉 | `assist` 策略下 LLM 不改变阻断决策 |
| 审计报告 | 生成失败 | 拒绝导入 + 上报失败 |
| 结果检查 | 检查报错 | 拒绝导出 |

---

## 11. 附录

### A. 文件清单

| 文件 | 用途 |
|------|------|
| `internal/security/rules.go` | Go 端安全规则定义（13 条） |
| `internal/security/scanner.go` | Go 端静态扫描引擎 |
| `internal/security/llm.go` | Go 端 Ollama LLM 客户端 |
| `internal/security/verifier.go` | Go 端 LLM 验证流程编排 |
| `internal/security/audit.go` | Go 端审计报告聚合 |
| `internal/security/result_checker.go` | Go 端结果导出检查 |
| `models/code_security_analyzer.py` | Python 端独立审计工具 |
| `models/generate_training_report.py` | Python 端训练报告生成 |
| `ollama-qwen2.5-coder-0.5b/` | Qwen 0.5B Ollama 离线包 |
| `ollama-qwen2.5-coder-1.5b/` | Qwen 1.5B Ollama 离线包 |
| `deploy_taa.sh` | 一键部署脚本 |

### B. 环境变量速查

安全扫描和资源路径的环境变量详见 §8.1 启动参数表。以下为 §8.1 未覆盖的平台配置变量：

| 变量 | 说明 |
|------|------|
| `PLATFORM_IP` | 平台地址（`IP:PORT`），TAA 注册和上报使用 |
| `DOCKER_ID` | 容器 ID，用于注册绑定和 attestation USERDATA |
