# TAA 代码安全审计规则设计方案

> 版本: v2.0 | 更新日期: 2026-08-25
> 适用模型: qwen2.5-coder:0.5b / 1.5b

## 1. 架构概述

```
源代码目录
    ↓
[静态规则扫描] ← 正则匹配，快速筛选可疑代码
    ↓
可疑 Findings 列表
    ↓
[LLM 语义分析] ← 小模型判断每个 finding 是否为真正的安全风险
    ↓
结构化审计报告（JSON）
```

## 2. 规则设计原则

### 2.1 核心原则
- **高精度优先**: 宁可漏报也不误报，误报会导致用户忽略真正的安全问题
- **排除常见模式**: 明确排除 PyTorch/TensorFlow 等深度学习框架的常见 API 调用
- **上下文感知**: 规则不仅匹配函数名，还要考虑调用上下文（如方法调用 vs 内置函数）

### 2.2 误报消除策略

| 误报模式 | 原因 | 修复方案 |
|----------|------|----------|
| `model.eval()` / `net.eval()` | PyTorch 模型评估模式切换，非 Python `eval()` | 使用负向后行断言 `(?<!\.)` 排除方法调用 |
| `self.model.eval()` | 同上 | 同上 |
| `torch.no_grad()` | PyTorch 梯度控制 | 不匹配（非可疑模式） |
| `torch.load()` / `torch.save()` | PyTorch 模型序列化 | 仅在配合编码/网络操作时才标记 |

## 3. 规则清单

### 3.1 高危规则 (HIGH)

| 规则ID | 类别 | 描述 | 正则模式 |
|--------|------|------|----------|
| `NET_001` | 网络请求 | HTTP/HTTPS 请求，可能向外发送数据 | `requests\.(get\|post\|put\|delete\|patch)` 等 |
| `NET_002` | 底层网络 | 原始 Socket 连接 | `socket\.socket\s*\(` 等 |
| `CMD_001` | 命令执行 | 子进程/系统命令 | `subprocess\.(run\|call\|Popen)`, `os\.system` 等 |
| `OBF_001` | 代码混淆 | 编码/反序列化，可能隐藏恶意载荷 | `base64\.(b64decode\|b64encode)`, `pickle\.loads` 等 |
| `PER_001` | 持久化后门 | 持久化机制 | `crontab`, `systemctl`, `/etc/init\.d` 等 |
| `EXF_001` | 数据外传 | 编码后发送 | `base64.*request`, `json\.dumps.*post` 等 |
| `EMB_001` | 结果嵌入 | 将训练数据写入输出文件 | `open.*write.*(data\|dataset)` 等 |
| `EMB_002` | 结果嵌入 | 将数据复制到输出目录 | `shutil\.(copy\|move).*output` 等 |
| `EMB_004` | 结果嵌入 | 将数据编码后嵌入模型权重 | `base64.*save`, `pickle\.dump.*(data)` 等 |

### 3.2 中危规则 (MEDIUM)

| 规则ID | 类别 | 描述 | 正则模式 | 排除模式 |
|--------|------|------|----------|----------|
| `DYN_001` | 动态执行 | Python `eval()`/`exec()` 内置函数 | `(?<!\.)\beval\s*\(` | `.eval()` 方法调用（PyTorch） |
| `FIL_001` | 敏感文件 | 读取 SSH/密钥/凭证文件 | `open.*\.(ssh\|env\|aws\|kube)`，`Path(...).read_text()`，`Path.home().joinpath(...)` | — |
| `ENV_001` | 环境变量 | 读取敏感环境变量获取密钥 | `os\.environ`, `os\.environ\.get`, `os\.getenv`（仅限 secret/token/key/password 等名称） | — |
| `EMB_003` | 结果嵌入 | 在日志中打印原始数据 | `print.*(data\|dataset)` | — |

### 3.3 DYN_001 规则详细说明（误报修复重点）

**修复前（产生大量误报）:**
```python
# Python 端
patterns = [r"\beval\s*\(", r"\bexec\s*\("]

# Go 端
patterns = [`[^.\w]eval\s*\(|^eval\s*\(`, `[^.\w]exec\s*\(|^exec\s*\(`]
```

问题: `\b`（word boundary）在 `.eval` 处也会匹配，因为 `.` 不是单词字符。

**修复后:**
```python
# Python 端 — 使用负向后行断言
patterns = [r"(?<!\.)\beval\s*\(", r"(?<!\.)\bexec\s*\("]

# Go 端 — 使用非捕获组明确起始位置
patterns = [`(?:^|[^.\w])eval\s*\(`, `(?:^|[^.\w])exec\s*\(`]
```

**效果:**
| 代码 | 修复前 | 修复后 | 说明 |
|------|--------|--------|------|
| `model.eval()` | ❌ 误报 | ✅ 跳过 | PyTorch 评估模式 |
| `net.eval()` | ❌ 误报 | ✅ 跳过 | PyTorch 评估模式 |
| `self.model.eval()` | ❌ 误报 | ✅ 跳过 | PyTorch 评估模式 |
| `eval(user_input)` | ✅ 检测 | ✅ 检测 | Python eval 函数调用 |
| `eval(label[0])` | ✅ 检测 | ✅ 检测 | Python eval 函数调用 |
| `exec(code_string)` | ✅ 检测 | ✅ 检测 | Python exec 函数调用 |

## 4. LLM Prompt 设计

### 4.1 Finding 级判断 Prompt

```
你是代码安全审计专家。分析以下代码是否有恶意行为。

文件: {file} (第 {line} 行)
```python
{context_before}
>>> {code_snippet}   ← 触发规则的代码
{context_after}
```

触发规则: {rule_id} ({category})
严重度: {severity}
说明: {description}

请判断这段代码是否构成安全风险，返回 JSON:
{"verdict": "MALICIOUS/SUSPICIOUS/BENIGN/UNCERTAIN", "reason": "一句话理由", "risk": "风险描述"}
```

### 4.2 注意事项（0.5b 模型限制）

0.5b 模型能力有限，已知问题：
- 对 PyTorch `torch.no_grad()` 可能产生幻觉判断
- JSON 输出偶尔不稳定
- 复杂代码链判断能力弱

建议：
- `SECURITY_LLM_POLICY=assist`（LLM 结果仅供参考，不改变阻断决策）
- 对 0.5b 模型降低期望，主要用于辅助人工审查

## 5. 审计报告模板

> 以下为带注释的报告模板，使用 `jsonc` 便于说明字段含义；实际输出报告时应移除注释，保持标准 JSON 格式。

```jsonc
{
  "report_id": "audit-YYYYMMDD-HHMMSS-randomid",  // 报告唯一标识，建议包含审计日期、时间和随机 ID，便于追踪与归档
  "audit_time": "ISO8601 timestamp",              // 审计执行时间，使用 ISO8601 格式，例如 2026-08-25T10:30:00Z
  "target": {                                      // 本次审计目标的整体信息
    "directory": "扫描目录路径",                   // 被扫描的源代码目录路径
    "files_scanned": 48,                          // 实际参与扫描的文件数量
    "total_lines": 13542,                         // 所有扫描文件的总代码行数
    "files_with_findings": 2                      // 至少包含一个 finding 的文件数量
  },
  "conclusion": {                                  // 本次审计的总体结论
    "passed": true,                               // 是否通过审计；true 表示未发现需要阻断的安全风险，false 表示存在高风险或明确恶意问题
    "risk_level": "MEDIUM",                       // 综合风险等级，取值 LOW、MEDIUM、HIGH、CRITICAL
    "summary": "审计结论摘要",                     // 面向用户的审计结论摘要，概括主要风险与判断依据
    "recommendation": "人工复核"                   // 面向用户的处理建议，例如继续人工复核、修复高危代码或拒绝运行
  },
  "statistics": {                                  // 全局统计信息，用于快速了解 findings 数量和 LLM 判断分布
    "total_findings": 2,                          // 所有文件中命中的 findings 总数
    "high": 1,                                    // 严重度为 HIGH 的 findings 数量
    "medium": 1,                                  // 严重度为 MEDIUM 的 findings 数量
    "malicious": 0,                               // LLM 判定为 MALICIOUS 的 findings 数量
    "suspicious": 0,                              // LLM 判定为 SUSPICIOUS 的 findings 数量
    "benign": 0,                                  // LLM 判定为 BENIGN (良性) 的 findings 数量
    "uncertain": 0                                // LLM 判定为 UNCERTAIN 的 findings 数量
  },
  "file_reports": [                                // 按文件聚合的审计结果列表
    {
      "file": "test_run.py",                      // 存在 findings 的文件路径，建议使用相对扫描根目录的路径
      "risk_level": "HIGH",                       // 当前文件的综合风险等级，由文件内 findings 严重度、链式行为和外传模式共同决定
      "findings_count": 1,                        // 当前文件中的 findings 数量
      "chained": false,                           // 是否存在多条可疑行为形成的攻击链，例如读取敏感数据后编码并发送
      "has_exfiltration_pattern": false,          // 是否命中数据外传相关模式，例如编码后网络发送、上传文件或写入远端接口
      "findings": [                               // 当前文件内的具体 findings 列表
        {
          "rule_id": "CMD_001",                   // 命中的静态规则 ID，对应规则清单中的规则编号
          "severity": "HIGH",                     // 该 finding 的规则严重度，通常为 HIGH 或 MEDIUM
          "code_snippet": "os.system(order)",     // 触发规则的关键代码片段，用于人工复核定位问题
          "llm_verdict": "MALICIOUS",             // LLM 对该 finding 的语义判断，取值为 MALICIOUS、SUSPICIOUS、BENIGN 或 UNCERTAIN
          "llm_reason": "执行系统命令",             // LLM 给出的简短判断理由，应说明为什么认为其有风险或可接受
          "suggestion": "移除子进程调用"             // 针对该 finding 的修复或处置建议
        }
      ]
    }
  ]
}
```

## 6. 验证结果

### 6.1 测试模型: Retina-DKD (48 个 Python 文件)

| 版本 | Findings | 误报 | 真正问题 |
|------|----------|------|----------|
| 修复前 | 13 | 11 (`model.eval()` 等) | 2 |
| **修复后** | **2** | **0** | 2 (`os.system`, `eval()`) |

### 6.2 测试模型: TEE-test (6 个 Python 文件)

| 版本 | Findings | 误报 | 真正问题 |
|------|----------|------|----------|
| 修复前 | 2 | 2 (`model.eval()`) | 0 |
| **修复后** | **0** | **0** | 0 |

### 6.3 Go 测试

全部 68 个测试通过，包括:
- `TestScannerOnTEEtestModel`: TEE-test 扫描 6 文件, 0 findings
- `TestScannerDetectsPersistence`: 持久化检测
- `TestScannerBenignSavePasses`: 正常保存不误报
- `TestAuditReport*`: 审计报告生成测试 (24 个)
