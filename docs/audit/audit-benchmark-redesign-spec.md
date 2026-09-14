# Audit-100 v2 Benchmark 架构重构规约

## 1. 痛点分析与重构动因

当前的 Audit-100 v1 基准体系源于微探针（Micro-benchmark）设计，在面对工业级生产落地时暴露出以下系统性缺陷：

1. **良性样本 0 Findings 架空动静协同核心价值**：
   - 50 个良性样本在静态扫描阶段全部 0 命中，触发“零命中快速旁路”直接放行。
   - 大模型在整个协同审计流程中**完全没有审过任何良性代码**，无法量化大模型最重要的“消除静态误报（De-noising）”能力。
2. **恶意样本仅 1 Finding 导致审计降维为单行判断**：
   - 恶意样本仅注入孤立的单点攻击，缺乏真实业务背景代码中的正常操作作为干扰项。
   - 现实中黑客攻击通常潜伏在正常系统调用（如显存查询、环境变量读取）之间，单 finding 无法评估大模型“沙里淘金”的抗噪识别能力。
3. **引擎 80 行硬编码截断引入长文件感知盲区**：
   - 分析引擎 `models/examples/code_security_analyzer.py:406` 硬编码截取前 80 行代码。长文件在 80 行后注入的特征无法被整文件总结感知，易引发假性 `UNCERTAIN`。
4. **基底工程单向绑定导致捷径学习（Shortcut Learning）**：
   - 良性样本全部基于 `LogisticRegression`/`TEE-test`，恶意样本全部基于 `Retina-DKD`。
   - 大模型可通过感知上下文中的 `import torch` 或医疗图像预处理直接推断标签，存在严重的作弊漏洞。
5. **工程文件规模极度不平衡引入算力倾斜**：
   - `Retina-DKD` 包含 53 个 `.py` 文件，而 `LogisticRegression` 仅 3 个文件。在 `pure-llm` 盲审时，单个样本处理耗时相差 18 倍，基准耗时被非核心测试文件绑架。
6. **静态正则缺少大小写不敏感（Case-Sensitivity）支持**：
   - 正则编译未加 `re.IGNORECASE`，常见的全大写敏感环境变量（如 `AWS_REGION`、`API_KEY`）反而无法触发规则，导致误报探针失效。

---

## 2. 双轨评测体系 (Dual-Track Architecture)

Audit-100 v2 将评测集重构为 **双轨双阶（Dual-Track）50:50 矩阵**（共 100 样本）：

```
                                  Audit-100 v2 评测基准
                                            │
          ┌─────────────────────────────────┴─────────────────────────────────┐
          ▼                                                                   ▼
   【Track 1: Micro-Bench】                                            【Track 2: Scenario-Bench】
     微观原子探针轨 (50 样本)                                            复合实战场景轨 (50 样本)
          │                                                                   │
  ┌───────┴───────┐                                                   ┌───────┴───────┐
  ▼               ▼                                                   ▼               ▼
25 例良性原子    25 例恶意原子                                       25 例良性硬负样本 25 例恶意多告警样本
(0 finding)     (1 finding)                                         (Hard Negatives) (Multi-Finding)
完全合规纯代码   单变量缺陷注入                                      1~3 正常高疑告警  2~4 告警 (1攻+N噪)
测试语法理解下限 测试单点逃逸捕获                                    测试 LLM 消噪能力 考验背景杂音识别
```

### 2.1 Track 1: Micro-Bench（微观原子探针轨，50 样本）
* **定位**：严格遵循控制变量法，排除长上下文和多告警干扰，评估模型对孤立语法的微观判别基线。
* **样本结构**：
  * **良性原子（B1~B5，25 样本）**：纯净代码重构、标准输出打点、合法基础配置读取等。静态 rules 扫描结果严格为 **0 finding**（全部触发毫秒级快速旁路）。
  * **恶意原子（M1~M5，25 样本）**：孤立的反弹 Shell、直接读 `/etc/shadow`、明文 base64/eval 动态加载等。静态 rules 扫描结果严格为 **1 finding**。

### 2.2 Track 2: Scenario-Bench（复合实战场景轨，50 样本）
* **定位**：高保真模拟真实算法工程中的复杂多告警环境，测试大模型在强干扰下的消噪能力与攻击归因精度。
* **样本结构**：
  * **良性硬负样本（Hard Negatives, HN1~HN5，25 样本）**：
    * `HN1: 合规环境与密钥探针`：合规读取 `os.environ.get("api_token")` 或本地公开配置，触发 `ENV_001`/`FIL_001`，但数据严格在本地使用，无任何网络外发。
    * `HN2: 硬件监控与诊断子进程`：调用 `subprocess.run(["nvidia-smi", ...])` 定期查询 GPU 状态，触发 `CMD_001`，但命令固定白名单且无 shell 注入。
    * `HN3: 本地特征与模型序列化`：使用 `torch.save` 或本地 `pickle.dump` 序列化模型，或将图像缩略图做 Base64 编码保存在本地缓存目录，触发 `OBF_001`，但无动态执行。
    * `HN4: 内网服务探测与健康上报`：使用 `urllib.request.urlopen("http://127.0.0.1:8080/health")` 探测回环地址健康状态，触发 `NET_001`，但目标非跨域公网。
    * `HN5: 动态白名单反射加载`：基于字典白名单通过 `getattr(module, class_name)` 加载模型组件，触发 `DYN_001`，但受到严格白名单约束。
    * **预期表现**：静态扫描产生 **1~3 个 findings**；动静协同中送入大模型，大模型结合 7 行上下文判断其为安全合规行为，全部给出 **BENIGN（消噪放行）**。
  * **恶意多告警样本（Multi-Finding Adversarial, ADV1~ADV5，25 样本）**：
    * 在植入真实恶意后门（反向 Shell、凭据窃取回传、提权脚本）的同时，保留或注入 1~3 个上述良性系统调用（如正常显存监控、正常环境读取）。
    * **预期表现**：静态扫描产生 **2~4 个 findings**（1 个真攻击 + 1~3 个良性噪点）。大模型必须准确指出哪一行是真正攻击，给出 **MALICIOUS（阻断）**。

---

## 3. 五大防作弊与工程高保真机制

### 3.1 跨工程交叉基座分配（Cross-Project Anti-Shortcut Allocation）
彻底打破基底工程与恶意标签绑定的历史缺陷，3 个真实基座工程均匀承载正负样本：

| 基底工程名称 | 承担样本总量 | 良性纯净 (B) | 良性硬负 (HN) | 恶意原子 (M) | 恶意多告警 (ADV) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`LogisticRegression`** (经典 ML) | 34 样本 | 9 样本 | 8 样本 | 9 样本 | 8 样本 |
| **`TEE-test`** (可信隐私计算工程) | 33 样本 | 8 样本 | 9 样本 | 8 样本 | 8 样本 |
| **`Retina-DKD`** (复杂深度学习视觉) | 33 样本 | 8 样本 | 8 样本 | 8 样本 | 9 样本 |
| **全集汇总 (Audit-100 v2)** | **100 样本** | **25 样本** | **25 样本** | **25 样本** | **25 样本** |

*任何模型均无法通过 `import torch`、`sklearn` 或视觉数据集依赖作为标签预测的近道。*

### 3.2 动态告警滑动上下文（Sliding Context Window）
针对 `analyze_file` 80 行硬编码截断问题：
* 在处理包含 Finding 的长文件时，如果文件超过 80 行，**以 Finding 所在行为中心**，向上提取 30 行、向下提取 30 行形成 60~70 行的局部动态视窗；
* 并在视窗首尾标明 `[Line X - Line Y Context Window]`，确保大模型无论在单告警微观仲裁还是整文件宏观裁决中，均能完整看到告警实体的真实语境。

### 3.3 Finding 级真值元数据（Finding-Level Ground Truth Schema）
在每个样本的 `sample.json` 中结构化声明告警级真值，彻底避免归因模糊：
```json
{
  "sample_id": "ADV1-01",
  "label": "malicious",
  "findings_manifest": [
    {
      "finding_id": "F1",
      "rule_id": "CMD_001",
      "target_file": "benchmark_variant.py",
      "target_line": 15,
      "expected_verdict": "BENIGN",
      "is_malicious": false
    },
    {
      "finding_id": "F2",
      "rule_id": "NET_002",
      "target_file": "benchmark_variant.py",
      "target_line": 32,
      "expected_verdict": "MALICIOUS",
      "is_malicious": true
    }
  ]
}
```

### 3.4 工程文件规模归一化（Auditable Scope Normalization）
对基底工程（尤其是深层嵌套的 `Retina-DKD`）进行剪枝：仅保留核心训练流水线代码（5~8 个 `.py` 文件），剥离冗余的重复测试脚本（如 30 余个 `test_*.py`），确保三大基底在 `pure-llm` 模式下的可审计文件规模保持在 5~8 个文件以内，消灭算力严重倾斜。

### 3.5 规则扫描大小写容错与 Ollama 超时防护
1. **正则大小写不敏感**：在 `StaticScanner` 中使用 `re.compile(p, re.IGNORECASE)`，完美支持合规的大写环境变量（`API_KEY`、`AWS_REGION`）探测；
2. **Ollama 推理超时适配**：HTTP 客户端超时从 60s 提升至 120s，并在 options 中固定 `num_ctx: 2048`，防止 CPU 环境下 7B/8B 处理长 prompt 产生虚假超时。

---

## 4. 全新指标度量体系

### 4.1 静态误报消除率 (De-noising Rate, DNR)
$$\text{DNR} = \frac{\text{良性硬负样本中被 LLM 判定为 BENIGN 的静态告警数}}{\text{良性硬负样本触发的静态告警总数}} \times 100\%$$
* **适用模式**：仅适用于 `static-llm`；在 `pure-llm` 模式下列标为 `N/A (无先验规则)`。
* **工程价值**：量化衡量大模型能否“看懂业务代码意图，压下机械死板的静态告警”。
* **策略依赖**：消噪能力强依赖于 `--policy gate` 门禁策略；在 `assist` 模式下静态 HIGH 告警拥有一票否决权，无法消除。

### 4.2 攻击归因准确率 (Attribution Accuracy, Attr-Acc)
对于包含多告警的恶意样本（ADV1~ADV5）：
$$\text{Attr-Acc} = \frac{\text{所有 is_malicious=True 的 Finding 被正确判定为 MALICIOUS 且未将所有良性噪点全量误判的样本数}}{\text{多告警恶意样本总数 (25)}} \times 100\%$$
*防止大模型“把显存监控误当木马、却放过真正反弹 Shell”导致的碰巧拦截（歪打正着）。*

### 4.3 真实动态算力旁路率 (Dynamic Bypass Rate)
$$\text{Bypass Rate} = \frac{\text{静态规则判定为 0 Finding 直接放行的样本数}}{\text{总样本数 (100)}} \times 100\%$$
*由于 Track 1 保留了 25 例纯净良性样本，基准集自然呈现出 **25.0% 左右的真实旁路率**（其余 75 个样本进入大模型仲裁）。*

### 4.4 单告警裁决耗时 (Per-Finding Latency) 与 进审单样耗时 (Per-Sample Latency)
* **单告警裁决耗时（底层原子算力基准）**：
  $$\text{Per-Finding Latency} = \frac{\text{LLM 推理实际总耗时}}{\text{进入 LLM 裁决的 Findings 总数}}$$
  *这是一个由硬件架构与模型参数量决定的恒定物理常数（例如 3B 模型在 CPU 上约为 14.8 秒/finding）。*
* **进审单样耗时（业务交付感知）**：
  $$\text{Per-Sample Latency (进审样本)} = \frac{\text{LLM 推理实际总耗时}}{100 - \text{Bypass Count}}$$
  *在生产中，一个复杂工程往往有 10~15 个 findings，单工程耗时自然达到 $15 \times 14.8\text{s} \approx 4\sim 5\text{ 分钟}$；而基准测试中单样本 1~3 个 findings，进审耗时表现为 15~45 秒。该双口径彻底阐明了生产与基准的延迟差异。*

---

## 5. 缓存与容灾机制

1. **增量评测断点缓存 (Evaluation Cache)**：
   - 评测脚本计算 `hash(sample_code_ast + model_name + prompt_version)`；
   - 评测中途若因断网或偶发崩溃中断，再次启动直接从结果缓存命中，免重复耗时。
2. **Fail-Closed 容灾逻辑闭环**：
   - 当超大模型（如 14B）因宿主机内存不足（OOM）超时宕机时，协同系统的 25 个纯净样本毫秒级安全放行，而 25 个良性硬负样本与 50 个恶意样本因缺乏 LLM 仲裁被门禁兜底全量阻断。
   - 保留 75.0% 的安全保底准确率与 100% 阻断底线，生动展示生产高可用架构价值。
