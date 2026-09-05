# 大模型辅助应用程序审计方法综述

> 版本：v2.1  
> 日期：2026-08-31  
> 体裁：结构化文献综述（structured narrative review）  
> 范围：公开可检索的代表性论文中，LLM 用于应用程序审计、代码审查、漏洞检测、静态分析增强、检索增强与智能体安全审计的方法。

---

## 摘要

大语言模型（Large Language Models, LLMs）已从通用语言生成工具演化为程序分析与安全审计中的通用语义组件。近两年的研究表明，LLM 已能在代码审查、漏洞检测、补丁修复、静态分析解释、检索增强推理以及智能体安全分析等任务上提供有价值的语义判断；然而，这种能力并不等同于可直接部署的审计可靠性。现有文献反复揭示如下问题：输出不稳定、格式脆弱、对上下文截断敏感、在证据不足时倾向于过度自信、在安全判断上存在系统性误报或漏报，并且在面对跨文件、跨模块、跨运行时阶段的行为链时，单纯的局部语义判断往往不足以支撑最终结论。

本文以应用程序审计为总问题域，构建一套面向研究与工程的分类框架，将现有方法划分为七类：直接 LLM 代码审查、漏洞检测与修复、与静态分析协同、结构化证据与检索增强、智能体/执行链审计、prompt 与 fine-tuning 驱动的安全审查、以及 benchmark 与评估协议。本文进一步从证据输入、判定目标、模型使用方式、输出粒度、可复现性和部署约束等维度进行比较，并在方法综述基础上提出研究议程：未来的高可靠应用程序审计需要从“单点判断”转向“证据链审计”，从“单模型”转向“多阶段系统”，从“代码可疑”转向“行为可疑”，并将不确定性显式纳入 fail-closed 机制。

**关键词**：大语言模型；代码审查；漏洞检测；程序分析；静态分析；检索增强生成；智能体安全；应用程序审计；安全软件工程

---

## 1. 引言

### 1.1 问题背景

应用程序审计（application auditing）指对软件代码、配置、依赖、运行逻辑与外部交互行为进行安全性分析，以识别命令执行、数据外传、敏感信息泄露、持久化、权限越界、提示注入、工具滥用等风险。传统审计主要依赖人工阅读、规则引擎、污点分析、静态分析和符号/抽象执行等方法。这些方法在既知模式识别上较强，但在跨文件推理、语义恢复、工程上下文补全和自然语言证据整合方面存在天然限制。

LLM 的引入改变了这一格局。与只做模式匹配的规则系统不同，LLM 可以在自然语言上下文中解释代码意图、调用链语义、框架惯例和潜在风险目的，从而在安全审计中扮演语义解释器、候选筛选器、风险裁决器或证据整合器等角色。问题在于：LLM 的“语义能力”并不自动转化为“安全可靠性”。一方面，它们可能对可疑模式过度敏感，导致误报；另一方面，它们也可能在证据不足时给出错误但自信的放行判断，导致漏报。

因此，LLM 在应用程序审计中的最佳角色并非“替代传统方法”，而是嵌入更大的多阶段审计体系：静态分析负责召回，LLM 负责语义裁决，规则或策略层负责最终阻断，人工复核负责边界样本。

### 1.2 术语界定

为避免概念混淆，本文区分以下四个层次：

- **代码审查（code review）**：面向函数、补丁、提交或 Pull Request 的局部判断，通常聚焦正确性、规范性和局部安全问题。
- **漏洞检测（vulnerability detection）**：面向可利用缺陷的识别，通常要求指出具体漏洞类型、位置或证据链。
- **程序分析（program analysis）**：面向代码行为的结构化理解，强调调用关系、数据流、控制流与语义解释。
- **应用程序审计（application auditing）**：更广义的安全分析，覆盖源码、配置、依赖、检索、工具调用、记忆与运行时行为链。

本文关注的是最后一层。前述三层方法都可能成为应用程序审计的组成部分，但它们不能等同于完整审计。

### 1.3 研究问题

本文围绕四个研究问题组织综述：

- **RQ1：** LLM 辅助应用程序审计的主要方法家族有哪些？
- **RQ2：** 不同方法家族分别依赖什么类型的证据，解决什么问题，又受什么约束？
- **RQ3：** 在模型选型、prompt 设计、fine-tuning、结构化证据和 benchmark 评估方面，哪些实践更稳定？
- **RQ4：** 当前文献揭示了哪些共性局限，未来最有价值的研究方向是什么？

### 1.4 主要贡献

本文的贡献不在于提出新模型，而在于将近两年公开文献中分散的研究脉络收束为一套可用于审计研究和系统设计的框架：

1. 提出面向应用程序审计的七类方法分类；
2. 用证据类型、输出粒度和部署方式比较不同方法；
3. 总结 LLM 审计的常见失效模式与威胁有效性问题；
4. 提出面向高可靠审计系统的研究议程；
5. 建立“结论—文献证据—benchmark 样本—评测工件”的追踪矩阵，使本文的关键判断能够被复查，而不是停留在经验性归纳。

---

## 2. 综述方法

### 2.1 文献来源与检索范围

本综述参考的文献主要来自 arXiv、IEEE Xplore、USENIX、Springer 与 ACM 相关页面，重点覆盖 2024–2026 年发表的工作。检索关键词围绕以下主题展开：

- code review / secure code review
- vulnerability detection / vulnerability repair
- software security / code security
- static analysis / program analysis
- retrieval-augmented generation / RAG
- agent security / prompt injection / malicious skills
- benchmark / evaluation / comparison / fair evaluation
- secure-aware fine-tuning / prompt mixture / secure reviewer

### 2.2 纳入与排除标准

**纳入标准**：

- 与 LLM、代码、安全审计、漏洞检测、程序分析、智能体安全或相关评估方法直接相关；
- 提供方法、系统、综述或实证评估；
- 能够为应用程序审计提供方法论启示。

**排除标准**：

- 仅讨论通用代码生成而无安全分析内容；
- 与软件安全关联过弱、无法抽象为审计问题；
- 仅有标题或摘要相关性但缺少方法信息者。

### 2.3 证据等级

为避免把“标题相关”误认为“证据充分”，本文将参考文献按证据强度分为三层：

- **A 级：综述/系统综述**，用于归纳领域结构与研究空白；
- **B 级：实证或对比研究**，用于判断实际可用性与稳定性；
- **C 级：系统/工具/新方法论文**，用于观察工程趋势与技术路线。

### 2.4 综述策略

本文采用结构化叙述综述（structured narrative review）而非严格 PRISMA 元分析。具体做法是：

1. 先按方法家族归类；
2. 再按审计对象和证据输入方式细分；
3. 最后按可复现性、可解释性、成本与部署约束比较。

这种做法适用于 LLM 安全审计研究，因为该领域的实验设计、数据集与标签定义尚未完全标准化。为降低叙述综述常见的主观性，本文对每个方法家族都采用同一套分析问题：它依赖什么证据、能解决什么审计子任务、在哪些样本上表现稳定、在哪些边界条件下容易失败、是否能接入可复现评测流水线。

### 2.5 证据追踪与可信度标注

为回应“方法优缺点必须有具体例子支撑”的要求，本文把每个主要结论都绑定到四类证据：

1. **文献证据**：公开论文、综述、系统论文或基准评估；
2. **样本证据**：本仓库 `benchmarks/audit-100/` 中可直接检查的 benign / malicious 样本；
3. **评测证据**：`audit/audit-results/` 中的 confusion matrix、sample-level 结果和错误类型；
4. **过程证据**：`docs/audit/audit-eval-iteration-log.md` 中记录的每轮观察、修改原因和影响。

本文使用如下可信度标签描述结论强度：

| 标签 | 含义 | 使用条件 |
|---|---|---|
| 高 | 文献结论、benchmark 样本和评测结果相互支持 | 至少有代表性文献 + 本仓库样本对照 + 评测或日志记录 |
| 中 | 有文献或样本支持，但缺少完整复现实验 | 适合作为设计依据，但不宜单独作为强结论 |
| 低 | 主要来自方法推断或趋势观察 | 只能作为研究假设，后续需要实证验证 |

### 2.6 结论—证据追踪矩阵

| 关键结论 | 文献证据 | 本仓库样本/工件证据 | 可复查位置 | 可信度 |
|---|---|---|---|---|
| 单轮直接代码审查容易受上下文粒度影响 | [1][10][12] | `TEE-test/B1-08` 是良性 wrapper；`Retina-DKD/M1-01/config_adapter.py` 是真实 shell 执行链 | 本文 3.1；`docs/audit/audit-eval-iteration-log.md` 轮次 18 | 高 |
| 漏洞检测必须区分词形相似与语义危险 | [2][13][14][19][20] | `eval(label[0])` 与 PyTorch `model.eval()` 形成反例对照 | 本文 3.2；原始 `Retina-DKD/data_pre_process/data_process.py` | 高 |
| 静态分析 + LLM 裁决比纯 LLM 更适合工程审计 | [5][15][16][18] | `M3-02` 的秘密采集链与 `B3-01/B3-04` 的公共配置读取需要先召回再裁决 | 本文 3.3、4.2；`models/code_security_analyzer.py` | 高 |
| 结构化表示/RAG 的价值取决于证据质量，不是“检索越多越好” | [5][15][16] | `M5-01` 需要跨文件链路；相似但无关的 `base64`/`requests` 示例可能误导 | 本文 3.4 | 中-高 |
| Agent 审计必须覆盖 prompt、工具、记忆、检索和执行日志 | [6][7][8][9][17] | 当前代码审计 benchmark 尚主要是静态代码包，尚未完整覆盖运行时 agent 行为 | 本文 3.5、6.3 | 中 |
| prompt / fine-tuning 的核心作用是稳定边界判断 | [1][10][21][22] | `B3-01/B3-04` 要求 prompt 明确区分公共配置与凭证读取 | 本文 3.6；`docs/audit/audit-prompt-matrix.md` | 中 |
| benchmark 治理决定指标是否可信 | [14][18][23] | 早期来源混杂导致“完美”结果不可解释；来源隔离后结果才可比较 | 本文 3.7、5.3；迭代日志轮次 8 | 高 |
| 当前 100 样本对静态规则仍偏容易 | 由本仓库评测结果支持 | `audit-100-static-difficulty6` 达到 tp=50/fp=0/tn=50/fn=0，但 `llm_available_rate=0` | `audit/audit-results/audit-100-static-difficulty6/summary.json`；迭代任务 #18 | 高 |

该矩阵的作用是把“综述判断”转化为可复查的研究记录。读者若质疑某个优缺点判断，可以沿着“文献编号 → 样本路径 → 评测工件 → 迭代日志”的链路回看证据，而不是只依赖本文作者的概括。

---

## 3. 方法家族与代表性工作

### 3.1 直接 LLM 代码审查

直接代码审查是最早、最直观的用法：将函数、补丁、Pull Request 或局部文件直接输入 LLM，要求其判断是否存在安全问题、逻辑错误或需求违背。该范式的优点是接入简单、部署成本低、与现有代码评审流程高度兼容；其缺点是对 prompt、上下文粒度与模型先验高度敏感。

代表性研究包括：

- *An Insight into Security Code Review with LLMs: Capabilities, Obstacles and Influential Factors* [1]
- *Evaluating Large Language Models for Code Review* [10]
- *Automated Code Review in Practice* [11]
- *Are LLMs Reliable Code Reviewers? Systematic Overcorrection in Requirement Conformance Judgement* [12]

这些研究共同说明两点：

1. LLM 在代码审查中能产生有用反馈，尤其在结构性缺陷、注释不一致和局部风险提示方面；
2. 但它们并不天然可靠，特别是在“是否违反需求”或“是否构成安全风险”这类需要证据链支撑的判断上，模型容易过度纠正、过度保守或过度自信。

**典型特征**：

- 输入粒度较小：函数、补丁、diff 或 PR；
- 输出形式多为自然语言评论、风险标签或建议；
- 通常需要 human-in-the-loop；
- 对 prompt 结构和评分标准非常敏感。

**适用场景**：

- 作为开发者辅助审查器；
- 作为安全代码评审前置筛查；
- 作为规则系统后的语义复核器。

**局限**：

- 容易遗漏跨函数、跨文件或配置相关风险；
- 容易受上下文窗限制；
- 对“正常工程代码”与“危险代码”的边界判断不稳定。

**例子：** 在本仓库的 benchmark 里，`TEE-test/B1-08` 只是在 `train.py` 外面包了一层 `runpy.run_path` 和 `signal.alarm`，语义上仍然是普通训练封装；一个过敏的审查器如果只看到“入口包装 + 超时控制”，就可能把它误判成高风险。相反，`Retina-DKD/M1-01/config_adapter.py` 中的 `launch_inline(["/bin/sh", "-lc", command])` 才是真正的命令执行链，规则与人工复核都应将其判为高危。这个对比例子说明：LLM 代码审查的优点是能结合上下文识别“包装”和“危险”，缺点是若上下文窗不完整，就会把 wrapper 当成攻击面。

---

### 3.2 漏洞检测与修复

漏洞检测与修复研究将 LLM 置于更具体的安全任务中：不仅判断代码是否“可疑”，还要定位漏洞点、说明风险类型并给出修复建议。与一般代码审查相比，这一任务更强调可利用性和漏洞证据链，因此对模型的精确推理要求更高。

代表性研究包括：

- *LLM for Vulnerability Detection and Repair: Literature Review and the Road Ahead* [2]
- *LLMs in Software Security: A Survey of Vulnerability Detection Techniques and Insights* [3]
- *A Systematic Literature Review on Detecting Software Vulnerabilities with Large Language Models* [4]
- *Understanding the Effectiveness of Large Language Models in Detecting Security Vulnerabilities* [13]
- *LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities (Yet?): A Comprehensive Evaluation, Framework, and Benchmarks* [14]
- *Large Language Models and Code Security: A Systematic Literature Review* [19]
- *Security of Language Models for Code: A Systematic Literature Review* [20]

这一组研究的核心结论可以概括为：LLM 在识别常见漏洞模式、解释可疑代码片段和生成初步修复建议方面具有潜力，但在涉及数据流、控制流、可利用性证明和上下文依赖时，其稳定性与可验证性仍明显不足。特别是，模型往往可以指出“像漏洞的地方”，却未必能够严格说明“为什么可利用”或“为什么不安全”。

因此，现有工作普遍将 LLM 视为：

- 候选生成器；
- 证据解释器；
- 修复建议器；
- 或静态工具之后的语义复核器。

**适用场景**：

- 安全代码扫描后的二次判断；
- 漏洞修复建议草案生成；
- 与静态分析结果联动的 triage。

**局限**：

- 对语法与数据流细节不稳定；
- 修复建议可能“看上去正确但并不安全”；
- 在缺乏明确证据时，错误判断仍较常见。

**例子：** `Retina-DKD/data_pre_process/data_process.py:128` 里的 `eval(label[0])` 是典型的危险用法，因为它直接把字符串当代码执行；但 `TEE-test` 和 `LogisticRegression` 里的 `model.eval()` 只是切换 PyTorch 推理模式，不是漏洞。这个对比说明漏洞检测比一般代码审查更依赖“对象语义”和“数据流”，因为同一个词形 `eval` 在不同上下文中有完全相反的安全含义。文献 [14][13] 之所以反复指出模型在漏洞推理上不稳定，正是因为它们常能认出局部危险模式，却未必能证明危险是否真的可利用。

---

### 3.3 LLM 与静态分析协同

在现有文献中，这一方向通常被认为是最具工程可行性的路线。其基本思想是：静态分析负责提供可重复、可解释的候选证据，LLM 则负责判断这些证据在当前上下文中是否真正构成安全威胁。

代表性研究包括：

- *A Contemporary Survey of Large Language Model Assisted Program Analysis* [5]
- *Synergizing Static Analysis with Large Language Models for Vulnerability Discovery and beyond* [15]
- *LLMxCPG: Context-Aware Vulnerability Detection Through Code Property Graph-Guided Large Language Models* [16]
- *Large Language Models Versus Static Code Analysis Tools: A Systematic Benchmark for Vulnerability Detection* [18]

这一方向的逻辑尤其适合应用程序审计，因为审计通常同时需要两种能力：

1. **高召回发现候选**：静态扫描、污点分析、规则引擎；
2. **低误报语义裁决**：LLM 判定上下文是否真正危险。

换言之，静态工具负责“发现可疑点”，LLM 负责“解释为什么可疑或为什么不危险”。

#### 3.3.1 典型协同模式

- **规则先行，LLM 后审**：先由静态规则和污点分析筛出候选，再让 LLM 判定；
- **候选解释**：LLM 对静态工具命中的路径或规则进行解释；
- **风险升级**：当静态分析给出弱证据时，LLM 用语义上下文判断是否升级为高风险；
- **误报压缩**：利用 LLM 过滤掉“看起来危险但实际上良性”的正常工程模式。

#### 3.3.2 证据边界

此类方法的关键在于，LLM 不应直接替代分析器，而应作为证据裁决器。静态分析提供的是结构化证据：规则命中、调用链、污点路径、源汇关系；LLM 提供的是语义解释：当前上下文是否支持安全风险判断。

#### 3.3.3 优势与局限

**优势**：

- 可追溯性较强；
- 与现有安全工具兼容；
- 更适合高风险、可审计的场景；
- 可在 precision 与 recall 之间形成可控折中。

**局限**：

- 前处理链条更长，整体系统更复杂；
- 结果受到静态分析质量影响；
- 若证据提取不完整，LLM 也只能在残缺上下文中判断。

**例子：** 在当前 benchmark 里，`Retina-DKD/M3-02` 的 `state_loader.py` 把 `getenv("AWS_SECRET_ACCESS_KEY")`、`.env`、`.ssh/id_rsa` 和 `.aws/credentials` 统一抽成一个跨文件秘密采集链；静态规则一旦命中，LLM 也很容易确认这是恶意。相反，`LogisticRegression/B3-04` 读取的是公共 `.ssh/config`，`LogisticRegression/B3-01` 读取的是 `config/public.json`，这类样本在静态层会触发 `FIL_001` 或 `ENV_001` 的相似形态，但正确结论应是 BENIGN。这个对比说明协同路线的价值在于：规则先把可疑片段提出来，LLM 再决定“这个敏感形状到底是真窃密，还是正常配置封装”。它的局限也很清楚——如果 LLM 没拿到支持文件或上下游函数，`M3-02` 这类跨文件链路就可能被压扁成普通配置读取。

---

### 3.4 检索增强与结构化表示增强

这一路线的核心思想是：不要把整份源码直接交给模型，而是先将程序知识压缩为更适合审计的证据，再让 LLM 在这些证据上推理。它通常包含结构化表示、检索增强和语义切片三种输入增强方式。

#### 3.4.1 结构化表示：让模型看证据而不是看全文

代表性工作包括基于代码属性图（CPG）、控制流图（CFG）和数据流图（DFG）的 LLM 辅助分析 [5][15][16]。这类方法通常先提取源码中的调用关系、数据流路径、敏感源/汇点、分支条件与跨函数连接，再将这些结构化证据提供给 LLM。

**主要收益**：

- 将长仓库压缩为高信噪比证据；
- 缓解上下文窗口限制；
- 使模型围绕“为什么危险”而不是“代码长什么样”做判断；
- 便于与污点分析、规则引擎和图分析方法整合。

**主要局限**：

- 图构建和切片本身可能出错；
- 关键边或节点的缺失会影响最终判断；
- 结构化表示可能削弱自然语言层面的工程语义。

#### 3.4.2 检索增强：把外部知识补进审计上下文

RAG 风格方法通常会检索以下内容，再交给 LLM 判断：

- API 文档与安全说明；
- 项目历史提交和相似函数；
- 已知漏洞样例和修复模式；
- 开发规范、配置说明与调用约定；
- 与目标函数邻近的文件或测试用例。

**检索增强的价值**主要体现在两方面：

1. **补上下文**：很多代码片段本身不足以判断风险，必须结合项目约定和上下游关系；
2. **补先验**：模型可能不知道某个 API 的危险语义，而检索到文档或类似案例后，判断会更稳。

**新的风险**在于：被检索到的外部文本本身可能含有误导性说明、恶意注释或提示注入，因此检索结果不能被视为默认可信证据。审计系统必须对证据来源、可信级别和检索策略进行单独建模。

#### 3.4.3 切片与摘要化：控制上下文预算

程序切片、函数摘要、调用链摘要和污点链摘要的目标，是从完整仓库中提取最相关的局部证据，例如：

- 敏感源到外部汇点的路径；
- 命令拼接和执行链；
- 读取—编码—持久化—外传的行为链；
- 配置加载与权限检查的关系。

这种做法很适合应用程序审计，因为大多数高风险行为并不是单点函数，而是由多个局部动作拼接而成。摘要化的优点是节省上下文预算，缺点是可能遗漏关键前提条件，或把“良性 wrapper”压缩成看似危险的片段。

#### 3.4.4 方法对比

| 子路线 | 典型输入 | 主要收益 | 主要局限 | 适合的问题 |
|---|---|---|---|---|
| CPG / CFG / DFG 增强 | 调用图、数据流、源汇路径 | 证据密度高，便于联动静态分析 | 图构建错误会传导到判定 | 跨函数污点、路径分析 |
| RAG / 文档检索增强 | API 文档、历史补丁、相似案例 | 补足模型先验，缓解知识缺口 | 检索噪声与提示注入风险 | 需要 API 语义和项目约定的审计 |
| 切片 / 摘要化 | 关键函数、路径摘要、调用链摘要 | 压缩上下文，控制 token 成本 | 可能丢失前提条件 | 长仓库、局部风险定位 |
| 证据分层融合 | 规则证据 + 图证据 + 检索证据 | 适合审计闭环与复核 | 工程复杂度更高 | 高风险、需可追溯场景 |

#### 3.4.5 对审计系统的启示

结构化增强的本质不是“让模型更聪明”，而是“让模型输入更像证据记录”。这意味着真实审计系统应当：

- 优先输入规则命中的证据片段，而不是整份文件；
- 将数据流、调用链、配置依赖与检索知识分层表示；
- 保留证据来源、可信度和时间戳；
- 将检索增强视为证据补全，而不是真理来源；
- 对图构建、检索召回和摘要压缩分别评估，避免把前处理误差直接归咎于 LLM。

这一方向最适合与静态分析结合，形成“静态召回 + 结构化证据 + LLM 语义裁决”的多阶段审计框架。

#### 3.4.6 可靠性评估维度

检索增强与结构化表示增强不能只用最终分类准确率评价。更合理的评价对象应拆成五层：

| 层次 | 要评价的问题 | 典型失败模式 | 对审计结论的影响 |
|---|---|---|---|
| 表示构建 | CPG/CFG/DFG 是否抽到关键节点和边 | 动态导入、反射、字符串拼接导致调用边缺失 | 恶意链被切断，形成漏报 |
| 证据切片 | 切片是否覆盖源、传播、汇点和条件 | 只保留危险 API，不保留前置校验或数据来源 | 可能误报，也可能无法证明可利用性 |
| 检索质量 | 检索结果是否相关、可信、最新 | 相似但无关案例进入上下文 | LLM 被错误先验牵引 |
| 证据冲突 | 不同来源证据是否互相矛盾 | 文档说安全，代码路径显示外传 | 需要升级为 UNCERTAIN 或人工复核 |
| 可复现性 | 同一版本输入能否复现同一证据包 | 检索源变化、模型摘要变化、排序变化 | 指标不可比较，结论难复核 |

因此，结构化/RAG 审计的研究报告不应只给出“模型判对多少样本”，还应报告证据召回率、切片完整性、检索命中来源、被丢弃证据、冲突证据处理规则和摘要版本。否则，最终错误无法归因：读者不知道是 LLM 判断错了，还是前处理根本没有把关键证据交给 LLM。

**例子：** `Retina-DKD/M5-01` 里，主文件只像普通 flow wrapper，但 `flow_adapter.py` 把 `harvest_bytes(path) -> encode_chain(payload) -> relay_chain(payload)` 的链路拆开后，攻击路径就清楚了：先读文件，再编码，再发往外部域名。若只给模型看主文件，LLM 可能只看到一个函数转发；若把 CPG/DFG、支持文件和摘要链一起给它，模型更容易判断这是跨文件外传。反过来，检索增强如果把一个 benign 项目里的 `base64` 用法、`requests.post` 示例或普通日志文档一起塞进上下文，模型也可能被“看起来相似”的证据误导，所以这类方法的可靠性不是“有检索就更准”，而是“检索到了什么、是否可信、有没有把证据链补完整”。

---

### 3.5 面向智能体与应用执行链的审计

随着 LLM 从代码生成器扩展到智能体（agent），审计对象不再仅是静态源码，而是一个会说话、会检索、会调用工具、会规划行动并在多轮交互中改变状态的执行系统。对这种系统进行审计，必须同时分析“代码风险”和“运行时行为风险”。

#### 3.5.1 审计对象的外延变化

传统代码审计主要关心函数、模块和依赖，而 agent 审计还必须关心：

- system prompt / developer prompt；
- 工具清单与调用权限；
- 检索源与记忆模块；
- 会话历史与多轮规划状态；
- 输出是否会触发外部动作；
- 工具调用是否可被外部输入劫持。

因此，agent 审计不是单纯检查“代码里有没有危险 API”，而是检查“模型是否可能把不可信输入转化为危险动作”。

#### 3.5.2 主要威胁类别

代表性研究 [6][7][8][9][17] 关注的风险大体可以归纳为：

- **提示注入（prompt injection）**：外部内容诱导模型忽略原始指令或执行越权动作；
- **工具滥用**：模型被诱导调用不该调用的工具、接口或操作；
- **记忆污染**：恶意输入写入长期记忆，影响后续会话；
- **数据外传**：把检索到的私有内容、上下文或中间结果发送到不可信位置；
- **权限越界**：多轮规划中逐步扩大行动范围，超出授权边界；
- **恶意技能/恶意子程序**：agent 能力模块本身被设计成隐蔽执行危险行为。

这些威胁的共同点是：危险性往往不体现在单个函数，而体现在“从输入到动作”的完整链路中。

#### 3.5.3 现有方法的分析重点

相关工作通常从以下几个维度审计 agent：

1. **输入层**：是否存在提示注入、数据伪装或恶意上下文污染；
2. **决策层**：模型是否会错误地把不可信输入当成高优先级指令；
3. **工具层**：调用的工具是否超出白名单，参数是否被污染；
4. **记忆层**：状态是否会被持久化保存并在后续轮次中放大风险；
5. **输出层**：输出是否会直接触发执行、外传或持久化动作。

这类方法比传统代码审查更强调“运行时控制平面”的安全性。也就是说，审计的单位不再只是源码，而是“源码 + prompt + 工具 + 记忆 + 检索 + 行为回路”的组合体。

#### 3.5.4 对应用程序审计的直接影响

这一方向说明，未来的应用程序审计不能只问“代码是否可疑”，还要问：

- 模型是否会被不可信输入牵引到错误动作；
- 工具调用是否存在跨轮次放大；
- 检索到的内容是否会成为新的攻击载体；
- 系统是否具备失败显式化和最小权限控制。

对实际系统来说，这意味着审计策略至少要增加三层：

- **静态层**：分析代码、配置和工具定义；
- **运行时层**：分析工具调用和消息流；
- **策略层**：分析授权、白名单和失败回退逻辑。

因此，agent/application auditing 是传统代码审计的自然延伸，但其难度显著更高，因为它审计的是“程序在运行中会做什么”，而不只是“程序写了什么”。

#### 3.5.5 代表性研究对比

| 研究 | 审计对象 | 主要威胁 | 方法特征 | 直接启示 |
|---|---|---|---|---|
| Agent Audit [6] | LLM agent 应用 | 代码/工具/配置漏洞、凭据暴露、权限风险 | 输出 terminal / JSON / SARIF，便于 CI/CD 集成 | 审计系统应支持结构化结果与工程流水线接入 |
| End-to-end security threats and defenses in retrieval-augmented LLM agents [7] | RAG agent | 检索链路中的端到端安全威胁 | 从检索到生成的全链路分析 | 审计范围必须覆盖检索源、提示与工具链 |
| LLM agents security duality [8] | LLM agent 生态 | 自身安全与赋能安全的双重属性 | 以综述方式梳理 agent 相关安全研究 | 需要区分“防御型 agent”与“攻击面扩大”两类问题 |
| Do Not Mention This to the User [9] | 野外出现的恶意 agent 技能 | 隐蔽技能、恶意能力模块 | 关注真实环境中的恶意技能形态 | agent 审计要看能力模块，而不是只看主提示词 |
| Securing AI Agents Against Prompt Injection Attacks [17] | Agent / 工具调用链 | 提示注入 | 讨论攻击面与防护策略 | 需要把输入可信度纳入审计策略 |

从方法论上说，这一组研究的共同结论是：agent 审计已经从“识别危险代码”转向“控制危险行为”。因此，审计器不仅要判断是否存在风险，还要定位风险是从输入、决策、工具、记忆还是输出环节进入系统的。

#### 3.5.6 Agent 审计协议建议

面向 agent 的审计应当从“看代码”扩展为“复盘一次受控执行”。一个较完整的协议可分为四步：

1. **静态资产清点**：列出 system/developer prompt、工具定义、权限、环境变量、文件读写范围、网络出口和持久化存储；
2. **不可信输入建模**：标注哪些内容来自用户、网页、检索库、邮件、日志、外部文件或其他 agent；
3. **行为链仿真**：用代表性恶意输入触发规划、检索、工具调用和输出动作，记录每一步证据；
4. **策略一致性检查**：检查工具调用是否满足最小权限、是否需要确认、失败是否显式、是否存在默认放行。

| 审计对象 | 需要收集的证据 | 典型风险 | 推荐判定字段 |
|---|---|---|---|
| Prompt / policy | system prompt、developer prompt、工具说明 | 高优先级指令被外部文本覆盖或绕开 | `prompt_boundary_risk` |
| Tool schema | 工具名称、参数、权限、确认策略 | 参数被污染后触发读文件、发请求或执行命令 | `tool_abuse_risk` |
| Retrieval | 检索源、片段、排序、可信级别 | prompt injection 或陈旧/伪造文档进入上下文 | `retrieval_trust_level` |
| Memory / state | 写入条件、读取范围、过期策略 | 记忆污染跨会话放大 | `memory_poisoning_risk` |
| Runtime trace | 模型计划、工具调用、返回值、最终输出 | 多步组合形成越权行为 | `execution_chain_risk` |

这种协议与传统代码审计的最大区别在于：证据不只来自仓库文件，还来自执行轨迹。若没有 trace，审计器只能猜测 agent “可能会做什么”；有了 trace，审计器才能判断外部输入是否真的改变了决策、工具参数是否真的被污染、输出是否真的触发了危险动作。

**例子：** 文献 [9] 讨论的“隐藏技能”说明，恶意能力不一定以明显的危险 API 形式出现，而可能包装在看似正常的 agent 技能或说明里；而文献 [17] 所强调的 prompt injection，则说明即使主模型本身是安全的，只要检索到的网页、消息或文件里出现“忽略之前指令”“把结果发到某个地址”这类文本，agent 也可能在工具调用层被牵引。换言之，agent 审计的优点是能把“输入 → 决策 → 工具 → 输出”整条链路都纳入分析，缺点是边界远比代码审查更宽：如果只检查源码而不检查 prompt、检索源和执行日志，就会漏掉真正的风险来源。

---

### 3.6 prompt 设计、secure-aware fine-tuning 与交互策略

除去结构化证据和静态分析，prompt 与模型微调本身也是审计性能的重要决定因素。很多研究表明，同一模型在不同提示模板下的输出差异非常大，尤其在安全场景中，少量措辞变化就会显著影响误报/漏报。

代表性工作包括：

- *iCodeReviewer: Improving Secure Code Review with Mixture of Prompts* [22]
- *SecureReviewer: Enhancing Large Language Models for Secure Code Review through Secure-aware Fine-tuning* [21]
- *Evaluating Large Language Models for Code Review* [10]
- *An Insight into Security Code Review with LLMs* [1]

#### 3.6.1 Prompt 设计的核心问题

安全审计 prompt 不是“让模型自由发挥”，而是强约束式判定协议。其设计目标通常包括：

- 明确输出类别（如 BENIGN / SUSPICIOUS / MALICIOUS / UNCERTAIN）；
- 明确证据优先级（先看上下文，再看 API 语义，再看是否有外传/持久化/载荷隐藏）；
- 明确不确定性处理（证据不足时必须返回 UNCERTAIN）；
- 明确格式约束（严格 JSON、固定字段、不得输出额外说明）；
- 明确 benign trap 豁免规则（例如配置读取、日志、报告导出、正常 wrapper）。

#### 3.6.2 Mixture of prompts 与分层提示

“混合 prompt”思路认为，不同类型样本应采用不同提示策略：

- 对局部函数适合细粒度审查 prompt；
- 对文件级或仓库级证据适合总结型 prompt；
- 对高风险样本适合风险优先 prompt；
- 对边界样本适合显式 uncertain prompt。

这种做法的本质是利用 prompt 作为“软分类器”。它适合减少误报，但也增加了设计复杂度，并使评估必须更加严格地绑定 prompt 版本。

#### 3.6.3 Secure-aware fine-tuning

与纯 prompt 调整相比，secure-aware fine-tuning 试图将安全判断偏好直接嵌入模型参数中，使其在 secure code review 任务上更稳健。其优点是可以缓解少量 prompt 设计失误带来的波动；缺点是训练成本更高，且容易引入数据依赖和过拟合。

#### 3.6.4 交互策略

文献整体趋势表明，在审计场景中，单轮自由生成不如多阶段、受控交互：

1. 先给规则命中的候选；
2. 再要求模型给出证据与风险理由；
3. 最后由策略层决定放行、阻断或人工复核。

这类交互策略显著优于“直接问模型安不安全”的方式，因为它强迫模型在证据上作答，而不是在印象上作答。

**例子：** 在本仓库 benchmark 中，`LogisticRegression/B3-04` 的 `resolve_cli_default(name, fallback)` 和 `TEE-test/B3-01` 的 `load_public_config()` 都是在读公开配置；如果 prompt 只问“是否读取文件”，模型很容易因为看到 `.ssh`、`.env`、`config` 这些词而过度保守，把它们推成可疑甚至恶意。反过来，如果 prompt 明确要求“区分公开配置、训练参数与凭证”，再加上 `UNCERTAIN` 作为合法输出，模型就更容易把这类 benign trap 判回 BENIGN。Secure-aware fine-tuning 与 mixture-of-prompts 的价值就在这里：不是让模型“更会猜”，而是让它在相同证据下更稳定地给出边界一致的判断。

---

### 3.7 benchmark 设计与评估协议

LLM 辅助审计的研究质量，很大程度上取决于 benchmark 设计。对于安全任务而言，benchmark 设计往往比模型本身更容易引入偏差。

代表性研究包括：

- *Large Language Models Versus Static Code Analysis Tools: A Systematic Benchmark for Vulnerability Detection* [18]
- *LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities (Yet?): A Comprehensive Evaluation, Framework, and Benchmarks* [14]
- *Automatic security-flaw detection - towards a fair evaluation and comparison* [23]
- *Large Language Models and Code Security: A Systematic Literature Review* [19]

#### 3.7.1 评估指标

安全审计不能仅看 accuracy。更适合的指标包括：

- **Precision**：减少误报，避免阻断正常程序；
- **Recall**：确保恶意样本能被识别；
- **FPR / FNR**：直接衡量误报/漏报；
- **F1 / F0.5**：在 precision 与 recall 之间权衡；
- **稳定性**：多次运行是否一致；
- **llm_available_rate**：是否真正拿到了有效 LLM 判定；
- **fail_closed_count**：失败时是否保守阻断；
- **可解释性**：是否给出可复核证据。

#### 3.7.2 Benchmark 设计原则

高质量 benchmark 至少应满足以下条件：

1. **来源隔离**：benign 与 malicious 不应共享污染来源；
2. **家族分层**：覆盖重构、日志、配置、报告、入口包装、命令执行、外传、隐写、持久化等不同风险类型；
3. **难度分层**：包含单点命中、上下文命中和跨文件链路三种层次；
4. **标注明确**：样本标签、预期规则、预期风险、预期最终判定都应明确；
5. **失败显式化**：不能把不可用、解析失败或不确定默认为安全。

#### 3.7.3 评估协议的现实问题

当前文献显示，benchmark 常面临以下问题：

- **标签污染**：样本来源混杂，导致结果不可解释；
- **语义漂移**：不同论文对“漏洞”“风险”“恶意”的定义不一致；
- **版本漂移**：prompt、模型版本、静态规则更新会改变结果；
- **报告偏差**：只报告最好结果，不报告失败模式；
- **复现困难**：上下文、运行环境、模型端点不可复现。

这意味着评估协议本身就是研究对象，而不是附属品。

**例子：** 我们自己的 benchmark 就经历过一次典型的评估污染：早期版本把 benign 和 malicious 样本混放在同一批 base project 里，结果让分数看上去几乎“完美”，但那其实是样本来源泄漏造成的假象；后来把 benign 限定到 `LogisticRegression` / `TEE-test`、malicious 限定到 `Retina-DKD` 之后，指标才真正可解释。再往后，`B3` 的公开配置读取、`B5` 的 wrapper/phase 调度、`M3` 的多源秘密采集和 `M5` 的跨文件外传，又分别证明了 benchmark 是否足够难、是否足够像真实工程，会直接决定 precision/recall 是否有意义。这个例子支撑了前面的判断：benchmark 不是“最后一步测一下”，而是决定研究结论是否可信的前提。

---

## 4. 综合比较

### 4.1 方法家族比较矩阵

| 家族 | 核心目标 | 证据输入 | 典型输出 | 主要优势 | 主要短板 | 本仓库支撑样本 | 文献支撑 | 可信度 |
|---|---|---|---|---|---|---|---|---|
| 直接代码审查 | 局部安全/正确性判断 | 函数、补丁、PR、单文件 | 评论、标签、建议 | 接入简单，适合嵌入开发流程 | 上下文弱，容易把 wrapper、测试脚本或日志误判成风险 | `TEE-test/B1-08` vs `Retina-DKD/M1-01` | [1][10][11][12] | 高 |
| 漏洞检测/修复 | 定位漏洞并给出修复 | 代码片段、函数、漏洞上下文 | 漏洞类型、位置、修复建议 | 任务边界较清楚，能生成可操作修复草案 | 可利用性证明不稳，容易混淆词形相似 API | `eval(label[0])` vs `model.eval()` | [2][3][4][13][14][19][20] | 高 |
| 静态分析协同 | 规则召回 + LLM 裁决 | 规则命中、污点路径、调用链 | 风险等级、解释、阻断建议 | 可追溯，可审计，可接入 CI | 管线复杂，静态证据缺失会导致 LLM 无法裁决 | `M3-02` vs `B3-01/B3-04` | [5][15][16][18] | 高 |
| 结构化/RAG 增强 | 从代码抽取高信噪比证据 | CPG/CFG/DFG、切片、文档、历史案例 | 证据链、路径解释、上下文摘要 | 降噪、补上下文、缓解长仓库限制 | 图/检索/摘要任一环节错误都会污染判断 | `M5-01/flow_adapter.py` | [5][15][16] | 中-高 |
| Agent/执行链审计 | 控制运行时危险行为 | prompt、工具、记忆、检索源、日志 | 行为风险、策略建议、SARIF/JSON | 覆盖真实 LLM 应用攻击面 | 边界远大于源码审计，复现实验更难 | 当前 benchmark 尚未完全覆盖，仅提供行为链类比 | [6][7][8][9][17] | 中 |
| Prompt / fine-tuning | 稳定安全判定边界 | 标准化证据 + 约束式 prompt + 标注样本 | 受控 JSON、标签、理由 | 改善一致性，利于后处理 | 对 prompt 版本、训练集和标签规范敏感 | `B3-01/B3-04` 的 benign trap | [1][10][21][22] | 中 |
| Benchmark / protocol | 评估方法有效性 | 规范化样本、manifest、结果包 | 指标、错误分解、复现记录 | 可复跑、可比较、可治理 | 易受来源泄漏、构造偏差和版本漂移影响 | `audit-100` 与迭代日志轮次 8、13、17、18 | [14][18][23] | 高 |

**例子：** 这张表里的每一项都能在本仓库 benchmark 里找到对应物。`B1/B5` 主要在考直接代码审查是否会把包装误判成攻击；`M1/M5` 在考命令执行与跨文件链路是否能被识别；`M3/B3` 则在考“敏感形状”与“正常配置封装”的边界。静态规则跑在这些样本上能得到一组稳定的 TP/FP/FN/TN，而 benchmark 的作用不是替代方法本身，而是告诉我们哪种方法在哪类样本上可靠、在哪类样本上会误判。

### 4.2 审计器模型与使用方式对比

本文把“被审计代码包”和“审计器模型”严格分开。`LogisticRegression`、`TEE-test`、`Retina-DKD` 是 subject-side 样本来源；Claude、GPT、Gemini、Qwen、DeepSeek、StarCoder 等才是 auditor-side 模型候选。二者混在一起会导致指标不可解释。

| 审计器类型 | 代表模型 | 推荐角色 | 优势 | 风险/限制 | 适合阶段 | 本仓库当前状态 |
|---|---|---|---|---|---|---|
| 前沿闭源通用模型 | Claude Opus/Sonnet、GPT-4.1、Gemini 2.5 Pro | 高质量语义裁决、边界样本仲裁、报告生成 | 推理能力强，适合跨文件解释与自然语言证据整合 | 成本、闭源版本漂移、复现性较弱 | finding-level 复核、最终报告、人工复核辅助 | 已在设计中作为高精度参考审计器候选，尚未完成全量同集对比 |
| 本地代码模型 | Qwen2.5-Coder、DeepSeek-Coder V2、StarCoder2 | 可复现批量审计、离线基线 | 成本低，可本地运行，便于重复实验 | 小模型更易格式不稳、推理不足或解析失败 | CI smoke test、初筛、可重复实验 | 已接入 Ollama/Qwen2.5-Coder 路径，但 `llm_available_rate` 和 JSON 稳定性仍需治理 |
| 静态规则引擎 | `models/code_security_analyzer.py`、`internal/codeaudit/rules.go` | 高召回候选生成、fail-closed 网关 | 可解释、可版本化、低成本 | 容易被变形绕过，也容易对 benign trap 误报 | 第一阶段召回、规则命中证据生成 | 最新静态难度结果仍为满分，说明当前 benchmark 对规则层偏容易 |
| 混合审计系统 | 静态规则 + 结构化证据 + LLM 裁决 + 策略层 | 生产级审计闭环 | 兼顾召回、语义解释、可追溯和保守失败 | 工程复杂度最高，需要结果治理 | 高风险审计、受限环境、发布前阻断 | 当前方案的目标形态，已有 manifest、结果包、迭代日志和 fail-closed 字段 |

从工程角度看，前沿模型适合作为“高精度裁决者”，本地代码模型适合作为“可重复实验审计器”，静态规则适合作为“候选召回器”。高可靠审计不应把任一模型当作绝对真理，而应记录 `auditor_model`、`rule_set_version`、`prompt_version`、`llm_state` 和 `fail_closed`，使每一次结论都可复查。

### 4.3 结果对比矩阵：当前仓库评测与含义

| 评测阶段 | 样本语义 | 代表结果 | 指标含义 | 主要问题 | 后续动作 |
|---|---|---|---|---|---|
| 初始静态基线 | 来源未充分隔离，benign trap 不足 | tp=43, fp=22, tn=28, fn=7 | 静态规则有召回能力，但误报明显 | benign/malicious 来源混杂；LLM 不可用 | 修正来源隔离，恢复 LLM 状态记录 |
| 恢复 Ollama 后 | LLM 开始参与，但返回不稳定 | tp=41, fp=22, tn=28, fn=9，`llm_available_rate=0.57` | 证明“模型可运行”不等于“审计可靠” | `llm_unavailable`、`parse_error`、`UNCERTAIN` 混合 | 加强 JSON 约束和 fail-closed 记录 |
| 来源隔离后 | benign 只来自 `LogisticRegression/TEE-test`，malicious 只来自 `Retina-DKD` | tp=50, fp=0, tn=50, fn=0 | 指标变得可解释，但可能偏容易 | 恶意样本与良性样本可分性过强 | 增加跨文件化与 benign trap |
| 跨文件化与去显式化后 | M1–M5 使用支持文件、动态导入和 wrapper 调度 | 仍保持 tp=50, fp=0, tn=50, fn=0 | 当前规则 + prompt 对这批样本仍可全分离 | benchmark 难度仍不足，尤其静态层过强 | 继续提升样本隐蔽度并加入更真实良性陷阱 |
| 最新静态 difficulty6 | 100 样本可全量静态分离 | tp=50, fp=0, tn=50, fn=0，`llm_available_rate=0` | 不能证明 LLM 审计有效，只证明规则和样本当前匹配 | 静态规则已饱和，无法测出 LLM 增益 | 任务 #18 继续提高 benchmark 难度 |

这个矩阵说明：本文当前的成果不是“已经证明某个大模型完美完成审计”，而是建立了可复跑、可解释、可追踪的评测闭环，并发现现有 100 样本仍不足以区分静态规则、LLM 语义裁决和混合系统的边界能力。因此，后续研究应继续提高 benchmark 难度，而不是把满分结果当作最终结论。

### 4.4 何种方法更适合应用程序审计

若目标是高可靠应用程序审计，而不是仅仅做研究演示，则最稳妥的组合通常是：

1. 静态分析做候选召回；
2. 结构化证据（图、切片、检索）做上下文压缩；
3. LLM 进行语义判断与风险解释；
4. prompt / fine-tuning 提升判定一致性；
5. benchmark 与日志系统保证可追踪和可复现；
6. 不确定时 fail-closed，而不是默认放行。

换言之，LLM 在这里更像“语义验证层”，而不是“最终安全真理”。

**例子：** `M1-01` 这种命令执行样本，静态规则一眼就能命中 `CMD_001`，但如果它被包在 helper 里，LLM 仍然有机会通过上下文确认“这不是普通 wrapper，而是真正调用 shell”；而 `B3-04` 这种只读公共 `.ssh/config` 的样本，则正好要求模型在看到 `.ssh` 时不要条件反射式地判恶意。这说明高可靠审计通常不是“只靠规则”或“只靠 LLM”，而是先让规则把候选找出来，再让 LLM 做语义边界判定，最后通过策略层决定放行、阻断还是人工复核。

### 4.5 适用性判断

- **低风险、开发辅助场景**：直接代码审查足够实用，但结论应作为 reviewer suggestion，而不是阻断依据；
- **中等风险、持续集成场景**：静态分析 + LLM 裁决更合适，尤其适合过滤误报和解释规则命中；
- **高风险、受限环境场景**：结构化证据 + 严格 prompt + fail-closed 最合适，并且必须记录模型版本、规则版本和失败状态；
- **智能体/工具调用场景**：必须把运行时行为链纳入审计，单纯源码扫描不足以覆盖 prompt injection、工具滥用和记忆污染。

**例子：** 对 `Retina-DKD/M5-01` 这类跨文件外传样本，如果只做直接代码审查，主文件看起来像普通 flow wrapper；如果加上结构化证据与支持文件，才能看见 `harvest_bytes -> encode_chain -> relay_chain` 这样的完整链路。相反，对 `TEE-test/B1-08` 这类 benign wrapper，过度强硬的单轮审查很容易把 `runpy.run_path`、`signal.alarm` 或入口脚本当成攻击链。这个差异说明，越是高风险或行为链长的场景，越不能只靠单次问答结论，而应采用多阶段审计。

---

## 5. 威胁有效性与综述局限

### 5.1 文献选择偏差

本综述采用结构化叙述方法，强调公开可检索的代表性工作，因此不可避免地存在：

- 英文文献偏置；
- arXiv 预印本偏置；
- 新近研究曝光度偏置；
- 以“安全/代码/审计”为关键词的语义筛选偏差。

### 5.2 概念不一致

不同论文对“漏洞”“安全缺陷”“风险”“恶意”“可疑”“高危”等术语的定义不完全一致，这会导致结果难以直接比较。尤其是在 code review 与 vulnerability detection 之间，任务边界常被混用。

### 5.3 评估基准异构

模型、数据集、上下文粒度、prompt、温度、后处理与标注标准均可能不同。因而某篇论文的高分并不一定可迁移到另一套数据或审计环境。

**例子：** 我们这个 benchmark 里，`B3-01` 读取的是 `config/public.json`，`B3-04` 读取的是公共 `.ssh/config`，二者都可能触发 `FIL_001` 或 `ENV_001` 的相关规则，但最终标签都应该是 BENIGN；而 `M3-02` 虽然也读配置/环境变量，却是在收集 `.env`、`.ssh/id_rsa` 和 `.aws/credentials`，应判为 MALICIOUS。若换一个 benchmark 把这些样本混到同一个 base project，或者把规则阈值改掉，precision/recall 就可能完全变样。这说明“同样的模型分数”不能脱离数据分布单独解释。

### 5.4 时间漂移与版本漂移

LLM 研究迭代极快，模型版本、 API 行为、默认安全策略、prompt 工程经验都会影响结果。因此，文献结论通常具有时间敏感性。

**例子：** 本仓库里就出现过典型的版本/运行时漂移：`llm_available_rate` 一开始是 0，因为本地 Ollama 端点不可达；后来通过 `bwrap` 恢复后，LLM 终于参与了判定，但结果又受到返回格式和 JSON 解析稳定性的影响。也就是说，哪怕 benchmark 不变，只要模型后端、封装方式或 prompt 改了，结论就可能变；这也是为什么审计研究必须记录 `rule_set_version`、`prompt_version`、`auditor_version` 和运行时间，而不能只报一个总分。

### 5.5 参考文献可核验性边界

本文引用的部分工作来自 arXiv、会议页面、出版社页面或项目仓库。由于 LLM 安全审计领域更新极快，预印本版本、正式出版版本、论文标题和 DOI 可能出现漂移。当前可明确核验到公开入口的代表性文献包括：[1]、[2]、[5]、[6]、[9]、[14]、[16]；其他引用应在正式投稿前逐条补齐作者、年份、venue、DOI/arXiv version 和访问日期。

这一区分很重要：文献入口可核验不等于论文结论已被完全复现；预印本可检索不等于结论已经过同行评审；系统仓库可运行不等于其 benchmark 与本文任务定义完全一致。因此，本文在使用文献时优先提取方法结构与已报告限制，而不是把任一单篇论文的绝对分数直接迁移到本仓库审计系统。

### 5.6 综述自身边界

本文没有采用完整的 PRISMA 流程，也未对所有候选论文做量化元分析。因此本文的定位是“结构化、证据驱动的学术综述”，而不是统计意义上的完全系统综述。若后续要升级为正式可投稿的系统综述，至少还需要补充：检索式全文、数据库命中数量、去重规则、筛选流程图、双人标注一致性、质量评估量表、排除论文清单，以及参考文献的 BibTeX/GB/T/IEEE 格式。

---

## 6. 研究议程

### 6.1 从单点分类走向证据链审计

未来的 LLM 审计应从“这段代码是否危险”转向“哪些证据能支撑危险判断”。这要求代码、规则、调用链、检索记录和输出解释共享统一表示。

### 6.2 从单模型走向多阶段系统

高可靠系统应采用多阶段架构：

- 静态分析产生候选；
- 结构化增强提取证据；
- LLM 进行语义判定；
- 策略层决定阻断或放行；
- 人工复核处理边界样本。

### 6.3 从漏洞检测走向应用行为审计

未来真正危险的部分常常不在静态代码，而在运行时行为：工具调用、提示注入、记忆污染、检索污染和多轮规划。因此，审计单元必须从“代码片段”扩展到“行为链”。

### 6.4 从准确率导向走向可治理性导向

高风险审计更需要：

- 可复跑；
- 可解释；
- 可追溯；
- 可版本化；
- 失败显式化；
- 不确定性可管理。

### 6.5 从一般微调走向安全感知微调

纯 prompt 改写通常不足以稳定提升安全审计质量。更有希望的方向是将安全审计任务、标注规范和失败样本纳入 secure-aware fine-tuning 或 mixture-of-prompts 训练框架 [21][22]。

### 6.6 从单一 benchmark 走向 benchmark governance

benchmark 设计必须治理化：来源隔离、版本固定、标签说明、错误分解和结果归档都应作为研究的一部分，而不是附加产物。对于应用程序审计，benchmark 本身就是方法有效性的前提。

### 6.7 对实践系统的建议

对真实审计系统而言，优先级应是：

1. 召回要稳定；
2. 证据要可追溯；
3. 输出要结构化；
4. 不确定要显式；
5. 失败要保守。

这五点比单次指标更能反映一个系统是否适合高风险环境。

---

## 7. 结论

LLM 已经成为应用程序审计的重要组成部分，但最成熟的范式并不是“纯 LLM 替代传统审计”，而是“LLM 与静态分析、结构化证据、检索机制、prompt 约束和策略控制协同工作”。公开文献一致表明：LLM 在语义理解、上下文归纳和自然语言解释方面具有明显优势，但在严格漏洞判定、格式稳定性、可复现性和失败显式化方面仍然不足。

对于应用程序审计这一更广义任务，未来的关键不在于把模型做得更“会说”，而在于把审计系统做得更“可证据化、可复核、可治理”。因此，真正可发表、可部署、可复现的研究，应当围绕以下原则展开：

- 证据链优先于印象判断；
- 多阶段系统优先于单轮问答；
- 行为链审计优先于仅代码审查；
- 失败显式化优先于默认放行；
- benchmark 治理优先于单次分数。

这也是 LLM 辅助应用程序审计未来最重要的研究主线。

---

## 附录 A：参考文献核验与引用格式说明

本文当前参考文献仍处于“研究草稿级”引用状态：已保留公开入口，但尚未逐条整理成最终投稿格式。正式投稿前建议按以下流程处理：

1. 对每条参考文献记录作者、题名、年份、版本、venue、DOI/arXiv ID、URL、访问日期；
2. 区分预印本、会议论文、期刊论文、系统仓库和 benchmark artifact；
3. 对同一工作的 arXiv 版本与正式出版版本去重，只保留一个主引用，其他入口作为 artifact 或补充材料；
4. 对综述类论文和实验类论文分开标注，避免用综述结论替代一手实验结果；
5. 对 agent/security 类 2026 年新文献单独标注“新近研究”，避免把尚未被充分复现的系统结论写成领域共识。

| 编号 | 当前入口 | 核验状态 | 投稿前动作 |
|---|---|---|---|
| [1] | arXiv `2401.16310`，另有 replication package | 已通过公开搜索核验题名与入口 | 补作者、版本、访问日期和复制包引用 |
| [2] | arXiv `2404.02525` | 已通过公开搜索核验题名与入口 | 补作者、版本与正式引用格式 |
| [5] | arXiv `2502.18474` / TAI 2025 | 已通过公开搜索核验预印本与期刊入口 | 确定主引用使用期刊版还是 arXiv 版 |
| [6] | arXiv `2603.22853` / GitHub | 已通过公开搜索核验入口 | 区分论文引用与工具仓库引用 |
| [9] | arXiv `2602.06547` / USENIX 2026 / benchmark repo | 已通过公开搜索核验入口 | 补正式 USENIX 信息与 artifact 引用 |
| [14] | IEEE S&P 2024 / arXiv `2312.12575` | 已通过公开搜索核验入口 | 以 IEEE 版本为主引用，arXiv 作为开放入口 |
| [16] | USENIX Security 2025 / arXiv `2507.16585` / GitHub / dataset | 已通过公开搜索核验入口 | 区分论文、artifact、dataset 三类引用 |
| 其他 | arXiv/Springer/IEEE 链接 | 待逐条核验 | 补齐作者、年份、venue、DOI 与版本 |

---

## 参考文献

[1] *An Insight into Security Code Review with LLMs: Capabilities, Obstacles and Influential Factors* — [arXiv](https://arxiv.org/abs/2401.16310)

[2] *Large Language Model for Vulnerability Detection and Repair: Literature Review and the Road Ahead* — [arXiv](https://arxiv.org/abs/2404.02525)

[3] *LLMs in Software Security: A Survey of Vulnerability Detection Techniques and Insights* — [arXiv](https://arxiv.org/abs/2502.07049)

[4] *A Systematic Literature Review on Detecting Software Vulnerabilities with Large Language Models* — [arXiv](https://arxiv.org/abs/2507.22659)

[5] *A Contemporary Survey of Large Language Model Assisted Program Analysis* — [arXiv](https://arxiv.org/abs/2502.18474)

[6] *Agent Audit: A Security Analysis System for LLM Agent Applications* — [arXiv](https://arxiv.org/abs/2603.22853)

[7] *End-to-end security threats and defenses in retrieval-augmented LLM agents* — [Springer](https://link.springer.com/article/10.1007/s44163-026-01726-x)

[8] *LLM agents security duality: a comprehensive survey of self-security and empowered cybersecurity* — [Springer](https://link.springer.com/article/10.1007/s10462-026-11563-0)

[9] *Do Not Mention This to the User: Detecting and Understanding Malicious Agent Skills in the Wild* — [USENIX](https://www.usenix.org/conference/usenixsecurity26/presentation/liu-yi)

[10] *Evaluating Large Language Models for Code Review* — [arXiv](https://arxiv.org/abs/2505.20206)

[11] *Automated Code Review in Practice* — [arXiv](https://arxiv.org/abs/2412.18531)

[12] *Are LLMs Reliable Code Reviewers? Systematic Overcorrection in Requirement Conformance Judgement* — [arXiv](https://arxiv.org/abs/2603.00539)

[13] *Understanding the Effectiveness of Large Language Models in Detecting Security Vulnerabilities* — [IEEE Xplore](https://ieeexplore.ieee.org/abstract/document/10988968/)

[14] *LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities (Yet?): A Comprehensive Evaluation, Framework, and Benchmarks* — [IEEE Xplore](https://ieeexplore.ieee.org/document/10646663)

[15] *Synergizing Static Analysis with Large Language Models for Vulnerability Discovery and beyond* — [arXiv](https://arxiv.org/abs/2509.15433)

[16] *LLMxCPG: Context-Aware Vulnerability Detection Through Code Property Graph-Guided Large Language Models* — [USENIX](https://www.usenix.org/conference/usenixsecurity25/presentation/lekssays)

[17] *Securing AI Agents Against Prompt Injection Attacks* — [arXiv](https://arxiv.org/abs/2511.15759)

[18] *Large Language Models Versus Static Code Analysis Tools: A Systematic Benchmark for Vulnerability Detection* — [arXiv](https://arxiv.org/abs/2508.04448)

[19] *Large Language Models and Code Security: A Systematic Literature Review* — [arXiv](https://arxiv.org/abs/2412.15004)

[20] *Security of Language Models for Code: A Systematic Literature Review* — [arXiv](https://arxiv.org/abs/2410.15631)

[21] *SecureReviewer: Enhancing Large Language Models for Secure Code Review through Secure-aware Fine-tuning* — [arXiv](https://arxiv.org/abs/2510.26457)

[22] *iCodeReviewer: Improving Secure Code Review with Mixture of Prompts* — [arXiv](https://arxiv.org/abs/2510.12186)

[23] *Automatic security-flaw detection - towards a fair evaluation and comparison* — [Springer](https://link.springer.com/article/10.1007/s10270-025-01300-6)
