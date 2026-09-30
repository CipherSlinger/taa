# 规则族语义基准与标签重建方案设计（预登记）

- 文档状态：已冻结（预登记）
- 关联规范：`.claude/specs/2026-09-16-audit-benchmark-design.md` §4.1（13 族「判定对象与匹配模式」及「预期良性豁免」）
- 关联判据：`.claude/specs/2026-09-22-semgrep-engine-noninferiority-evidence-design.md`（非劣效主基准）
- 关联实施计划：`.claude/plans/abundant-exploring-hennessy.md`（阶段 H3）
- 预登记冻结 SHA256 (`SCOPE_SHA256`)：`f3b691803b5d299ff17e99f11689fc0f58813def812a73490cf941287afa165b`

---

## 1. 目标与范畴校正

在阶段 H2 留出集非劣效性评测中，基准评测产生了 `ΔFPR = +1/154`（容差为 0，判定不通过）。根因剖析表明：语料中样本的标签并非依据我方规则族语义产生，而是机械继承上游单点规则测试预期（如 `sr-0155` 与 `sr-0156` 代码形态完全一致，上游标记因鉴权语义不同而分化），或按数据集归属（如 PyPI 均为良性、DataDog 均为恶意）贴标。

这导致 Tier 1 检测器（AST/正则语法模式匹配）被强行要求回答属于「Tier 1 语法匹配 + Tier 2 LLM 意图裁决」的联合问题。
本设计的目标是**校正该范畴错误**：将标签标准对齐至「代码是否包含我方 13 个规则族在规范中明确定义的语法/调用构造且不符合良性豁免」。

---

## 2. 标签定义与判据

### 2.1 判定准则

对任意样本源码 $S$：
- **`malicious`**（在范围内，应报告）：源码中存在至少一个语法调用或文本构造命中我方 13 个规则族的「判定对象与匹配模式」，且**不落入**该族预登记的「预期良性豁免」场景。
- **`benign`**（良性/范围外，不应报告）：源码中未包含任何规则族判定构造，或命中的构造全部属于书面列明的良性豁免情形。

### 2.2 同义反复防线（独立 Oracle）

为了防止比较退化为同义反复（若用待评测引擎自身打标，该引擎天然得分为满分）：
1. 标签**绝不**来自 `RegexScannerAdapter`、`SemgrepScannerAdapter` 或任一引擎的扫描输出；
2. 标签由独立的 Python AST 静态语法分析器（`models/audit/tools/family_scope.py`）产生；
3. Oracle 自行构建文件级 import 别名映射与调用解析，不引用任何被测引擎代码（单测 `tests/test_family_scope.py` 强制保证无引擎模块导入）。

---

## 3. 口径裁定与 13 族规格（D1–D13）

用户裁定采纳**宽口径（最大合理读法）**，同时设置**敏感性带（Sensitivity Band）**。

### 3.1 D1–D13 裁决明细

| 编号 | 规则族 | 判定对象与口径裁定（宽口径 primary） | 预期良性豁免（BENIGN） | 严格变体（strict）差异 | 宽容变体（permissive）差异 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **D1** | NET_001 | `requests.*`, `urllib.request.*`, `httpx.*`, `aiohttp.*` 等网络请求。解析 import 别名（如 `from requests import get; get(u)` 计入） | 仅限内网健康检查 `127.0.0.1:port/health` 或 `localhost:port/health` | 不解析 import，仅认字面带点全称 | 允许任意匹配 `requests.`/`urllib.` 的调用 |
| **D2** | NET_002 | `socket.socket`, `socket.create_connection`, `connect`, `send`, `recv` 等底层套接字通信 | 无豁免（直接阻断） | 仅认 `socket.create_connection` 与字面 `socket.socket` | 任意 `socket.*` 构造均计入 |
| **D3** | CMD_001 | `os.system`, `subprocess(shell=True)`, `subprocess` 执行系统二进制命令（如 `ping`, `curl`, `bash` 等），动态取法 `getattr(os, "system")`，`os.spawn*`, `pty.spawn`, `paramiko` | 严格参数化的 GPU/硬件诊断如 `nvidia-smi`（无 `shell=True`） | 仅认标准 `os.system`, `os.popen`, `subprocess` 显式 `shell=True` | 任意 `subprocess.*` 均计入 |
| **D4** | OBF_001 | `base64` 编解码（`b64decode`/`b64encode` 等），`pickle.load`/`loads`，反序列化包括 `_pickle`/`cPickle`，`zlib` 解压缩 | 纯内存特征提取与合法缩略图本地缓存 | 仅认标准 `pickle.loads` 字面，不含 `_pickle` | 任意 `base64.*` 均计入 |
| **D5** | DYN_001 | `eval`, `exec`, 动态 `__import__`, `importlib.import_module` | 基于白名单受控动态分发组件 | 仅认字面 `eval`/`exec` | 包含所有动态导入形式 |
| **D6** | FIL_001 | `open(...)`, `Path(...)` 访问敏感路径（如 `/etc/passwd`, `~/.ssh`, `id_rsa`, `.aws/credentials` 等） | 读取本地公用算法超参数 `params.json` | 仅严格敏感文件名命中 | 任意读取绝对敏感目录 |
| **D7** | ENV_001 | 读取高危环境变量（`AWS_SECRET`, `API_KEY`, `TOKEN`, `PASSWORD` 等） | 读取 `DATA_DIR`、`EPOCHS`、`MODEL_PATH` 等合法训练变量 | 仅认标准大写高危密钥 | 宽泛密钥关键词匹配 |
| **D8** | PER_001 | 字符串字面量中包含持久化路径（`/etc/crontab`, `/etc/systemd`, `/etc/rc.local` 等）或命令 | 无合规场景（直接阻断） | 仅标准全路径匹配 | 包含命令型持久化匹配 |
| **D9** | EXF_001 | 作用域复合：同函数/范围内同时存在数据编码（base64/dumps）与网络传输（requests/socket） | 无合规场景（直接阻断） | 仅限单行紧邻协同 | 允许模块范围内的协同 |
| **D10** | EMB_001 | `torch.save`, `np.save`, `numpy.save` 等将未经许可的数据集落盘 | 合法模型权重落盘 `torch.save(model.state_dict(), ...)` | 仅认字面 `torch.save` | 扩展至所有权重导出函数 |
| **D11** | EMB_002 | `shutil.copy`, `copytree`, `os.rename` 将非结构化数据写入输出导出目录 | 复制合规的图表与评估日志至输出目录 | 仅标准 `shutil.copy` | 包含各类文件移动与复制 |
| **D12** | EMB_003 | `print`, `logging` 打印或流式导出数据集内容 | 打印训练 Loss、Step、准确率指标统计 | 仅标准 `print` | 扩展所有标准流写操作 |
| **D13** | EMB_004 | 在模型元数据字典或权重文件中隐蔽附带数据（pickle.dump 携带数据对象） | 正常的模型超参数字典元数据附加 | 仅字面嵌入 | 宽泛元数据检测 |

---

## 4. 敏感性带（Sensitivity Band）与判定门禁

系统在相同样本集上并行计算三套口径的标签：
1. **`primary`（宽口径）**：主判定口径。
2. **`strict`（严格口径）**：仅字面匹配，无别名解析。
3. **`permissive`（宽容口径）**：扩展通配。

### 门禁规则（无利好妥协）

- 最终非劣效性判定结论以 `primary` 为主准则；
- **一致性约束**：在 `strict` 与 `permissive` 变体下，不得出现结论与 `primary` 相反或恶化（即不得出现任何变体下 `ΔFPR > 0` 或 `Δrecall < 0`）；
- 若结论在不同变体间发生翻转，**直接判定为「未确立（Inconclusive）」，坚决不挑选有利变体作为结论**。

---

## 5. 安全与审计约束

1. **零动态执行原则**：样本语料包含真实恶意代码（DataDog 归档），严禁任何 `import`、`eval`、`exec`、`compileall` 或运行包安装钩子；仅使用只读方式读取文件并进行 `ast.parse`。
2. **证据可溯源性**：Oracle 输出包含详细的 `evidence` 列表，包含 `file`, `line`, `family`, `construct`, `detail`, `citation`，确保每条标签判断人类完全可复查。
3. **哈希冻结**：范围定义哈希 `SCOPE_SHA256` 写入代码与规范文档，任何规则修改均会导致哈希变更，防止事后微调评测标准。
