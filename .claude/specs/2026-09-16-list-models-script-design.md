# 大模型列表查询脚本 (list_models.py) 设计规范

## 1. 背景与目标

在云端和本地大模型生态中，服务提供商与网关（如 OpenAI、Claude Relay Service、vLLM、Ollama、One-API 等）各自暴露不同的模型列表查询端点与数据结构。开发者在排查、配置和调用模型服务时，常需要直观了解某个 `BASE_URL` 当前到底支持和部署了哪些模型。

本项目旨在提供一个通用、自适应、零外部依赖的 Python 3 命令行脚本 `list_models.py`，能够针对用户给定的或环境中已配置的 `BASE_URL` 自动探测后端服务类型，获取全部可用大模型列表并进行规整展示。

## 2. 设计原则与约束

1. **零外部依赖 (Zero External Dependencies)**：仅使用 Python 3 标准库（`sys`, `os`, `json`, `argparse`, `urllib.request`, `urllib.error`, `ssl`），无需 `pip install` 任何第三方库。
2. **多协议智能自适应 (Multi-Protocol Adaptive Probing)**：
   - 优先适配当前开发环境部署的 Claude Relay Service 统计与模型路由端点；
   - 兼容标准 OpenAI 协议（`/v1/models`、`/models`）；
   - 兼容 Ollama 本地/远程服务协议（`/api/tags`）。
3. **环境无感知与平滑回退 (Graceful Fallback)**：
   - 优先使用命令行显式指定的参数；
   - 未指定参数时，自动从系统环境变量降级读取（`BASE_URL` -> `ANTHROPIC_BASE_URL` -> `OPENAI_BASE_URL`；`API_KEY` -> `ANTHROPIC_AUTH_TOKEN` -> `OPENAI_API_KEY`）；
   - 当所有端点无法接通时，提供清晰的诊断信息与可用候选项排查提示。
4. **多样化输出视图 (Flexible Output Formats)**：
   - **默认交互视图**：规整的终端对齐表格，按厂商或类别（Claude / Gemini / OpenAI / Ollama / Other）分组，清晰列出序号、模型 ID、展示名称/标签；
   - **管道纯文本视图 (`--raw`)**：每行仅输出一个模型 ID，便于与 `grep`, `xargs`, `fzf` 等 Shell 命令行工具组合；
   - **JSON 视图 (`--json`)**：输出结构化 JSON，便于程序下游解析与消费。
5. **安全与健壮性 (Robustness & Security)**：
   - 默认超时 10 秒（可通过 `--timeout` 调节），防止网络挂起；
   - 支持忽略 SSL 证书校验错误（针对自签名私有网关场景提供 `--insecure` 选项）；
   - 请求头脱敏，不在非调试模式下打印用户的 Token。

---

## 3. 详细设计

### 3.1 路径与执行权限
- **文件路径**：`list_models.py`（位于项目根目录）
- **Shebang 与权限**：第一行为 `#!/usr/bin/env python3`，赋予 `chmod +x` 可执行权限。

### 3.2 命令行参数规范
| 参数 | 简写 | 环境变量回退 | 说明 | 默认值 |
|---|---|---|---|---|
| `--url` | `-u` | `BASE_URL` -> `ANTHROPIC_BASE_URL` -> `OPENAI_BASE_URL` | 大模型服务端点 BASE_URL | 必选（若环境变量无则报错） |
| `--key` | `-k` | `API_KEY` -> `ANTHROPIC_AUTH_TOKEN` -> `OPENAI_API_KEY` | 接口鉴权 API Key / Token | 可选（部分服务公开免鉴权） |
| `--raw` | `-r` | 无 | 纯文本模式：仅打印模型 ID 列表（每行一个） | `False` |
| `--json` | `-j` | 无 | JSON 模式：打印标准 JSON 数组 | `False` |
| `--timeout` | `-t` | 无 | HTTP 请求超时时间（秒） | `10` |
| `--insecure` | 无 | 无 | 允许跳过 SSL 证书校验 | `False` |

### 3.3 探测与解析流水线 (Probing & Parsing Pipeline)

输入 `BASE_URL` 归一化处理：
1. 若 URL 未包含 `http://` 或 `https://`，自动前缀补齐 `http://`。
2. 剥离末尾的斜杠 `/`，得到 `clean_url`。
3. 计算 `root_url`（如 `clean_url` 包含 `/api` 或 `/v1`，提取其上层协议根目录）。

#### 探测���选端点列表（按探测优先级）：
1. **Claude Relay Service 模型端点**：
   - URL: `{root_url}/apiStats/models`
   - 判定准则: HTTP 200，JSON 返回包含 `{"success": true, "data": ...}`。
   - 数据解析: 遍历 `data.claude`、`data.gemini`、`data.openai`、`data.other` 或 `data.all`，提取 `value`（模型 ID）与 `label`（展示标签）。
2. **标准 OpenAI `/v1/models` 端点**：
   - URL 候选: `{clean_url}/models` 以及 `{clean_url}/v1/models`
   - 判定准则: HTTP 200，JSON 返回包含 `{"data": [...]}` 且子项包含 `"id"`。
   - 数据解析: 提取每个元素中的 `"id"` 与可选的 `"owned_by"`。
3. **Ollama `/api/tags` 端点**：
   - URL 候选: `{clean_url}/api/tags` 以及 `{root_url}/api/tags`
   - 判定准则: HTTP 200，JSON 返回包含 `{"models": [...]}` 且子项包含 `"name"`。
   - 数据解析: 提取每个元素中的 `"name"`，并附带参数规模或大小信息。

### 3.4 异常处理与退出码
- **退出码 0**：成功获取并打印模型列表。
- **退出码 1**：参数错误（未提供 URL 且无环境变量）。
- **退出码 2**：连接异常或鉴权失败（401/403/无法访问），且所有候选探测端点均失败。

---

## 4. 验证策略

1. **环境集成测试**：在宿主环境下直接运行 `./list_models.py`，验证自动读取 `ANTHROPIC_BASE_URL`（`https://cc.sususu.cf/api`）并解析出 35+ 个大模型。
2. **参数覆盖测试**：
   - `./list_models.py --raw`：验证只输出纯 ID 列表。
   - `./list_models.py --json`：验证输出有效的 JSON 数据。
   - `./list_models.py -u http://127.0.0.1:11434`：验证对本地 Ollama 端点的探测兼容性。
3. **异常参数验证**：
   - 传递无效 URL（如 `-u http://127.0.0.1:9999`）验证错误提示与优雅退出。
