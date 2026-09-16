# 大模型列表查询脚本 (list_models.py) 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现一个通用自适应的大模型列表查询脚本 `list_models.py`，支持自动探测并打印 BASE_URL 中支持的所有大模型列表，并兼容 Claude Relay、OpenAI、Ollama 等协议。

**Architecture:** 基于 Python 3 标准库，通过自适应候选探测链（Claude Relay `/apiStats/models` -> OpenAI `/v1/models` -> Ollama `/api/tags`）获取后端支持的模型清单，自动提取环境变量回退，提供默认表格、`--raw` 和 `--json` 三种输出模式。

**Tech Stack:** Python 3 (urllib.request, json, argparse, unittest)

---

### Task 1: 编写核心解析与探测逻辑的单元测试

**Files:**
- Create: `tests/test_list_models.py`

- [ ] **Step 1: 编写单元测试用例**
  覆盖：
  - URL 归一化与 root URL 提取（处理末尾斜杠、`/api`、`/v1`）
  - 环境变量与参数优先级解析
  - Claude Relay 响应解析器（解析按分类及 all 列表）
  - OpenAI 响应解析器（解析 `{"data": [{"id": ...}]}`）
  - Ollama 响应解析器（解析 `{"models": [{"name": ...}]}`）

```python
#!/usr/bin/env python3
import unittest
from list_models import (
    normalize_url,
    parse_claude_relay_response,
    parse_openai_response,
    parse_ollama_response,
    resolve_config,
)

class TestListModels(unittest.TestCase):
    def test_normalize_url(self):
        clean, root = normalize_url("https://cc.sususu.cf/api")
        self.assertEqual(clean, "https://cc.sususu.cf/api")
        self.assertEqual(root, "https://cc.sususu.cf")

        clean, root = normalize_url("http://127.0.0.1:11434/")
        self.assertEqual(clean, "http://127.0.0.1:11434")
        self.assertEqual(root, "http://127.0.0.1:11434")

        clean, root = normalize_url("example.com/v1")
        self.assertEqual(clean, "http://example.com/v1")
        self.assertEqual(root, "http://example.com")

    def test_parse_claude_relay_response(self):
        sample = {
            "success": True,
            "data": {
                "claude": [{"value": "claude-opus-4-6", "label": "Claude Opus 4.6"}],
                "gemini": [{"value": "gemini-2.5-pro", "label": "Gemini 2.5 Pro"}],
                "openai": [{"value": "gpt-5", "label": "GPT-5"}],
                "other": [{"value": "qwen", "label": "Qwen"}],
            }
        }
        models = parse_claude_relay_response(sample)
        self.assertEqual(len(models), 4)
        self.assertEqual(models[0]["id"], "claude-opus-4-6")
        self.assertEqual(models[0]["group"], "claude")

    def test_parse_openai_response(self):
        sample = {
            "object": "list",
            "data": [
                {"id": "gpt-4o", "owned_by": "openai"},
                {"id": "deepseek-r1", "owned_by": "deepseek"}
            ]
        }
        models = parse_openai_response(sample)
        self.assertEqual(len(models), 2)
        self.assertEqual(models[0]["id"], "gpt-4o")
        self.assertEqual(models[0]["group"], "openai")

    def test_parse_ollama_response(self):
        sample = {
            "models": [
                {"name": "qwen2.5-coder:3b", "details": {"parameter_size": "3B"}},
                {"name": "llama3.2:latest", "details": {"parameter_size": "3B"}}
            ]
        }
        models = parse_ollama_response(sample)
        self.assertEqual(len(models), 2)
        self.assertEqual(models[0]["id"], "qwen2.5-coder:3b")
        self.assertEqual(models[0]["group"], "ollama")

if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: 运行测试以验证由于尚未实现而失败**

Run: `python3 tests/test_list_models.py`
Expected: FAIL (`ModuleNotFoundError: No module named 'list_models'`)

---

### Task 2: 实现 `list_models.py` 核心功能与 CLI 接口

**Files:**
- Create: `list_models.py`

- [ ] **Step 1: 实现 URL 归一化、各协议响应解析器、自适应请求探测与格式化输出逻辑**
  包括：
  - `normalize_url(raw_url)`
  - `resolve_config(args)`
  - `parse_claude_relay_response(data)`
  - `parse_openai_response(data)`
  - `parse_ollama_response(data)`
  - `fetch_json(url, token, timeout, insecure)`
  - `probe_models(base_url, token, timeout, insecure)`
  - `format_table(models)`
  - `main()` 完整命令行解析（支持 `--url`, `--key`, `--raw`, `--json`, `--timeout`, `--insecure`）

- [ ] **Step 2: 赋予可执行权限**

Run: `chmod +x list_models.py`

- [ ] **Step 3: 运行单元测试验证其全部通过**

Run: `python3 tests/test_list_models.py`
Expected: 4 tests OK, Ran 4 tests in 0.001s, OK

---

### Task 3: 真实环境联调与命令行模式测试

**Files:**
- Target: `list_models.py`

- [ ] **Step 1: 测试默认环境读取（当前 ANTHROPIC_BASE_URL）**

Run: `./list_models.py`
Expected: 输出包含 claude, gemini, openai, other 等各分类大模型，表格对齐整洁，末尾输出总计数量。

- [ ] **Step 2: 测试 `--raw` 模式**

Run: `./list_models.py --raw | head -n 5`
Expected: 仅输出纯模型 ID，每行一个。

- [ ] **Step 3: 测试 `--json` 模式**

Run: `./list_models.py --json | python3 -m json.tool | head -n 15`
Expected: 打印标准 JSON 数组格式。

- [ ] **Step 4: 测试指定外部 URL 与帮助信息**

Run: `./list_models.py --help`
Expected: 打印完整的参数说明与默认环境变量回退规则。

- [ ] **Step 5: 提交代码**

```bash
git add list_models.py tests/test_list_models.py
git commit -m "feat(script): 新增 BASE_URL 大模型列表自动探测与查询脚本"
```
