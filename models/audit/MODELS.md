# 支持的 Qwen 审计大模型清单

本文档列出独立子模块 TEE-LLM（`teellm/models/ollama/`）已就绪的离线模型名称、配置模板与管理方式。模型运行时已统一解耦至 `teellm` 模块，并支持基于 `teellm/configs/models.json` 的多模型预设配置与 CLI 管理工具。

---

## 1. 快速复制区 (纯模型名称)

点击或双击即可直接复制模型名：

```text
qwen3:8b
qwen3:14b
qwen2.5-coder:0.5b
qwen2.5-coder:1.5b
qwen2.5-coder:3b
qwen2.5-coder:7b
```

---

## 2. 常见配置片段

### 2.1 `taa-config.json` 配置片段

修改 `/root/taa/taa-config.json`（或项目模板）中的 `llm` 节点：

#### 方案 A: 使用当前默认的 `qwen3:8b` (高推理能力，带边界微调)
```json
  "llm": {
    "enabled": true,
    "endpoint": "http://127.0.0.1:11434",
    "model": "qwen3:8b",
    "policy": "assist",
    "failClosed": true,
    "dir": "/root/taa/ollama"
  }
```

#### 方案 B: 使用极速轻量 `qwen2.5-coder:1.5b` (推荐：CPU 秒级响应)
```json
  "llm": {
    "enabled": true,
    "endpoint": "http://127.0.0.1:11434",
    "model": "qwen2.5-coder:1.5b",
    "policy": "assist",
    "failClosed": true,
    "dir": "/root/taa/ollama"
  }
```

#### 方案 C: 使用超轻量 `qwen2.5-coder:0.5b` (毫秒级响应，低内存占用)
```json
  "llm": {
    "enabled": true,
    "endpoint": "http://127.0.0.1:11434",
    "model": "qwen2.5-coder:0.5b",
    "policy": "assist",
    "failClosed": true,
    "dir": "/root/taa/ollama"
  }
```

---

### 2.2 模型管理与切换 CLI (teellm/deploy.sh)

TEE-LLM 提供了原生的模型管理 CLI 命令：

```bash
# 进入 teellm 目录
cd teellm

# 查看本地就绪模型与配置概览
./deploy.sh models list

# 查看指定模型的完整配置参数与磁盘 Blobs 校验状态
./deploy.sh models info qwen2.5-coder:3b

# 切换活跃模型（自动原子更新 configs/models.json 与服务配置文件）
./deploy.sh models switch qwen2.5-coder:3b

# 启动部署并指定目标模型
./deploy.sh docker start --model qwen2.5-coder:3b
```

---

## 3. 模型规格与推荐场景

| 模型标识 (Model Name) | 参数规模 | 权重体积 | 推荐内存 | 适用场景与特点 |
| :--- | :--- | :--- | :--- | :--- |
| **`qwen2.5-coder:0.5b`** | 0.5B | ~397 MB | ≥ 2 GB | **极低资源/超低延迟**。CPU 推理约 1~2 秒，适合资源受限或大批量单项规则初筛。 |
| **`qwen2.5-coder:1.5b`** | 1.5B | ~986 MB | ≥ 4 GB | **轻量平衡推荐**。体积小（<1GB），代码安全特征理解明显优于 0.5B，CPU 响应仅需 3~5 秒。 |
| **`qwen2.5-coder:3b`** | 3B | ~1.9 GB | ≥ 6 GB | **代码专业级**。针对语法树、AST 敏感逻辑与数据外传特征微调，推理准确性高。 |
| **`qwen2.5-coder:7b`** | 7B | ~4.7 GB | ≥ 8 GB | **高级代码安全审计**。具备更强的长上下文理解力与利用链推理能力。 |
| **`qwen3:8b`** *(当前运行)* | 8B | ~5.2 GB | ≥ 10 GB | **最新综合推理模型**。当前容器内默认运行。逻辑推理最严密，支持多级安全边界判定（已配置 `think: false` 优化响应速度）。 |
| **`qwen3:14b`** | 14B | ~9.0 GB | ≥ 16 GB | **高阶复杂分析**。推理精度更高，适合宿主机资源充足的深度离线审查。 |

---

## 4. 容器内当前装载状态

当前运行容器 `taa-env-slim-v2` 中已预载入以下模型，可直接配置免拉取即时使用：

1. `qwen3:8b` (当前 TAA 关联模型)
2. `qwen2.5-coder:0.5b`
3. `qwen2.5-coder:1.5b`

可通过以下命令在容器内确认或查看：
```bash
docker exec taa-env-slim-v2 /root/taa/ollama/ollama list
```
或在 `teellm` 目录下使用 CLI 工具查看：
```bash
./deploy.sh models list
```
