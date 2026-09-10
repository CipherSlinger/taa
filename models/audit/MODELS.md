# 支持的 Qwen 审计大模型清单

本文档列出本地离线模型库（`models/audit/ollama-qwen`）已打包就绪的 Qwen 模型名称与配置模板，方便在配置文件、环境变量及部署脚本中快速复制粘贴使用。

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
    "dir": "/root/taa/ollama-qwen"
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
    "dir": "/root/taa/ollama-qwen"
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
    "dir": "/root/taa/ollama-qwen"
  }
```

---

### 2.2 部署脚本指定模型命令

使用 `deploy.sh` 进行增量部署或同步指定模型到容器/远程节点：

```bash
# 部署 1.5b 模型
./deploy.sh --model qwen2.5-coder:1.5b

# 部署 0.5b 模型
./deploy.sh --model qwen2.5-coder:0.5b

# 部署 8b 模型
./deploy.sh --model qwen3:8b

# 部署 3b 模型
./deploy.sh --model qwen2.5-coder:3b

# 部署 7b 模型
./deploy.sh --model qwen2.5-coder:7b

# 部署 14b 模型
./deploy.sh --model qwen3:14b
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
docker exec taa-env-slim-v2 /root/taa/ollama-qwen/ollama list
```
