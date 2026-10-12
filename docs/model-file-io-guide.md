# 模型代码文件读写约定

面向模型提供方。本文只回答一个问题：**搬进 TAA 沙箱执行的训练/推理代码，应该从哪里读文件、往哪里写文件，以及写的时候要遵守什么格式。**

按本文改造后的代码，无需调用任何网络接口，也无需引入任何 TAA 专有依赖，在普通环境下同样可以跑。

---

## 1. 目录布局

沙箱内固定提供以下目录，训练代码只与它们打交道：

```text
/opt/taa/input/                 只读输入
├── train/                      训练集
├── val/                        验证集
├── test/                       测试集
├── labels.csv                  标签/标注映射
└── weights/                    预训练底模（若有）

/opt/taa/output/                可写
├── result/                     产物目录 ← 唯一会被带出去的地方
│   ├── weights/                权重 (*.pt / *.onnx ...)
│   ├── training_result.json    必须产出的结果汇总
│   └── test_result.xlsx        评测明细（阶段 2）
├── log/                        终端日志 (*.jsonl / *.log)
└── progress/                   进度文件 (progress.json)

/opt/taa/checkpoint/            可写，断点快照
/opt/taa/models/                你的模型源码（进程工作目录）
```

三条硬性规则：

1. **输入目录只读**：不得在 `/opt/taa/input` 下创建、修改或删除任何文件，包括缓存和临时文件。
2. **产物集中在 `result/`**：`log/` 与 `progress/` 只是旁路通道，写在里面的东西不会被带出；需要交付的文件一律放 `result/`。
3. **路径不要写死也不要写相对路径**：进程的工作目录是模型源码目录，相对路径会落到代码目录而非产物目录。用第 2 节的宏或环境变量取值。

---

## 2. 路径怎么取

TAA 启动你的命令时，会做宏替换并注入环境变量。两种方式取到的都是同一批真实路径。

### 2.1 命令行宏

写在 `runtimeConfig.commands` 里的字符串会被替换：

| 宏 | 替换为 |
| :--- | :--- |
| `<input>` `<INPUT>` `<in>` `<IN>` | 输入数据目录（默认 `/opt/taa/input`） |
| `<output>` `<OUTPUT>` `<out>` `<OUT>` | 产物目录（默认 `/opt/taa/output/result`） |

```json
{
  "commands": ["python train_fusion.py --data-root <input> --output-dir <output> -e 150"],
  "env": { "OMP_NUM_THREADS": "8" }
}
```

环境变量 `env` 的值同样支持宏替换。

### 2.2 环境变量

| 变量 | 含义 |
| :--- | :--- |
| `TAA_TASK_ID` | 本次任务标识 |
| `TAA_STARTED_AT` | 任务启动时间（RFC3339） |
| `TAA_DATA_DIR` / `TAA_INPUT_DIR` / `TAA_MODEL_INPUT_DIR` | 输入数据目录 |
| `TAA_OUTPUT_DIR` / `TAA_MODEL_OUTPUT_DIR` | 产物目录 |
| `TAA_LOG_DIR` | 日志目录（默认 `/opt/taa/output/log`） |
| `TAA_PROGRESS_DIR` | 进度文件位置（默认 `/opt/taa/output/progress/progress.json`） |
| `TAA_CHECKPOINT_DIR` / `TAA_MODEL_CHECKPOINT_DIR` / `CIPHERFLOW_CHECKPOINT_DIR` | 断点目录 |

推荐写法是**读环境变量、缺省回落到默认绝对路径**：

```python
import os
from pathlib import Path

INPUT_DIR  = Path(os.environ.get("TAA_INPUT_DIR",  "/opt/taa/input"))
OUTPUT_DIR = Path(os.environ.get("TAA_OUTPUT_DIR", "/opt/taa/output/result"))
LOG_DIR    = Path(os.environ.get("TAA_LOG_DIR",    "/opt/taa/output/log"))
PROGRESS   = Path(os.environ.get("TAA_PROGRESS_DIR", "/opt/taa/output/progress/progress.json"))
CKPT_DIR   = Path(os.environ.get("TAA_CHECKPOINT_DIR", "/opt/taa/checkpoint"))

TASK_ID    = os.environ.get("TAA_TASK_ID", "local-task")
```

上面这些默认绝对路径即使直接硬编码也能正常工作（例如 `/opt/taa/output/result/xxx` 会被自动换算到实际产物目录）；但环境变量优先，便于本地调试与路径调整。

---

## 3. 写日志

**位置**：`/opt/taa/output/log/`（或 `$TAA_LOG_DIR`）。目录下所有 `*.jsonl` 与 `*.log` 文件都会被读取。

**格式**：每行一个 JSON 对象，追加写入。

```json
{"timestamp": "2026-10-12T07:15:32Z", "message": "[Train] Epoch 3/150 finished - loss: 0.3821"}
```

- 消息字段取 `message`，也接受 `msg`；时间字段取 `timestamp`，也接受 `time`、`ts`。
- 时间戳可选。写了会显示为日志前缀。
- 也接受不含 JSON 的纯文本行。
- 未识别的字段会被忽略，可以按需增加。

**必须遵守**：

1. **每行以换行符结尾。** 没有换行的尾部（包括正在写入的半行）不会被读取，直到换行符落盘为止。
2. **只追加，不覆盖、不回退。** 文件如果变小（被截断重写），会被当作新文件从头读取，导致日志重复。
3. **及时 flush**，否则缓冲在进程内存里的日志看不到。

参考实现：

```python
import json, sys
from datetime import datetime, timezone

class ModelLogger:
    def __init__(self, log_dir, filename="train.log"):
        self.path = Path(log_dir) / filename
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.path, "a", encoding="utf-8")

    def log(self, message: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._file.write(json.dumps({"timestamp": ts, "message": str(message)}, ensure_ascii=False) + "\n")
        self._file.flush()          # 不 flush，日志会滞留在缓冲区
        print(message)              # 同时输出到控制台，便于本地调试

    def close(self) -> None:
        if self._file and not self._file.closed:
            self._file.flush()
            self._file.close()
```

> 每次任务开始前，`log/` 目录会被清空。不要依赖上一次运行留下的文件，每次运行重新创建。

---

## 4. 写进度

**位置**：`/opt/taa/output/progress/progress.json`（或 `$TAA_PROGRESS_DIR` 指向的位置；默认值是一个**文件路径**，不是目录）。

**格式**：

```json
{
  "percent": 34.6525,
  "timestamp": "2026-10-12T07:15:32.123456Z",
  "stage": "train",
  "message": "Epoch 3/150 (Midpoint) [Batch 20/40, 50.0%] - loss: 0.3821, acc: 85.00%",
  "epoch": 3,
  "total_epochs": 150,
  "batch": 20,
  "total_batches": 40,
  "loss": 0.3821,
  "acc": 85.0
}
```

| 字段 | 必填 | 说明 |
| :--- | :--- | :--- |
| `percent` | 是 | 0.0 – 100.0。也接受 `percentage`。越界或非数字会被忽略，进度将停在原处 |
| `timestamp` | 否 | RFC3339 / RFC3339Nano UTC，建议带微秒。缺失或格式非法时使用文件修改时间 |
| `stage` / `message` / `epoch` / `total_epochs` / `batch` / `total_batches` / `loss` / `acc` | 否 | 用于平台展示；其余自定义字段也会被忽略，不会报错 |

**必须遵守**：

1. **原子写入。** 先写同目录下的临时文件，`fsync`，再 `os.replace` 覆盖。直接覆盖写会让读取方读到半截 JSON。
2. **只在有变化时写。** 只有 `(percent, timestamp)` 这一对与上次不同时才会被采用；重复写同样的值没有意义。
3. **建议节流。** 每个 batch 都落盘会拖慢训练；典型策略是距上次写入超过 0.2 秒、或进度变化超过 0.0001% 才写，关键里程碑强制写一次。
4. **建议单调不回退。** 进度回退会让进度条来回跳。

参考实现：

```python
import json, os, time
from datetime import datetime, timezone

class ProgressTracker:
    def __init__(self, progress_path, min_interval_seconds=0.2, min_percent_delta=0.0001):
        self.path = Path(progress_path)
        self.tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.min_interval_seconds = min_interval_seconds
        self.min_percent_delta = min_percent_delta
        self._last_percent = -1.0
        self._last_write_time = 0.0

    def update(self, percent, stage=None, message=None, force=False, **extra) -> bool:
        percent = max(0.0, min(100.0, round(float(percent), 4)))
        if self._last_percent >= 0.0:
            percent = max(percent, self._last_percent)          # 单调不回退
        if not force and self._last_percent >= 0.0:
            elapsed = time.time() - self._last_write_time
            if elapsed < self.min_interval_seconds and abs(percent - self._last_percent) < self.min_percent_delta:
                return False

        payload = {
            "percent": percent,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        }
        if stage:   payload["stage"] = stage
        if message: payload["message"] = message
        payload.update({k: v for k, v in extra.items() if v is not None})

        with open(self.tmp_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(self.tmp_path, self.path)                    # 原子替换

        self._last_percent = percent
        self._last_write_time = time.time()
        return True
```

建议的进度预算（可按任务调整，原则是**初始化与收尾都要覆盖，长循环中间要有细粒度变化**）：

| 区间 | 内容 |
| :--- | :--- |
| 0% – 2% | 参数解析、模型构建、损失/优化器、DataLoader 就绪 |
| 2% – 96% | 按 epoch 均分；epoch 内按 batch 平滑插值；每 epoch 开始、25%、50%、75%、收尾各强制写一次 |
| 96% – 100% | 指标汇总、写 `training_result.json`、完成 |

> 每次任务开始前，进度文件会被删除。若进度长时间不动，平台侧看到的进度条也会停住。

---

## 5. 写结果汇总 `training_result.json`

**位置**：产物目录根部，即 `<output>/training_result.json`。

训练进程以退出码 0 结束后，该文件会被读取并与审计信息、数据校验和合并成最终报告。**只有 `result/` 目录里的产物会被带出**；进程非 0 退出时产物不会被收集。

```json
{
  "training_task": {
    "metrics": {
      "final_accuracy": 0.9425,
      "final_loss": 0.1352,
      "final_auc": 0.9810,
      "final_f1": 0.9380,
      "epochs": [
        {"epoch": 1, "accuracy": 0.6500, "loss": 0.8500},
        {"epoch": 2, "accuracy": 0.8100, "loss": 0.4200},
        {"epoch": 3, "accuracy": 0.9425, "loss": 0.1352}
      ]
    }
  },
  "dataset": {
    "total_samples": 12500,
    "splits": {"train": 10000, "test": 2500}
  }
}
```

- `training_task.metrics` 与 `dataset` 是实际被采集的两块内容，指标键名自定。
- **无需填写** `task_id`、`started_at`、`finished_at`、`duration_seconds`、`status`、`exit_code`、`failure_reason`：这些由运行侧统一填写，你写了也会被覆盖。
- `dataset` 中不要使用 `data_structure` 字段。
- 文件缺失不会导致任务失败，但报告里就没有你的指标。**无论成功失败都应尽量写出该文件。**

```python
import json
from pathlib import Path

result_path = OUTPUT_DIR / "training_result.json"
with open(result_path, "w", encoding="utf-8") as f:
    json.dump(training_result, f, indent=2, ensure_ascii=False)
    f.write("\n")
```

阶段 2（测试）另需在 `result/` 下产出评测明细表（按约定命名 `test_result.xlsx`），文件名与列结构由模型方与平台约定。

---

## 6. 写断点

**位置**：`/opt/taa/checkpoint/`（或 `$TAA_CHECKPOINT_DIR`）。此目录跨任务保留，用于宿主机异常重启后的续训。

约定文件名：

| 文件 | 内容 |
| :--- | :--- |
| `latest.pt` | 最新权重快照 |
| `best.pt` | 最优指标权重快照 |
| `checkpoint_meta.json` | 元数据：`task_id`、`epoch`、`step`、`metrics`、`is_best` |

是否从断点恢复由**你的脚本自行判断**（例如目录非空、文件可加载、epoch 未达上限），建议在脚本入口做一次检测并在日志中说明走的是恢复还是全新训练。

权重同时保存到 `result/weights/` 时，交付产物与断点是两份独立文件，互不影响。

---

## 7. 禁止事项

| 行为 | 后果 |
| :--- | :--- |
| 在 `/opt/taa/input` 下创建、修改、删除文件 | 违反沙箱只读约束 |
| 把输入数据原样拷贝进 `result/`（原始图片、CSV、标注文件） | 导出前的反泄露检查会比对数据特征，命中即**拒绝导出** |
| 在产物中写入明文 PEM 私钥、`SECRET_KEY=` / `API_KEY=` 等环境变量转储 | 同上，命中明文特征即拒绝导出 |
| 任何网络外联（`socket` / `requests` / `urllib` / `httpx` / `aiohttp`） | 代码审计红线，导入阶段即被阻断 |
| 反弹 Shell、提权、危险系统调用 | 同上 |
| 单次产物超过大小上限（默认 3 GB） | 导出被拒绝 |

---

## 8. 上线前检查清单

- [ ] 输入目录只读，代码中没有任何指向 `/opt/taa/input` 的写操作。
- [ ] 所有需要交付的文件都写在产物目录（`<output>` / `TAA_OUTPUT_DIR`）下，没有散落在别处。
- [ ] 路径从环境变量或宏获取，没有硬编码相对路径。
- [ ] 日志写在 `$TAA_LOG_DIR`，每行以换行符结尾，只追加不重写。
- [ ] 进度原子写入 `$TAA_PROGRESS_DIR`，`percent` 在 0–100 之间且单调不回退。
- [ ] 训练结束前写出 `<output>/training_result.json`，包含 `training_task.metrics` 与 `dataset`。
- [ ] 失败路径同样写出 `training_result.json`（或至少保证日志与进度可用），便于定位。
- [ ] 断点写入 `$TAA_CHECKPOINT_DIR`，入口处有恢复检测。
- [ ] 产物中没有原始数据副本、密钥、环境变量转储。
- [ ] 代码中不存在任何网络调用。
