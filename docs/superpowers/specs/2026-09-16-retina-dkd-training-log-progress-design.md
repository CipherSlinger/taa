# Retina-DKD 训练日志与进度落盘适配设计

## 1. 背景与目标

在 TAA（可信计算执行代理）执行模型训练任务时，其后台的 `reportWatcher` 监听器会周期性（每 500ms）轮询模型的输出目录：
1. **任务终端日志（Model Terminal Logs）**：扫描 `modelLogDir` 下所有 `.log` 或 `.jsonl` 文件，提取增量日志内容，向平台接口 `/v1/taa/modelLog` 发送日志流。
2. **任务进度（Task Progress）**：扫描 `modelProgressDir` 下最新修改的 `.json` 文件，解析其中的 `percent`（或 `percentage`）数值及时间戳，向平台接口 `/v1/taa/reportProgress` 发送进度更新。

当前 `models/examples/Retina-DKD/Retina-DKD/train_fusion.py` 仅将日志打印到控制台，且未生成进度文件。本项目旨在对 `train_fusion.py` 进行调整，规范化地将终端执行日志与训练进度实时写入适配 TAA 监听器的对应文件路径中。

## 2. 约束与原则

1. **不检测任何环境变量**：根据用户明确要求，路径解析逻辑完全不读取 `os.environ` 中的变量，仅依据命令行参数与 `--output-dir` 进行关联推导或使用默认保底路径。
2. **严格对齐 TAA 读取规范**：文件格式、字段命名与更新逻辑必须与 TAA `internal/controller/model_reporting.go` 的读取逻辑完全一致。
3. **原子更新与即时刷盘**：
   - 进度文件采用“临时文件写入 + 原子重命名”避免 TAA 读到残缺 JSON。
   - 日志文件每行写入后强制 `flush()`，确保行缓冲不滞留。
4. **代码改动范围**：仅修改 `models/examples/Retina-DKD/Retina-DKD` 目录下的代码（主要为 `train_fusion.py`）。

---

## 3. 详细设计

### 3.1 路径解析机制 (Path Resolution)

在 `train_fusion.py` 的参数解析器中新增：
- `--log-dir`: 指定终端日志输出目录（可选）
- `--progress-dir`: 指定进度文件输出目录（可选）

路径推导规则：
- **日志目录 (`resolve_log_dir`)**：
  1. 若命令行显式传入 `--log-dir`，直接使用该路径；
  2. 否则，基于 `--output-dir` 解析：
     - 若 `--output-dir` 为 `.../result`（如 `/opt/taa/output/result`），推导为其父目录同级的 `log`（即 `<output_root>/log`）；
     - 否则取 `--output-dir` 下的 `log` 子目录（即 `<output-dir>/log`）；
  3. 最终默认保底路径：`/opt/taa/output/log`。
- **进度目录 (`resolve_progress_dir`)**：
  1. 若命令行显式传入 `--progress-dir`，直接使用该路径；
  2. 否则，基于 `--output-dir` 解析：
     - 若 `--output-dir` 为 `.../result`，推导为其父目录同级的 `progress`（即 `<output_root>/progress`）；
     - 否则取 `--output-dir` 下的 `progress` 子目录；
  3. 最终默认保底路径：`/opt/taa/output/progress`。

### 3.2 终端日志落盘规范 (Model Log Format)

- **落盘文件路径**：`<log_dir>/train.log`。
- **数据格式**：标准 JSONL 单行格式，每行以 `\n` 结尾：
  ```json
  {"timestamp": "2026-09-16T12:00:00Z", "message": "[Train] Epoch 1/150 - loss: 0.2450, acc: 88.50%"}
  ```
- **TAA 对齐性**：TAA 的 `logMessageFromLine` 解析 `{"message": "..."}` 提取内部纯文本，并自增 `seq` 序号上报管控平台。
- **控制台兼容**：保留控制台原样输出，双写文件并每次执行 `flush()`。

### 3.3 任务进度落盘规范 (Task Progress Format)

- **落盘文件路径**：`<progress_dir>/progress.json`。
- **数据格式**：
  ```json
  {
    "percent": 25.5,
    "timestamp": "2026-09-16T12:00:00.000000Z"
  }
  ```
- **TAA ��齐性**：TAA 的 `readLatestProgress` 扫描 `.json` 文件并解析 `percent` 和 `timestamp`（RFC3339 格式），检查变动后触发上报。
- **并发与原子性**：先写入 `<progress_dir>/progress.json.tmp`，随后通过 `os.replace` 替换到 `progress.json`。由于 `.tmp` 不以 `.json` 结尾，TAA 监听器会完全忽略临时文件，并在替换后瞬间感知最新完整的 JSON。

### 3.4 训练生命周期插桩节点

| 阶段 | 进度百分比 | 触发事件与日志内容 |
| :--- | :---: | :--- |
| **初始化启动** | `0.0%` | 目录与参数准备完毕：`[Init] Starting Retina-DKD training...` |
| **模型就绪** | `2.0%` | 数据集与网络模型初始化完成：`[Init] Model KeNetMultFactorNew initialized, total epochs: X` |
| **Epoch 训练循环** | `2.0% ~ 95.0%` | 每个 Epoch 结束计算线性比例：`percent = 2.0 + 93.0 * (epoch + 1) / total_epochs`，记录 Loss 与 Acc |
| **测试评估 (可选)** | `95.0% ~ 99.0%` | 评估完成时输出验证集指标：`[Eval] Epoch X - Acc: ...%, Sen: ...%, Spec: ...%` |
| **训练完毕** | `100.0%` | 产物保存与 `training_result.json` 生成完毕：`[Done] Training finished successfully` |

---

## 4. 验证计划

1. **语法与静态分析**：使用 `python3 -m py_compile` 校验 `train_fusion.py` 语法。
2. **单批次训练运行测试**：在临时隔离目录下执行快速训练（设置 `-bc 4 -e 1 -s 64` 等轻量参数或 dry-run 验证），验证：
   - `<log_dir>/train.log` 正确生成且各行能被 JSON 正确解码；
   - `<progress_dir>/progress.json` 存在且 `percent` 最终达到 100.0；
   - 无未捕获异常。
3. **现有 Go 语言单元测试**：运行 `go test -v ./internal/controller -run "TestRetinaDKD"`，确保既有逻辑未受破坏。
