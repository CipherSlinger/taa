# TAA 模型提供方开发与接口对接规范 (CipherFlow Spec)

## 1. 概述与演进背景

### 1.1 为什么需要 CipherFlow 专属 Spec？
在密态计算场景下，蚂蚁 TrustFlow 的 Protobuf 方案（`secretflow_spec`）主要面向分布式多方安全计算（MPC/FL）的算子节点编排，其定义重在多方节点拓扑图、表属性抽取（`TableAttrDef`）与分布式数据指针（`DistData`）。

但在 **TAA（Trusted Application Agent，基于海光 CSV TEE 的可信执行环境）** 体系下，模型提供方的执行场景具有独特的物理安全边界与管控诉求：
1. **密态黑盒执行与黑天鹅风���**：模型代码在 TEE 物理内存加密环境中执行，外部平台全程不可见内部过程。如果缺乏**实时的训练进度与心跳上报机制**，数小时的训练过程将沦为不可观测的黑盒，卡死、死循环或资源耗尽无法提前预警。
2. **严苛的单向沙箱物理路径约束**：数据机密性要求**输入数据路径绝对只读**，防止模型恶意篡改或注入；同时**输出产物路径独立隔离**，并接受防数据泄露检查（`ResultChecker`）。
3. **四阶段生命周期流转**：TAA 规定了 Phase 1（调试跑通）、Phase 2（基准测试）、Phase 3（密态正式训练）、Phase 4（推理部署）的递进阶段，不同阶段的导出权限（明文 vs SM2 密态信封）和计算目标各异。
4. **TEE 宿主崩溃自愈与断点续训**：硬件故障或容器自愈重启时，训练任务需要能无缝从检查点（Checkpoint）恢复，避免从头开始的算力浪费。
5. **严格的本地代码审计门禁**：模型代码导入时必须通过 AST 规则与本地轻量 LLM（Qwen）的静态语义双重审计，严禁网络外联、敏感数据明文拷贝等越界行为。

为此，本项目在吸收 TrustFlow 规范优点的基础上，演进出专属于本项目的 **`cipherflow.v1` 协议族与 Python SDK（CipherFlow）**。

---

## 2. 协议架构总览

CipherFlow Spec 位于 `models/spec/cipherflow/protos/cipherflow/v1/`（并在 `api/proto/cipherflow/v1/` 提供同步定义），分为 8 个核心模块：

```text
cipherflow.v1
├── types.proto         # 基础超参容器 (Attribute)、数据格式 (DataFormat)、通用键值
├── sandbox.proto       # 沙箱物理边界 (TeePathContract)：固定输入(/opt/taa/input)、输出(/opt/taa/output)、检查点
├── progress.proto      # 训练实时进度 (TrainingProgress)、Epoch评估总结、双向控制与 gRPC/流式服务
├── checkpoint.proto    # 故障自愈元数据 (CheckpointMeta)、断点恢复策略 (ResumeConfig)、保存策略
├── result.proto        # 训练结果标准体 (TrainingResult，对齐 /opt/taa/output/training_result.json)
├── security.proto      # 代码合规声明 (ModelSecurityDeclaration)、反泄露与依赖白名单
├── component.proto     # 组件模型 (ComponentDef)、算子插槽 (IoDef)、硬件算力配额 (ResourceRequirements)
└── evaluation.proto    # 执行运行参数 (TeeNodeEvalParam)、聚合执行结果 (TeeNodeEvalResult)
```

同时提供易用的 Python SDK：`from cipherflow import ProgressReporter, CheckpointManager, TrainingResult, TeePathContract, get_execution_phase`。

---

## 3. 核心契约与接口规约

### 3.1 契约一：固定输入输出路径与沙箱物理边界 (`sandbox.proto`)

TAA 容器内对文件系统划分出明确的物理安全边界：

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        TAA CSV TEE 容器沙箱                           │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  [输入目录] /opt/taa/input (只读挂载 READ_ONLY)                         │
│   ├── train/            # 训练集数据目录 (CSV/图像目录/Tensor)         │
│   ├── val/              # 验证集数据目录                               │
│   ├── test/             # 测试集数据目录                               │
│   ├── labels.csv        # 标签/标注映射文件                            │
│   └── weights/          # 预训练初始底模 (若有)                        │
│                                                                        │
│  [输出目录] /opt/taa/output (读写沙箱 READ_WRITE)                       │
│   ├── result/           # 训练代码主输出目录 (权重、结果、评测等产物)   │
│   │   ├── weights/      # 训练产出的模型权重文件 (*.pt, *.onnx)        │
│   │   ├── training_result.json # 必须产出的标准化训练结果与汇总指标    │
│   │   └── test_result.xlsx  # 评测阶段生成的明细指标表格               │
│   ├── log/              # 模型实时终端日志目录 (*.jsonl / *.log)       │
│   └── progress/         # 实时进度状态目录 (*.json 轮询通道)           │
│                                                                        │
│  [自愈目录] /opt/taa/checkpoint (持久化断点目录 READ_WRITE)            │
│   ├── latest.pt         # 最新权重快照                                 │
│   ├── best.pt           # 最优指标权重快照                             │
│   └── checkpoint_meta.json # 检查点元数据描述                          │
│                                                                        │
│  [代码目录] /opt/taa/models (工作区)                                   │
│   └── <解压后的模型源码>                                               │
└────────────────────────────────────────────────────────────────────────┘
```

#### 规则约束：
1. **输入只读**：模型脚本绝对不可在 `/opt/taa/input` 内创建或修改文件。
2. **输出自包含**：所有需要带出 TEE 的文件必须保存到 `/opt/taa/output/result`；实时日志与进度分别写入 `/opt/taa/output/log` 与 `/opt/taa/output/progress`。
3. **宏替换与环境注入**：TAA 在执行 `runtimeConfig` 时，会自动提供宏替换与环境变量：
   - 命令行宏：`<input>` 自动替换为输入数据实际路径，`<output>` 自动替换为训练代码产物目录 `/opt/taa/output/result`。
   - 环境变量：`TAA_INPUT_DIR`、`TAA_OUTPUT_DIR`（指向 `/opt/taa/output/result`）、`TAA_CHECKPOINT_DIR`、`TAA_TASK_ID`。

---

### 3.2 契约二：实时训练进度与心跳上报 (`progress.proto`)

长耗时训练任务必须定时或按 Step 上报进度，TAA 将进度实时透传给管控平台与监控面板。

#### 3.2.1 进度载荷结构 (`TrainingProgress`)
| 字段 | 类型 | 说明 |
| :--- | :--- | :--- |
| `task_id` | `string` | 平台分配的任务唯一标识 |
| `phase` | `ExecutionPhase` | 当前阶段（1=Debug, 2=Test, 3=Train, 4=Inference） |
| `current_epoch` | `int32` | 当前所处轮次（1-indexed） |
| `total_epochs` | `int32` | 训练总轮数 |
| `current_step` | `int64` | 全局累计迭代步数 |
| `total_steps` | `int64` | 预估总迭代步数（若未知置 0） |
| `percentage` | `float` | 总体任务进度（0.0% ~ 100.0%） |
| `elapsed_seconds` | `int64` | 任务已消耗时长（秒） |
| `eta_seconds` | `int64` | 预估剩余完成时间（秒） |
| `throughput_samples_per_sec` | `float` | 训练实时样本吞吐率 |
| `current_metrics` | `map<string, double>` | 实时指标（如 `loss`, `accuracy`, `learning_rate` 等） |
| `stage_name` | `string` | 当前细分阶段（如 `forward_backward`, `evaluating`） |
| `message` | `string` | 可读的进度摘要信息 |
| `timestamp` | `string` | ISO8601 UTC 时间戳 |

#### 3.2.2 三种上报载体通道
模型提供方可选择以下任意一种或多种通道上报，`cipherflow.ProgressReporter` 默认采用 **双通道自动模式 (AUTO)**：
1. **通道 A：标准输出流标记 (STDOUT Stream)**
   - 模型在控制台打印特定前缀行：
     ```text
     [CIPHERFLOW_PROGRESS] {"task_id": "task-001", "current_epoch": 5, "percentage": 50.0, "current_metrics": {"loss": 0.231}}
     ```
   - TAA 子进程管道自动拦截解析该标记行（兼容 `[CIPHERFLOW_PROGRESS]` 与 `[TAA_PROGRESS]`），不影响常规日志。
2. **通道 B：文件持久化落盘 (File Flush)**
   - 模型定时将最新进度原子写入 `/opt/taa/output/progress/` 目录下的 JSON 文件（如 `/opt/taa/output/progress/progress.json`）。
   - TAA 控制器具备文件变更探测能力，即时抓取进度并通过 `/v1/taa/reportProgress` 接口向平台上报。
   - 模型方终端日志追加写入 `/opt/taa/output/log/` 目录下的 JSONL 文件，TAA 自动增量读取并通过 `/v1/taa/modelLog` 接口上报。
3. **通道 C：本地 HTTP / gRPC 内部调用**
   - 模型通过本地接口 `POST http://127.0.0.1:6001/internal/progress` 发送 Protobuf JSON。

---

### 3.3 契约三：计算阶段识别与自适应逻辑 (`ExecutionPhase`)

TAA 的平台调度由 `/v1/taa/switch` 推进，模型代码通过 `cipherflow.get_execution_phase()` 识别当前阶段并采取不同分支策略：

| 阶段 | 枚举值 | 模型代码行为契约 | 导出与安全约束 |
| :--- | :--- | :--- | :--- |
| **Phase 1: 调试 (Debug)** | `PHASE_DEBUG` (1) | 使用少量样本（如 1~2 个 Batch，1 个 Epoch），快速验证数据读取、模型前向、反向传播与输出写入链路跑通 | 产物允许明文导出给模型方调试排错 |
| **Phase 2: 测试 (Test)** | `PHASE_TEST` (2) | 加载预训练底模或已有权重，在验证集上仅做推理评估，产出 `test_result.xlsx` 评估指标 | 产物明文返回平台 |
| **Phase 3: 训练 (Train)** | `PHASE_TRAIN` (3) | 全量敏感数据深度训练，定期上报进度与检查点，输出收敛权重与结果文件 | 产物**强制使用模型方 SM2 导出公钥加密**，平台仅为密文通道 |
| **Phase 4: 推理 (Inference)** | `PHASE_INFERENCE` (4) | 载入最终权重，读取批量未标注输入，生成预测结果表格 | 依业务要求密态回传 |

---

### 3.4 契约四：检查点与故障自愈断点续训 (`checkpoint.proto`)

应对 TEE 宿主机崩溃、容器 OOM 重启时的算力保护：
1. **保存检查点**：
   - 权重保存至 `/opt/taa/checkpoint/latest.pt`，最优指标保存至 `/opt/taa/checkpoint/best.pt`。
   - 同步更新元数据文件 `/opt/taa/checkpoint/checkpoint_meta.json`。
2. **检测与恢复**：
   - 任务重启后，TAA 注入 `TAA_RESUME=true`。
   - 模型在启动前调用 `CheckpointManager.should_resume()`，若检测到有效检查点，则加载权重、优化器与当前 Epoch，从断点继续训练。

---

### 3.5 契约五：最终结果文件规约 (`/opt/taa/output/result/training_result.json`)

训练进程成功退出（`exit_code=0`）后，TAA 立即读取 `/opt/taa/output/result/training_result.json`，与代码审计报告、数据集校验和聚合后构建最终的 `training_report.json` 并上报平台。

#### 标准结构示例：
```json
{
  "training_task": {
    "task_id": "task-20260911-001",
    "status": "succeeded",
    "exit_code": 0,
    "failure_reason": null,
    "started_at": "2026-09-11T10:00:00Z",
    "finished_at": "2026-09-11T10:45:00Z",
    "duration_seconds": 2700,
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
    "splits": {
      "train": 10000,
      "test": 2500
    }
  },
  "artifacts": {
    "primary_weight_path": "weights/best_model.pt",
    "format": "PyTorch"
  }
}
```

---

### 3.6 契约六：代码安全审计与反泄露红线 (`security.proto`)

在 TAA 中，所有模型源码都会经过 **静态规则检测 + 本地 LLM (Qwen) 深度语义研判**。模型代码必须遵守以下安全红线：

| 安全检查项 | 行为要求 | 违规后果 |
| :--- | :--- | :--- |
| **网络外联** | 严禁使用 `socket`, `requests`, `urllib`, `aiohttp`, `httpx` 等任何网络外联行为 | 审计阻断（Verdict: MALICIOUS），物理清除代码并终止导入 |
| **系统逃逸** | 严禁反弹 Shell（如 `/dev/tcp`, `sh -i`）、提权操作（`sudo`, `setuid`）、危险系统调用（`subprocess.Popen("rm -rf /")`） | 审计阻断，上报平台并终止 |
| **环境窃取** | 严禁扫描获取包含 `SECRET`, `KEY`, `TOKEN` 的系统环境变量 | 审计阻断 |
| **数据泄露** | 严禁将 `/opt/taa/input` 中的原始图片、原始数据文件直接复制到输出目录。TAA `ResultChecker` 会对输出进行特征比对与大小异常排查 | 导出阶段阻断，拒绝回传密文 |

---

## 4. 模型提供方接入实战指南 (代码示例)

模型提供方只需安装或引入 `cipherflow` 模块，几行代码即可完成完整合规对接。

```python
#!/usr/bin/env python3
"""
示例：使用 cipherflow 适配的标准 PyTorch 训练脚本 (train.py)
"""
import os
import torch
import torch.nn as nn
from pathlib import Path

# 引入 CipherFlow 契约 SDK
from cipherflow import (
    TeePathContract,
    ProgressReporter,
    CheckpointManager,
    CheckpointMeta,
    TrainingResult,
    TrainingTaskSummary,
    MetricsSummary,
    DatasetSummary,
    get_execution_phase,
    is_debug_phase,
)

def main():
    # 1. 初始化路径沙箱契约
    paths = TeePathContract()
    paths.prepare() # 自动确保输出目录 /opt/taa/output 等可用
    print(f"数据输入目录: {paths.input.root_dir}")
    print(f"模型输出目录: {paths.output.root_dir}")

    # 2. 判断当前计算阶段 (Phase 1 调试模式支持快速验证)
    phase = get_execution_phase()
    total_epochs = 1 if is_debug_phase() else 50
    print(f"当前阶段: {phase.description}, 计划训练 Epochs: {total_epochs}")

    # 3. 初始化进度上报器与检查点管理器
    reporter = ProgressReporter(task_id=paths.task_id, total_epochs=total_epochs)
    ckpt_mgr = CheckpointManager(checkpoint_dir=paths.checkpoint_dir, task_id=paths.task_id)

    # 4. 断点自愈检测
    start_epoch = 1
    if ckpt_mgr.should_resume():
        latest_ckpt = ckpt_mgr.get_resume_target()
        meta = ckpt_mgr.load_latest_meta()
        if latest_ckpt and meta:
            print(f"[自愈恢复] 检测到检查点: {latest_ckpt}, 从 Epoch {meta.epoch + 1} 恢复")
            start_epoch = meta.epoch + 1

    # 5. 训练循环
    best_loss = 999.0
    epoch_records = []
    
    for epoch in range(start_epoch, total_epochs + 1):
        # --- 模拟单轮训练过程 ---
        simulated_loss = round(1.0 / epoch, 4)
        simulated_acc = round(0.5 + (0.45 * epoch / total_epochs), 4)

        # 实时上报 Step / Epoch 进度 (自动计算 ETA 与吞吐量)
        reporter.report(
            epoch=epoch,
            step=epoch * 100,
            loss=simulated_loss,
            accuracy=simulated_acc,
            stage_name="training",
            message=f"完成第 {epoch} 轮训练",
            samples_in_batch=128,
        )

        epoch_records.append({"epoch": epoch, "loss": simulated_loss, "accuracy": simulated_acc})

        # 定期保存 Checkpoint (支持自愈)
        is_best = simulated_loss < best_loss
        if is_best:
            best_loss = simulated_loss
            # 保存最优权重
            torch.save({"epoch": epoch, "state_dict": {}}, paths.output.weights_dir / "best_model.pt")

        ckpt_mgr.record_meta(CheckpointMeta(
            checkpoint_id=f"ckpt-epoch-{epoch}",
            task_id=paths.task_id,
            epoch=epoch,
            step=epoch * 100,
            metrics={"loss": simulated_loss, "accuracy": simulated_acc},
            is_best=is_best,
        ))

    # 6. 保存标准结果 training_result.json (供 TAA 聚合上报平台)
    result = TrainingResult(
        training_task=TrainingTaskSummary(
            task_id=paths.task_id,
            status="succeeded",
            exit_code=0,
            duration_seconds=int(time.time() - reporter.started_time) if 'time' in globals() else 60,
        ),
        metrics=MetricsSummary(
            final_accuracy=epoch_records[-1]["accuracy"],
            final_loss=epoch_records[-1]["loss"],
            epochs=epoch_records,
        ),
        dataset=DatasetSummary(
            total_samples=1000,
            splits={"train": 800, "test": 200},
        ),
    )
    result.save(paths.output.root_dir)
    print("模型训练完成，契约结果已就绪。")

if __name__ == "__main__":
    main()
```
