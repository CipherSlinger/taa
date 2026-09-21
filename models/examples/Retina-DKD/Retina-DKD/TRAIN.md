# 模型训练与测试指南 (CPU & 自定义输入尺寸 512)

本文档说明如何在 CPU 环境下使用输入尺寸 `img_size = 512` 进行 TransMUF 模型的训练与测试。

---

## 1. 模型训练 (Train)

使用 CPU 进行训练，并将输入图像尺寸指定为 512：

```bash
python train_fusion.py -b TransMUF -g cpu -bc 4 -e 150 -d _dkd -s 512 -nw 4
```

### 参数说明
- `-b TransMUF`: 基础网络架构（可选 `TransMUF`, `m1`, `m2`, `m3`, `m3_cnn_weight`, `m3_trans`, `resnet` 等）
- `-g cpu`: 使用 CPU 训练（若使用 GPU 则可指定如 `-g 0`）
- `-bc 4`: Batch size（批次大小）
- `-e 150`: 训练的总轮数（Epoch 数）
- `-d _dkd`: 数据集后缀（对应 `cls_dkd`）
- `-s 512`: 输入图像尺寸 `img_size`
- `-nw 4`: DataLoader 数据加载线程数 `num_workers`
- `--data-root`: 数据集根目录（默认为 `/opt/taa/input` 直读目录）
- `--output-dir`: 结果输出根目录（默认为 `/opt/taa/output`）
- `--log-dir`: 终端执行日志目录（默认为 `None`，推导为 `<output_dir>/log` 或同级 `log`）
- `--progress-dir`: 训练进度文件目录（默认为 `None`，推导为 `<output_dir>/progress` 或同级 `progress`）

训练产出的模型权重及评测汇总将保存在：
- 模型权重：`/opt/taa/output/model_fusion_TransMUF_dkd_win_num3_lr1_ep150bc_4lnum_1_Nopretrain_DKD/`
- 任务结果：`/opt/taa/output/training_result.json`
- 任务终端日志：`/opt/taa/output/log/train.log`（JSONL 单行格式，记录每行执行日志及 UTC 时间戳）
- 任务进度：`/opt/taa/output/progress/progress.json`（原子写入的进度 JSON，包含高精度时间戳、多阶段进度百分比与详细训练元数据）

### 1.1 细粒度训练进度与状态上报机制

`train_fusion.py` 实现了多阶段细粒度进度追踪与元数据写入，便于平台与终端实时直观地观测训练状态：

1. **进度预算划分**：
   - **初始化阶段 (0.0% - 2.0%)**：记录环境准备、模型初始化、损失函数/优化器配置、数据集与 DataLoader 创建。
   - **训练与评估阶段 (2.0% - 96.0%)**：
     - 每个 Epoch 根据总轮数均分进度区间。
     - Epoch 内按训练 Batch 动态插值计算进度，并在 Batch 1、尾 Batch 及每 10% 进度处原子写入 `progress.json`。
     - 每 20% Batch 在终端和 `train.log` 中同步输出 Step 级别的 loss 与 accuracy。
     - 评估轮次（`epoch % 4 == 0`）动态细分 Evaluation 进度并汇报检查点保存事件。
   - **收尾阶段 (96.0% - 100.0%)**：记录评测指标汇总、`training_result.json` 生成以及任务成功完成。

2. **`progress.json` 数据结构示例**：
```json
{
  "percent": 34.65,
  "timestamp": "2026-09-21T07:15:32.123456Z",
  "stage": "train",
  "message": "Epoch 3/150 [Batch 15/40] - loss: 0.3821, acc: 85.00%",
  "epoch": 3,
  "total_epochs": 150,
  "batch": 15,
  "total_batches": 40,
  "loss": 0.3821,
  "acc": 85.0
}
```

3. **I/O 节流与单调性保障**：
   - 默认通过 `min_interval_seconds=0.5` 与 `min_percent_delta=0.1` 防止高频 Batch 刷盘造成的 I/O 抖动。
   - 关键状态变更与 Milestone 支持 `force=True` 强制落盘。
   - 进度百分比具备单调递增保障，防止网络抖动或异步轮询导致的进度回退。

---

## 2. 模型测试 (Test)

测试阶段指定 `-g cpu` 以及 `-s_img 512`，`-mnp` 填入对应的模型目录名。`-el` 与 `-er` 用于指定测试的 epoch 范围（默认测试保存的模型权重）。

### 2.1 图像级别测试 (`test_fusion.py`)

```bash
python test_fusion.py -s main -m TransMUF -x test_result.xlsx -d 1 \
  -mnp model_fusion_TransMUF_dkd_win_num3_lr1_ep150bc_4lnum_1_Nopretrain_DKD \
  -b TransMUF -g cpu -s_img 512 -df _dkd -nw 4 -el 1 -er 2
```

### 2.2 患者级别测试 (`test_fusion_pat.py`)

```bash
python test_fusion_pat.py -s main -m TransMUF -x test_result_pat.xlsx -d 1 \
  -mnp model_fusion_TransMUF_dkd_win_num3_lr1_ep150bc_4lnum_1_Nopretrain_DKD \
  -b TransMUF -g cpu -s_img 512 -df _dkd -nw 4 -el 1 -er 2
```

### 测试参数说明
- `-s main`: 测试集类型（可选 `main`, `Prospective`, `Multi_center`, `Non_standard`）
- `-m TransMUF`: 模型标识名称
- `-x test_result.xlsx`: 测试结果输出的 Excel 文件名
- `-d 1`: 数据集编号
- `-mnp <model_dir_name>`: 模型保存文件夹名称（`model/` 下的子目录名）
- `-b TransMUF`: 基础模型类型
- `-g cpu`: 指定运行设备为 CPU
- `-s_img 512`: 指定测试图像输入尺寸
- `-df _dkd`: 数据集描述后缀
- `-el 1 -er 2`: 测试 epoch 范围（从 epoch 1 测试到 epoch 1，步长为 4）
- `-nw 4`: DataLoader 读取线程数
