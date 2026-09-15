# Audit-100 安全审计基准重构设计规范（真实生产模型与全正交架构 v2）

- **版本**：v2.0 (RFC)
- **日期**：2026-09-15
- **状态**：架构已修正 · 待用户复核
- **适用范围**：`models/audit` 下的基准体系设计、基准物化生成器（`tools/generate_benchmark_samples.py`）、审计分析引擎（`models/examples/code_security_analyzer.py`）、评测执行套件（`tools/audit_benchmark_eval.py`）及关联设计文档

---

## 1. 背景与重构动因

在 Audit-100 Benchmark v1 的早期设计与验证中，评测集虽然成功跑通了“纯端到端 LLM（Pure-LLM）”与“动静两阶段协同（Static-LLM）”的对比评测闭环，但在方法学、工程真实性与审计引擎底层机制上暴露了系统性缺陷：

1. **项目来源与标签的完全混杂偏置（Domain Confounding / Perfect Collinearity）**：
   - 旧设计中，50 个良性样本 100% 来源于 `LogisticRegression` 与 `TEE-test`；50 个恶意样本 100% 来源于 `Retina-DKD`。
   - 导致项目类型与安全标签形成了 1:1 的虚假强相关。大模型只要识别出代码属于图像处理或深度学习即可盲猜“恶意”，识别出简单回归即可盲猜“良性”，并未真正检验对具体数据流和执行逻辑的研判能力。
2. **基座代码底噪导致虚假的“50% 快速旁路率”（Baseline Noise Bias）**：
   - 原始 `LogisticRegression` 与 `TEE-test` 静态规则命中数为严格 0；而原始 `Retina-DKD` 自身带有 2 处高危写法（`test_run.py:18` 的 `os.system` 和 `data_process.py:128` 的 `eval`）。
   - 导致良性样本全部碰巧进入“0 Finding 快速旁路”，掩盖了真实工业深度学习代码在保存权重、多线程数据加载等合法操作时可能诱发语法误报的实际挑战。
3. **基座模型缺乏真实工业参考价值（Toy & Simulated Models）**：
   - 现存 `LogisticRegression` 为纯模拟玩具代码，数据完全由内存列表伪造生成，缺少真实数据读取与特征清洗工程；`TEE-test` 仅为底层驱动桩代码，非真实算法训练业务。
4. **审计分析引擎中的“80 行硬编码截断”感知盲区**：
   - 现有分析引擎 `code_security_analyzer.py:406` 硬编码截取前 80 行代码进行整文件安全分析。真实工业模型脚本通常有 150~400 行，后半部分注入的恶意行为会直接被截断抛弃，大模型完全不可见。

---

## 2. 核心架构修复与关键边界界定

针对审查中发现的 6 大错漏与工程隐患，v2 架构确立以下核心设计规范：

### 2.1 基座边界界定：“用户算法工程包” vs “系统预装框架库”
- **严禁全量打包开源库源码**：严禁将 `ultralytics`（200+ 文件）或 `transformers`（1000+ 文件）的上万行底层框架代码塞入审计样本。否则框架内部的合法自省与下载逻辑会触发上百个静态伪告警，导致算力崩溃。
- **正确定位**：在 TAA 真实生产环境中，PyTorch、Transformers、Ultralytics、XGBoost 均属于 TEE 基础镜像中预装的第三方库；
- **被审计对象规范**：每个基座严格限定为**“用户编写的真实业务训练工程包（User Algorithm Package）”**，包含 `train.py`、`dataset.py`、`model.py`、`pipeline.py` 等 **3~8 个核心业务文件**，总代码量控制在 **500~2000 行**，通过标准 `import` 引用预装框架。

### 2.2 审计引擎“80 行截断”改造规范（Engine Slicing Upgrade）
现有引擎盲目取前 80 行的做法必须予以修正，以支持真实工程的长代码审查：
1. **全局文件截断阈值提升**：将 `analyze_file` 中的 `max_lines` 从 80 提升至 **400 行**，确保完整覆盖常规业务训练的主干代码；
2. **基于 Finding 锚点的语义切片（Finding-Centered Context Slicing）**：当文件超过 400 行时，禁止简单的头部截断，改为优先保留文件头部 Import 语句 + 全部 Finding 命中行前后各 15 行上下文 + 入口 `if __name__ == '__main__'` 块，确保大模型获得完整的关键控制流。

### 2.3 微缩级生产数据规范（Micro-Dataset Spec）
为防止 100 份样本在沙箱物化（`copy_tree`）时造成 GB 级磁盘膨胀，每个真实基座配套的数据集执行微缩抽样：
- **P1 (XGBoost)**：`creditcard_sample.csv` 取 Kaggle 真实脱敏数据前 100 条（< 50 KB）；
- **P2 (Retina)**：`data/` 保留 5 张真实医学眼底切片图（< 500 KB）；
- **P3 (YOLOv8)**：`data/` 保留 5 张微型工业缺陷图像及对应标注 YAML（< 500 KB）；
- **P4 (BERT)**：离线迷你词表与 20 条真实文本语料（< 200 KB）。
- **硬指标**：单个基座工程总大小严格控制在 **< 2 MB**；100 个沙箱样本全量物化后总磁盘占用 **< 200 MB**。

### 2.4 离线内置资产规范（Vendored Offline Assets）
- **杜绝生成阶段动态外网依赖**：严禁在 `generate_benchmark_samples.py` 运行时发起动态 `git clone` 或 HuggingFace 网络拉取；
- **静态内置管理**：4 大基座的清洗版代码与微缩数据集统一作为静态资源内置在仓库 `benchmarks/base-projects/` 目录下，确保基准生成在完全断网的 TEE 生产与 CI 容器中 100% 确定性复现。

### 2.5 TAA 契约与合法业务白名单边界（Whitelisted Business Operations）
明确界定真实生产中的合法行为，避免大模型发生语法过敏：
- **合法模型权重保存**：通过 `torch.save(model.state_dict(), '/opt/taa/output/weights/best.pt')` 或 `joblib.dump()` 保存模型属于合法算法产出，规则与大模型在提示词引导下不得将其误判定性为 `OBF_001`（反序列化载荷）或 `EMB_001`（数据外泄）；
- **输入输出物理隔离**：严格对齐 TAA 契约，合规脚本仅从只读挂载目录读取数据，产出物写入指定 output 目录。

### 2.6 基准协议生命周期版本化（Protocol Lifecycle: v1 vs v2）
- **Audit-100 v1（历史经验基准）**：在旧版 3 基座（含模拟项目）上测得的 12 组对照矩阵数据（保留在 HTML 报告第 5 节，明确标注为 v1 历史基线）；
- **Audit-100 v2（全正交真实工业基准）**：本次重构确立的 4 大真实基座全正交架构，作为下一阶段物化执行与模型重新评测的新标准。

---

## 3. 4 大真实工业训练基座定义与工程规范

| 基座代号 | 真实模型与业务场景 | 开源官方来源与技术栈 | 业务代码与数据形态 | 关键安全审查敏感点 |
| :--- | :--- | :--- | :--- | :--- |
| **P1** | **`XGBoost-Finance`**<br>信用卡反欺诈交易预测 | **Kaggle / Scikit-Learn 官方流水线**<br>`xgboost`, `scikit-learn`, `pandas`, `joblib` | 真实脱敏信用卡交易 CSV；包含缺失值填充、特征缩放、分箱、5 折交叉验证与模型持久化导出 | 数据路径读取（防止遍历敏感环境变量）、模型权重序列化保存 |
| **P2** | **`Retina-ResNet`**<br>眼底病变医学影像分类 | **开源医疗 AI 诊断基准**（经白盒清洗）<br>`torch`, `torchvision` (ResNet-50) | 真实医学眼底影像切���；包含多线程 `DataLoader`、随机数据增强、混合精度训练（AMP）、TensorBoard 打点 | 历史遗留子进程命令派生与动态求值（须清洗）、大张量内存与权重落盘 |
| **P3** | **`YOLOv8-Detection`**<br>工业缺陷与目标检测 | **Ultralytics 官方精简独立训练工程**<br>`ultralytics`, `torch` | 真实标注工业缺陷数据集（YAML 驱动）；包含 Anchor 计算、Mosaic 数据拼贴增强、多进程派生、保存 `best.pt` | 官方代码后台自动更新检查与网络探针（须切断）、多进程任务分发 |
| **P4** | **`BERT-Sentiment`**<br>文本情感分析与微调 | **HuggingFace 官方 `transformers` 仓库**<br>`transformers`, `datasets`, `torch` | 真实文本分类语料；包含 `BertTokenizer` 离线词表分词、`Trainer` 训练循环、梯度累积、Checkpoints 检查点轮转 | 预训练权重与分词器隐式在线拉取（须限制离线）、动态导入与复杂依赖链 |

### 基座工程目录布局规范

```
benchmarks/base-projects/
├── P1-XGBoost-Finance/       # ~4 个业务脚本 + 微缩 CSV (~100KB)
│   ├── data/creditcard_sample.csv
│   ├── data_pipeline.py
│   ├── model_evaluate.py
│   └── train.py
├── P2-Retina-ResNet/         # ~5 个业务脚本 + 微缩切片 (~600KB)
│   ├── data_pre_process/data_process.py
│   ├── models/resnet50.py
│   └── train.py
├── P3-YOLOv8-Detection/      # ~4 个业务脚本 + 微缩缺陷图 (~600KB)
│   ├── data/industrial_defect.yaml
│   ├── yolo/data/dataset.py
│   ├── yolo/engine/trainer.py
│   └── train.py
└── P4-BERT-Sentiment/        # ~4 个业务脚本 + 离线轻量分词词表 (~300KB)
    ├── configs/training_args.json
    ├── dataset_loader.py
    ├── model_wrapper.py
    ├── tokenizer/
    └── run_classification.py
```

---

## 4. 完全正交平衡样本矩阵（Orthogonal Benchmark Matrix）

基准保持 **100 个样本（50 良性 + 50 恶意）** 以及 **10 个对抗家族各 10 个样本**，每个基座分配 **25 个样本**（12~13 良性，13~12 恶意）：

| 样本类别 | 对抗变体家族 (Family) | P1: XGBoost | P2: Retina | P3: YOLOv8 | P4: BERT | 家族合计 | 预期审计裁决 |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **良性**<br>(50例) | **B1** 等价语法重构 (Refactor) | 3 | 2 | 3 | 2 | **10** | BENIGN (放行) |
| | **B2** 诊断日志与指标打点 (Logging) | 2 | 3 | 2 | 3 | **10** | BENIGN (放行) |
| | **B3** 配置解析与数据流封装 (Config) | 3 | 2 | 3 | 2 | **10** | BENIGN (放行) |
| | **B4** 权重导出与结果落盘 (Export) | 2 | 3 | 2 | 3 | **10** | BENIGN (放行) |
| | **B5** 入口包装与 CLI 重构 (Wrapper) | 3 | 2 | 2 | 3 | **10** | BENIGN (放行) |
| **良性小计** | **每个基座良性样本数** | **13** | **12** | **12** | **13** | **50** | **100% 预期放行** |
| **恶意**<br>(50例) | **M1** 系统子进程命令执行 (Command) | 2 | 3 | 2 | 3 | **10** | MALICIOUS (阻断) |
| | **M2** 隐蔽网络数据外传 (Exfiltration) | 3 | 2 | 3 | 2 | **10** | MALICIOUS (阻断) |
| | **M3** 敏感凭证与密钥探测 (Credential) | 2 | 3 | 2 | 3 | **10** | MALICIOUS (阻断) |
| | **M4** 动态编码混淆载荷 (Obfuscation) | 3 | 2 | 3 | 2 | **10** | MALICIOUS (阻断) |
| | **M5** 复合利用链与持久化 (Chaining) | 2 | 3 | 3 | 2 | **10** | MALICIOUS (阻断) |
| **恶意小计** | **每个基座恶意样本数** | **12** | **13** | **13** | **12** | **50** | **100% 预期阻断** |
| **全量合计** | **每个基座样本总数** | **25** | **25** | **25** | **25** | **100** | **50:50 严格平衡** |

### 核心方法学收益
1. **先验概率严格归一化为 50%**：任何基座内良恶比为 ~50%，模型仅凭识别工程类型无法获取任何���签先验线索，彻底杜绝捷径学习（Shortcut Learning）；
2. **多模态与多计算范式覆盖**：兼顾经典表格风控、传统医学图像 CNN、工业缺陷目标检测与现代 NLP 大模型微调流水线。

---

## 5. 基座代码底噪清洗规范（Baseline Sanitization Gate）

所有基座在注入变体前，必须经过严格的白盒清洗，并通过扫描门禁测试：

1. **`XGBoost-Finance` 清洗**：
   - 统一数据与输出相对路径规范，禁止无界遍历环境变量（避免触发 `ENV_001` 误判）；
   - 使用标准 `joblib.dump` 保存模型对象，去除不安全的对象序列化写法。
2. **`Retina-ResNet` 清洗**：
   - 修复 `test_run.py:18`：将遗留的 `os.system(order)` 重构为安全规范的内部函数调用 `train_main(args)`，消除命令执行告警；
   - 修复 `data_process.py:128`：将 `eval(label[0])` 替换为强类型转换 `int(label[0].strip())`，消除动态代码执行。
3. **`YOLOv8-Detection` 清洗**：
   - 显式配置 `SETTINGS['sync'] = False`，彻底剥离后台自动遥测与更新探针代码分支。
4. **`BERT-Sentiment` 清洗**：
   - 显式设置 `local_files_only=True`，加载本地预置轻量词表与权重字典，杜绝隐式联网请求。

> **门禁验收红线**：直接对 4 大基座原始工程运行 TAA 静态扫描器时，**必须达到严格 0 Finding 纯净基线**。

---

## 6. 动静协同双阶段分流机制的真实演进

在 Audit-100 v2 体系下，动静协同架构展现出更具生产说服力的双道防线：

```
                              100 个真实评测样本
                                       │
                    Stage 1: 静态规则初筛 (<50ms/样本)
                                       │
                ┌──────────────────────┴──────────────────────┐
          零命中纯净代码                                 疑似命中可疑代码
         len(findings) == 0                             len(findings) > 0
                │                                             │
      【极速旁路 (Bypass)】                         Stage 2: 本地大模型定向语义仲裁
      约 30~35 例良性代码                                     │
      (B1等价重构 / B5入口包装)                 ┌─────────────┴─────────────┐
      毫秒级直接放行，免唤醒大模型               良性语法探针 (约15~20例)    真实恶意载荷 (50例)
                                                (B2指标打点/B3配置/B4权重)   (M1~M5 全部覆盖)
                                                       │                          │
                                                【行级语义纠偏放行】       【精准拦截 / 兜底】
                                                7行切片引导排除语法误报    确认恶意 / Fail-Closed
```

### 真实分流指标特征：
1. **真实算力减负**：~30%~35% 的确定性纯净样本通过 Stage 1 毫秒级直接旁路，免除大模型推理功耗；
2. **真实误报纠偏（FPR 压降）**：复杂生产代码中的良性语法探针（如 B2 打印整数计数器被误触发为 key 匹配、B4 保存模型权重触发文件落盘）进入 Stage 2，大模型利用 7 行局部切片与规则先验成功识别为合法业务并纠偏放行，从而在真实复杂代码下定量度量大模型压降误报的工程 ROI。

---

## 7. 关联文档与工件更新对照

| 工件文件路径 | 承担角色 | 更新与修复重点 |
| :--- | :--- | :--- |
| `docs/superpowers/specs/2026-09-15-benchmark-redesign-design.md` | 本设计规范文件 | 固化 4 真实基座、全正交矩阵、清洗规范、微缩数据集、引擎 80 行修复与白名单定义。 |
| `models/audit/research/taa-audit-design.html` | 核心架构设计全景 HTML | 第 4 节更新为 v2 架构；第 5 节增加协议版本标记（说明第 5 节为 v1 历史实测矩阵，v2 待物化执行刷新）。 |
| `models/audit/research/audit-benchmark-manifest.md` | 基准样本与家族清单 | 声明 4 大真实基座的工程来源与文件规范，明确 4 基座 × 10 家族 100 样本分配清单。 |
| `models/audit/research/audit-eval-iteration-log.md` | 评测迭代与设计日志 | 新增轮次 21 记录，详述发现混淆偏置缺陷、淘汰模拟模型、解决 80 行截断与确立 v2 全正交基准的决策链条。 |
