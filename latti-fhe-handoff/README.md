# Latti FHE 服务端 — 交付包（handoff bundle）

这是一套**已在本机跑通完整平台化 FHE 端到端（cifar-10）**的服务端交付物，
包含：服务端 Docker 镜像、FHE 运行时、部署编排文件、测试模型、浏览器 WASM 客户端包与任务参数包。

> 设计前提：FHE 服务是平台的**一个功能模块**。平台/TAA 负责鉴权、对象存储（MinIO）
> 和文件上下行；FHE 只读写容器内约定目录，并对外暴露少量 HTTP 接口。
> 详见下方「接口」与「目录约定」。

---

## 1. 交付内容

```
latti-fhe-handoff/
├── image/
│   └── latti-server-latest.tar.gz      # 服务端镜像 latti/latti-server:latest (≈400MB 镜像)
├── third_party/
│   ├── latti-ai-runtime/               # FHE 运行时（精简包，镜像外部挂载用）
│   └── latti-ai-runtime.tar.gz         # 同一运行时的归档（转手/异地部署用）
├── deploy/docker/                      # 部署编排
│   ├── docker-compose.node.yml         #   api / worker / redis 三服务
│   ├── configs/node.toml.template      #   容器内配置模板
│   ├── env/{node.env,node.local.env}   #   通用 / 本机覆盖环境变量
│   └── scripts/run-node.sh             #   一键启动脚本
├── data/
│   └── models/cifar10/server/          # 测试模型（放进目录后热加载，不改配置）
├── client/
│   ├── latti-client-wasm-0.1.0.zip     # 浏览器 WASM 客户端（本地生成密钥 / 加密 / 解密）
│   └── tasks.zip                       # 任务参数包：tasks/<model>/client/{task_config,ckks_parameter,img}.csv
├── TAA-FHE-对接说明.md                  # 给对接同事的一页流程 / 目录 / 接口说明
├── 模型端到端性能验证报告.md             # 关键阶段耗时 / 内存 / 显存实测
└── README.md
```

镜像里只有 **Python 3.10 运行环境 + 服务端代码**（`/app/server`）。
FHE 原生库（`liblattisense.so`、Python 绑定等）和模型都**在镜像外**，运行时挂载。
运行时是**精简包**：只含 worker 真正加载的库（约 100 MB），
不再打包 `examples/` 模型、Node/Windows SDK 与验证用例；模型改从
`data/models/<model_id>/server/` 热加载。

---

## 2. 前置条件

- Linux x86_64，glibc ≥ 2.38（本机 openEuler 24.03 满足）
- NVIDIA 驱动 + **nvidia-container-toolkit**（本机已装 1.20.1），`docker run --gpus all` 可用
- Docker + docker compose v2
- 当前用户在 `docker` 组（否则命令前加 `sg docker -c '...'` 或 `sudo`）

---

## 3. 快速开始

```bash
cd /home/jiangsy/latti-fhe-handoff

# (1) 导入镜像
sg docker -c 'docker load -i image/latti-server-latest.tar.gz'
sg docker -c 'docker images | grep latti-server'

# (2) 检查/修改本机变量（端口、数据目录、运行时目录、GPU）
vi deploy/docker/env/node.local.env

# (3) 启动三服务（api + worker + redis）
cd deploy/docker
sg docker -c './scripts/run-node.sh up -d'
sg docker -c './scripts/run-node.sh ps'
```

> 运行时目录已就绪在 `third_party/latti-ai-runtime`，`node.local.env` 里的
> `HOST_RUNTIME_DIR` 默认指向它。若移走交付包，务必同步修改所有 `HOST_*` 路径。
>
> 若本机已有 FHE 栈占用 58996/58998，请改 `node.local.env` 的
> `API_PORT` / `API_HOST_PORT` / `LOCAL_REDIS_HOST_PORT`。

### 验证
```bash
curl -s http://127.0.0.1:58996/api/v1/health | python3 -m json.tool
# 期望：status=ok，能看到 models_dir / dynamic_models 等字段
```

---

## 4. 接口（统一前缀 `/api/v1`，无鉴权；租户标识走请求头 `X-User-Id`）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 健康检查 |
| GET | `/models` | 列出现已注册模型 |
| POST | `/models/activate?model_id=<id>` | 扫描模型目录并热加载（不重启进程） |
| POST | `/tasks` | 创建任务（读 `input.zip`，见下） |
| GET | `/tasks/{task_id}` | 任务状态 / 各 case 进度 |
| GET | `/tasks/{task_id}/events` | SSE 事件流 |
| POST | `/tasks/{task_id}/cancel` / `/heartbeat` / `/continue`(`/retry`) / `/delete` | 取消 / 续租 / 重试 / 删除 |
| GET | `/tasks/{task_id}/results` | 结果清单 |
| GET | `/tasks/{task_id}/results/download` | 下载 `output.zip` |

创建任务请求体示例：
```json
{ "user_id": "testuser", "model_id": "cifar10",
  "callback_url": "http://<taa-host>:59999/callback", "cancel_on_disconnect": false }
```
任务完成后服务端会向 `callback_url` POST 结果 JSON（含 `status`、各 case、`result_zip` 路径），
失败会重试若干次。

---

## 5. 目录约定（容器内 `/data`，对应宿主机 `HOST_DATA_DIR`）

```
<data>/
├── models/<model_id>/server/            # 模型资源（交由 activate 热加载）
├── keys/<user_id>/eval_context.bin      # 用户评估上下文/公钥（所有模型共用一份），服务端只读不校验
├── tasks/<task_id>/input.zip            # 任务输入密文包，条目 <case_id>.ct
└── results/<task_id>/output.zip         # 任务结果包，条目 <case_id>.result.bin
```

- 输入 zip 扁平存放，**一个 case 一个密文文件**：`case-00.ct`；多输入模型为
  `case-00__<input_name>.ct`。
- TAA 负责把浏览器产生的密文放到 `tasks/<task_id>/input.zip`，并在任务完成后
  把 `results/<task_id>/output.zip` 上传回 MinIO 供浏览器端解密。
- 服务端**不接触 MinIO**，只认本地目录。

---

## 6. 测试模型
交付包自带 `data/models/cifar10/server`。模型不再写进配置，由 `[model_registry]`
扫描 `data/models/<model_id>/server/` 热加载（启动日志会打印
`Model registry: N model(s)`）。启动后：
```bash
curl -s -X POST 'http://127.0.0.1:58996/api/v1/models/activate?model_id=cifar10'
curl -s http://127.0.0.1:58996/api/v1/models -H 'X-User-Id: testuser'
```
本包 `client/tasks.zip` 内的 `tasks/resnet20/client/` 与
`data/models/cifar10/server/` 的参数**逐字节一致**（`param_hash = c985b737…`），
因此可直接用于 cifar10 的端到端。

浏览器侧怎么集成见 `client/latti-client-wasm-0.1.0.zip` 内的 `README.md`：
把 `dist/` 作为静态资源托管（`.wasm` 需 `application/wasm`），
把 `tasks/<model>/client/` 作为客户端目录，导入 `dist/index.js` 即可。

---

## 7. 校验
`SHA256SUMS` 记录了大件（镜像、运行时归档、两个客户端包）的 SHA-256：
```bash
cd /home/jiangsy/latti-fhe-handoff && sha256sum -c SHA256SUMS
```

## 8. 已在本机验证的结果（参考）

> 详细数据见同目录 `模型端到端性能验证报告.md`。

- **本交付镜像**（`sha256:252fa15c9133…`）+ **本交付运行时**（精简包）容器化冒烟：
  启动日志 `Model registry: 1 model(s), models_dir=/data/models`、
  `isolate_gpu_task_process=False, resident_server_enabled=True`、
  `Loaded: /runtime/latti-ai-runtime/build/inference/lattisense/liblattisense.so`。
- 容器化端到端（cifar-10，10 条批量，`keys/testuser/eval_context.bin` 一份公钥）：
  任务 `completed` 10/10，`output.zip` 10 条目，回调 HTTP 200。
- **常驻复用**：同用户连续两任务 —— 冷启动 **108.9s**，第 2 个 **78.6s**
  （第 2 个任务不再 `import_eval_context`，日志出现 `Reusing resident server`）。
  两轮 10 个 case 结果逐字节一致。
- **显存归还**：任务间 GPU 从 **43,875 MiB → 515 MiB**（空闲只占 ~0.5 GiB）；
  `import_eval_context` 3.18 GiB 全程 **0 显存**（纯 host，耗时 28.4s）。
- 单 case GPU 推理 **7.2–7.8s**；worker RSS 峰值 29.2 GiB。
- 热加载：服务**不重启**，把模型放进 `data/models/<id>/server/` 调 `activate` 即可提交任务。
- **浏览器 WASM 客户端端到端（Playwright/Chromium 实测，本机）**：`setup()`
  466s → `eval_context.bin` **3,329,929,205 B**（与运行时基准 `evalFileSize`
  完全一致）、`full_context.bin` 25,494,056 B；`encrypt(img.csv)` →
  3,653,705 B / 1.4s；单 case 任务 `completed` 1/1；`decrypt` 194ms，
  与明文基准 `max|Δ| = 0.000498`（阈值 0.1 内）。页面刷新后 `restore()`
  1.1s 且解密结果一致；重复 `setup()` 被正确拒绝（提示 restore）。

### 显存池预算（一卡多容器时使用）

默认首次上卡按空闲显存的 90% 预占（本机 43.9 GiB）。多容器共卡时给每个
worker 设上限即可（48 GB 卡可并放 3 个 16 GiB 预算的容器）：

```yaml
# docker-compose.node.yml -> fhe-worker environment
HEONGPU_DEVICE_POOL_MAX_BYTES: "17179869184"   # 16 GiB
```

