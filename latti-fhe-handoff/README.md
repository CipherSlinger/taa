# Latti FHE 服务端 — 交付包

一个**自包含的 FHE 推理服务镜像** + 测试模型 + 浏览器客户端包。

平台侧要做的事只有三件：**起一个容器、挂一个数据卷、暴露一个端口（58996）**。
鉴权、对象存储、文件上下行、多节点调度都由平台负责；FHE 服务只读写容器内约定目录并对外提供 HTTP 接口。

---

## 1. 交付内容

```
latti-fhe-handoff/
├── image/
│   └── latti-server-latest.tar.gz  # 服务端镜像 latti/latti-server-node:latest（667 MB）
├── data/
│   └── models/
│       ├── resnet20/server/             # ResNet20（CIFAR-10）模型（12 MB）
│       └── retina/server/               # Retina-DKD degree8_02 模型（444 MB）
├── client/
│   └── latti-e2e-0.1.2-v1.zip              # 浏览器客户端 + 两个模型的 task/data 包（5.0 MB）
├── TAA-FHE-对接说明.md                   # 对接流程 / 目录 / 接口示例
├── 模型端到端性能验证报告.md              # 耗时 / 内存 / 显存实测
├── SHA256SUMS
└── README.md
```

镜像内已经包含：Python 3.10 运行时、服务端代码、**redis**、**FHE 运行时**
（`liblattisense.so` + Python 绑定 + HEonGPU）、单容器启动脚本。
**模型和用户公钥不打进镜像**，全部从挂载目录读。

---

## 2. 前置条件

- Linux x86_64
- NVIDIA 驱动 + nvidia-container-toolkit（或 Kubernetes + NVIDIA device plugin）
- 一个持久卷挂到容器内 `/data`

---

## 3. 部署

```bash
docker load -i image/latti-server-latest.tar.gz

docker run -d --name fhe-node --gpus all \
  -p 58996:58996 \
  -v /opt/fhe-data:/data \
  -e NODE_ID=node-a \
  latti/latti-server-node:latest

# 健康检查
curl -s http://127.0.0.1:58996/api/v1/health
```

Kubernetes（平台按自己的规范写即可，关键点只有 GPU、卷、端口）：

```yaml
containers:
  - name: fhe
    image: latti/latti-server-node:latest
    ports: [{ containerPort: 58996 }]
    resources:
      limits: { nvidia.com/gpu: 1 }
    volumeMounts:
      - { name: data, mountPath: /data }
    env:
      - { name: NODE_ID, value: node-a }
```

**端口**：只有 `58996`（`API_PORT`）。redis 监听容器内 `127.0.0.1:6379`，不对外暴露；
日志、结果、事件流都走这同一个端口。

**进程守护**：entrypoint 同时拉起 redis → api_server → worker，任一进程退出则容器退出，
交给 `restartPolicy` 处理；`SIGTERM` 转发给全部子进程。

**镜像自包含**：CUDA 只依赖驱动侧注入的 `libcuda.so.1`，**不需要**挂载宿主 `/usr/local/cuda`。

---

## 4. 目录约定（容器内 `/data`，对应挂载的持久卷）

```
<data>/
├── models/<model_id>/server/          # 模型资源，放入后热加载
├── keys/<user_id>/eval_context.bin    # 用户评估上下文（所有模型共用一份），服务端只读
├── tasks/<task_id>/input.zip          # 任务输入密文包，条目 <case_id>.ct
├── results/<task_id>/output.zip       # 任务结果包，条目 <case_id>.result.bin
└── logs/worker.log                    # worker 运行日志（自动轮转）
```

- 输入 zip 扁平存放，**一个 case 一个密文**：`case-00.ct`；多输入模型为 `case-00__<input_name>.ct`。
- 服务端**不接触对象存储**，只认本地目录；平台负责把密文放进来、把结果包取走。

---

## 5. 接口（前缀 `/api/v1`，无鉴权；租户标识走请求头 `X-User-Id`）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 健康检查 |
| GET | `/models` | 列出已注册模型 |
| POST | `/models/activate?model_id=<id>` | 扫描模型目录并热加载（不重启进程） |
| POST | `/tasks` | 创建任务 |
| GET | `/tasks/{task_id}` | 任务状态 / 各 case 进度 |
| GET | `/tasks/{task_id}/logs` | **实时运行日志**（`text/plain` 流，平台终端窗口用） |
| GET | `/tasks/{task_id}/events` | SSE 事件流 |
| GET | `/tasks/{task_id}/results` | 结果清单 |
| GET | `/tasks/{task_id}/results/download` | 下载 `output.zip` |
| POST | `/tasks/{task_id}/cancel` / `/heartbeat` / `/continue`(`/retry`) / `/delete` | 取消 / 续租 / 重试 / 删除 |

创建任务：

```bash
curl -s -X POST http://127.0.0.1:58996/api/v1/tasks \
  -H 'Content-Type: application/json' -H 'X-User-Id: testuser' \
  -d '{"user_id":"testuser","model_id":"resnet20","task_id":"task-abc123",
       "callback_url":"http://<platform-host>:59999/callback","cancel_on_disconnect":false}'
```

任务完成后服务端向 `callback_url` POST 结果 JSON（含 `status`、各 case、`result_zip` 路径），失败会重试几次。

**实时日志**（平台展示推理进度的终端窗口）：

```bash
curl -N 'http://127.0.0.1:58996/api/v1/tasks/task-abc123/logs' -H 'X-User-Id: testuser'
```

纯文本逐行追加，默认 `follow=true`：从该任务的起点回放并持续跟随，最后一行固定是
`===== task <task_id> end status=<completed|failed> =====`，然后自动断开。

---

## 6. 环境变量

未注入的用镜像默认值：

| env | 默认 | 说明 |
|---|---|---|
| `API_PORT` | `58996` | 对外 HTTP 端口 |
| `GPU_DEVICES` | `0` | 可见 GPU 列表 |
| `NODE_ID` / `NODE_INSTANCE` | 容器主机名 | 节点标识，进 redis key 前缀 |
| `HEONGPU_DEVICE_POOL_INITIAL_BYTES` | `21474836480` | 显存池起步 20 GiB |
| `HEONGPU_DEVICE_POOL_MAX_BYTES` | 不设 | 不设时上限 = `0.95 × 启动时空闲显存`（随卡自适应） |
| `INFERENCE_STALL_TIMEOUT_SECONDS` | `600` | 任务看护超时 |
| `LOCAL_REDIS_PASSWORD` | 空 | 设了就要求 redis AUTH |

---

## 7. 显存与任务看护

- 显存池是**进程级**的：首次上卡按 `INITIAL` 预占，之后**按需增长**（每次扩到
  「上限与当前值的中点」），任务结束由 `release_device()` **整池归还**（空闲只剩 ~0.5 GiB）。
- 默认 20 GiB 起步足够跑 resnet20（实测峰值 20,993 MiB）；retina 会自动涨到 ~34 GiB。
- `MAX_BYTES` **默认不设**：上限按 `0.95 × 启动时空闲显存` 自适应，不会因为"上限贴着整卡"
  而在初始化时和别的进程抢不过就失败。
- ⚠️ 预算**别贴着真实用量设**：不够时 RMM 抛 `out_of_memory`，任务直接 `failed`
  并把原因写进 `task.error`（不会静默卡住）。
- **一卡多容器**：需要把一张卡并放多个容器时，才显式给每个容器设 `MAX_BYTES` 份额。
- **内存**：常驻的解析结果约 14–15 GiB（3.2 GiB 公钥展开）；每个 case 结束后 worker 会做一次
  `malloc_trim`，把该次计算的临时内存还回系统（实测每次还 3–4 GiB）。
- **任务看护**：`INFERENCE_STALL_TIMEOUT_SECONDS` 内推理无任何进度推进，worker 会把该 case
  记为失败、写入 `task.error` 并重启自己，避免任务永久停在 `running`。

---

## 8. 测试模型与客户端

- **模型**：把 `data/models/<model_id>/server/` 拷进卷里的 `<data>/models/` 即可，启动后
  `POST /api/v1/models/activate?model_id=<model_id>` 热加载（日志打印 `Model registry: N model(s)`）。
  当前提供两个：`resnet20`（CIFAR-10 数据集，12 MB）、`retina`（Retina-DKD degree8_02，444 MB）。
- **客户端**：`client/latti-e2e-0.1.2-v1.zip` 内 `manifest.json` + `README.md` 说明各包含什么——
  `WASM-0.1.2.zip`（浏览器运行时）、`<model>-task-*.zip`（解出 `tasks/<model>/client/` 客户端目录）、
  `<model>-data-*.zip`（测试数据）。把 `client/` 作为 `clientDirectory`、`dist/` 作为静态资源托管
  （`.wasm` 需 `application/wasm`），导入 `dist/index.js`。浏览器本地生成密钥（`setup()` 约 466 s，一次性）、加密、解密。
  **客户端内容与 v0 完全相同**（就是同事给的 `latti-e2e-0.1.2.zip`），本次只随服务端重命名为 `-v1` 以便配对；v1 的改动全在服务端镜像里。

---

## 9. 校验

```bash
sha256sum -c SHA256SUMS
```

---

## 10. 已在本机验证（参考）

- 容器化端到端（resnet20）：任务 `completed`，`output.zip` 条目数与输入一致，回调 HTTP 200。
- 单 case GPU 推理 7.2–7.8 s；`import_eval_context` 3.18 GiB 全程 **0 显存**（纯 host，28 s）。
- 常驻复用：同用户连续两任务 108.9 s → 78.6 s（第二个任务跳过 import）。
- 显存：任务结束从峰值 **→ 513 MiB** 归还；worker RSS 峰值 29.2 GiB。
- 浏览器 WASM 端到端：`setup()` 466 s → `eval_context.bin` 3,329,929,205 B；`decrypt` 194 ms，
  与明文基准 `max|Δ| = 0.000498`（阈值 0.1）。

详细数据见 `模型端到端性能验证报告.md`。
