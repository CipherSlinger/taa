# TAA ↔ FHE 对接说明（简版）

> FHE 服务**不知道 MinIO 的存在**。平台/TAA 负责鉴权、对象存储与文件上下行；
> FHE 只做三件事：**读约定目录 → 算 → 写约定目录 + 回调**。

---

## 1. 整体交互流程

```
 浏览器                 TAA（平台侧）                      FHE 服务（本镜像）
   │                        │                                   │
   │ ① 生成密钥 / 加密       │                                   │
   │   （平台集成）          │                                   │
   ├───────────────────────►│                                   │
   │                        │ ② 把公钥与输入密文写到共享目录      │
   │                        ├──── 共享目录 (本地磁盘) ──────────►│
   │                        │    keys/<user>/eval_context.bin   │
   │                        │    tasks/<task_id>/input.zip      │
   │                        │                                   │
   │                        │ ③ POST /api/v1/tasks  创建任务 ───►│
   │                        │                                   │ ④ Worker 读密文
   │                        │                                   │   做 FHE 推理
   │                        │ ⑤ HTTP 回调（任务完成/失败）◄──────┤
   │                        │                                   │   并写
   │                        │    results/<task_id>/output.zip   │
   │                        │◄────────── 读 output.zip ─────────┤
   │                        │ ⑥ 上传结果密文到 MinIO            │
   │◄── ⑦ 下载结果密文 ──────┤                                   │
   │ ⑧ 本地解密             │                                   │
```

要点：**FHE 只认本地目录 + 一个任务接口**，不碰鉴权、不碰 MinIO。

---

## 2. 目录约定（容器内 `/data`，宿主机为 `HOST_DATA_DIR`）

| 目录 | 谁写 | 谁读 | 说明 |
|---|---|---|---|
| `models/<model_id>/server/` | 平台/TAA | FHE | 模型服务端资源；放入后调 `activate` 热加载 |
| `keys/<user_id>/eval_context.bin` | TAA | FHE | **一个用户一份公钥**（所有模型共用同一套 65536+BTP 参数）；FHE 只读、不校验 |
| `tasks/<task_id>/input.zip` | TAA | FHE | 任务输入密文包，一个 case 一个文件 |
| `results/<task_id>/output.zip` | FHE | TAA | 任务结果密文包 |

> ⚠️ 公钥路径**不含 `model_id`**：参数统一后，同一用户的公钥对所有模型通用，
> 因此目录只有 `<user_id>` 一层。

### zip 内部命名

- `input.zip`：单个密文 = 一个 case/图片
  - 单输入模型：`<case_id>.ct`（如 `case-00.ct`）
  - 多输入模型：`<case_id>__<input_name>.ct`（如 `case-00__input.ct`）
- `output.zip`：`<case_id>.result.bin`（如 `case-00.result.bin`）

---

## 3. 接口（前缀 `/api/v1`，无鉴权；租户标识走请求头 `X-User-Id`）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 健康检查 |
| GET | `/models` | 列出现已注册模型 |
| POST | `/models/activate?model_id=<id>` | 发现并热加载模型（**不重启进程**） |
| POST | `/tasks` | 创建任务 |
| GET | `/tasks/{task_id}` | 任务状态/各 case 进度 |
| GET | `/tasks/{task_id}/events` | SSE 事件流 |
| POST | `/tasks/{task_id}/cancel` | 取消任务 |
| POST | `/tasks/{task_id}/heartbeat` | 续租（`cancel_on_disconnect` 时用） |
| POST | `/tasks/{task_id}/continue` | 重跑未完成 case（别名 `/retry`） |
| POST | `/tasks/{task_id}/delete` | 删除任务及其输入/结果 |
| GET | `/tasks/{task_id}/results` | 结果清单 |
| GET | `/tasks/{task_id}/results/download` | 下载 `output.zip` |

创建任务请求体：

```json
{
  "user_id": "testuser",
  "model_id": "cifar10",
  "task_id": "task-abc123",
  "callback_url": "http://<taa-host>:59999/callback",
  "cancel_on_disconnect": false
}
```

任务终态后，FHE 会向 `callback_url` POST 一份 JSON（含 `status`、各 case 的
`entry`/`result_id`/`error`、以及 `result_zip` 相对路径）；失败按 0/1/4/16s 退避重试。

---

## 4. 使用步骤

```bash
# 0) 让 FHE 栈跑起来（见交付包 README；本包已配好路径）
cd deploy/docker && ./scripts/run-node.sh up -d
curl -s http://127.0.0.1:58996/api/v1/health

# 1) 放入模型（可放多个），热加载
#    把 <model>/server/* 放到  <data>/models/<model_id>/server/
curl -s -X POST 'http://127.0.0.1:58996/api/v1/models/activate?model_id=<model_id>'
curl -s http://127.0.0.1:58996/api/v1/models -H 'X-User-Id: testuser'

# 2) 写公钥（一个用户一份）
#    cp eval_context.bin  <data>/keys/<user_id>/eval_context.bin

# 3) 写输入包
#    mkdir -p <data>/tasks/<task_id>
#    把 case-*.ct 打成 zip 放  <data>/tasks/<task_id>/input.zip

# 4) 创建任务
curl -s -X POST http://127.0.0.1:58996/api/v1/tasks \
  -H 'Content-Type: application/json' -H 'X-User-Id: testuser' \
  -d '{"user_id":"testuser","model_id":"cifar10","task_id":"task-abc123",
       "callback_url":"http://<taa-host>:59999/callback","cancel_on_disconnect":false}'

# 5) 拿结果
curl -s 'http://127.0.0.1:58996/api/v1/tasks/task-abc123/results/download' \
  -H 'X-User-Id: testuser' -o output.zip
```

---

## 5. 浏览器客户端与任务参数包

浏览器侧不再使用 Node 包，改用 WASM 包：

- `client/latti-client-wasm-0.1.0.zip`：纯浏览器客户端（Dedicated Worker +
  Go/WASM），**不需要 Node，也不需要本地代理**。把 `dist/` 当静态资源托管
  （`.wasm` 必须返回 `application/wasm`；页面须为 HTTPS 或 `http://localhost`），
  导入 `dist/index.js`，调 `openBrowserClient({ clientDirectory })`。
- `client/tasks.zip`：任务参数包，`tasks/<model>/client/` 内含
  `task_config.json`、`ckks_parameter.json`、`img.csv`；这个目录就是
  `clientDirectory`，必须先把前两个文件放进去再 `openBrowserClient()`。
  其中 `tasks/resnet20/client/` 与 `data/models/cifar10/server/` 参数逐字节一致。

调用顺序：

```js
const client = await openBrowserClient({ clientDirectory });  // 目录含 task_config/ckks_parameter
if (await hasFile(clientDirectory, 'full_context.bin')) await client.restore();
else await client.setup();          // 生成 eval_context.bin + full_context.bin
const ct = await client.encrypt({ inputName: 'input', inputFile, outputDirectory });
// ① 把 clientDirectory/eval_context.bin 复制到 keys/<user_id>/eval_context.bin
// ② 把 ct（input.ct.bin）作为 tasks/<task_id>/input.zip 内的 case-00.ct
// ③ POST /tasks 并在完成后取回 output.zip
const out = await client.decrypt({ outputName: 'output', ciphertextFile, outputDirectory });
```

- `inputName` / `outputName` 必须等于 `task_config.json` 的
  `task_input_id[0]` / `task_output_id[0]`（cifar10 即 `input` / `output`）。
- `full_context.bin` 含本地私钥，**绝不上传**；只上传 `eval_context.bin`。
- 本机实测（Playwright/Chromium，cifar10）：`setup()` 约 466s（单线程）、
  `eval_context.bin` 3,329,929,205 B、`full_context.bin` 25,494,056 B、
  `encrypt` ~1.4s、`decrypt` ~0.19s，端到端与明文基准 `max|Δ| ≈ 5e-4`。

---

## 6. 一句话总结
TAA：**把公钥和密文放到约定目录 → 调 `POST /tasks` → 收回调 → 把 `output.zip` 传回 MinIO**；
FHE：**只读写这些目录、跑推理、回调通知**。
