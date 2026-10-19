# TAA ↔ FHE 对接说明

> FHE 服务**不知道对象存储（MinIO）的存在**。平台负责鉴权、存储和文件上下行；
> FHE 只做三件事：**读约定目录 → 算 → 写约定目录 + 回调**。

---

## 1. 交互流程

```
 浏览器                 TAA（平台）                         FHE 服务（本镜像）
   │                        │                                   │
   │ ① 本地生成密钥 / 加密   │                                   │
   ├───────────────────────►│                                   │
   │                        │ ② 写公钥与输入密文到共享目录        │
   │                        ├───── keys/<user>/eval_context.bin ►│
   │                        │      tasks/<task_id>/input.zip    │
   │                        │ ③ POST /api/v1/tasks ────────────►│
   │                        │                                   │ ④ 读密文做 FHE 推理
   │                        │ ⑤ HTTP 回调（完成/失败）◄──────────┤    并写
   │                        │      results/<task_id>/output.zip │
   │                        │ ⑥ 取走 output.zip 上传 MinIO       │
   │◄── ⑦ 下载结果密文 ──────┤                                   │
   │ ⑧ 本地解密             │                                   │
```

---

## 2. 目录约定（容器内 `/data`，即挂载的持久卷）

| 目录 | 谁写 | 谁读 | 说明 |
|---|---|---|---|
| `models/<model_id>/server/` | 平台/TAA | FHE | 模型资源；放入后调 `activate` 热加载 |
| `keys/<user_id>/eval_context.bin` | TAA | FHE | **一个用户一份公钥**（所有模型共用同一套参数）；FHE 只读不校验 |
| `tasks/<task_id>/input.zip` | TAA | FHE | 输入密文包 |
| `results/<task_id>/output.zip` | FHE | TAA | 结果密文包 |

> 公钥路径**不含 `model_id`**：参数统一后，同一用户的公钥对所有模型通用，所以只有 `<user_id>` 一层。

### zip 内部命名

- `input.zip`：一个密文 = 一个 case
  - 单输入模型：`<case_id>.ct`（如 `case-00.ct`）
  - 多输入模型：`<case_id>__<input_name>.ct`（如 `case-00__input.ct`）
- `output.zip`：`<case_id>.result.bin`（如 `case-00.result.bin`）

---

## 3. 接口（前缀 `/api/v1`，无鉴权；租户标识走请求头 `X-User-Id`）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 健康检查 |
| GET | `/models` | 列出已注册模型 |
| POST | `/models/activate?model_id=<id>` | 发现并热加载模型（**不重启进程**） |
| POST | `/tasks` | 创建任务 |
| GET | `/tasks/{task_id}` | 任务状态 / 各 case 进度 |
| GET | `/tasks/{task_id}/logs` | 实时运行日志（`text/plain` 流） |
| GET | `/tasks/{task_id}/events` | SSE 事件流 |
| GET | `/tasks/{task_id}/results` | 结果清单 |
| GET | `/tasks/{task_id}/results/download` | 下载 `output.zip` |
| POST | `/tasks/{task_id}/cancel` | 取消任务 |
| POST | `/tasks/{task_id}/heartbeat` | 续租（`cancel_on_disconnect` 时用） |
| POST | `/tasks/{task_id}/continue` | 重跑未完成 case（别名 `/retry`） |
| POST | `/tasks/{task_id}/delete` | 删除任务及其输入/结果 |

创建任务：

```json
{
  "user_id": "testuser",
  "model_id": "resnet20",
  "task_id": "task-abc123",
  "callback_url": "http://<taa-host>:59999/callback",
  "cancel_on_disconnect": false
}
```

任务终态后向 `callback_url` POST 一份 JSON（含 `status`、各 case 的 `entry`/`result_id`/`error`、
`result_zip` 相对路径）；失败按 0/1/4/16s 退避重试。

---

## 4. 使用步骤

```bash
# 0) 起服务（也可交给平台按 Pod 拉起，见交付包 README）
docker run -d --gpus all -p 58996:58996 -v /opt/fhe-data:/data latti/latti-server-node:latest
curl -s http://127.0.0.1:58996/api/v1/health

# 1) 放入模型（可多个），热加载
#    <model>/server/*  →  <data>/models/<model_id>/server/
curl -s -X POST 'http://127.0.0.1:58996/api/v1/models/activate?model_id=<model_id>'
curl -s http://127.0.0.1:58996/api/v1/models -H 'X-User-Id: testuser'

# 2) 写公钥（一个用户一份）
#    eval_context.bin  →  <data>/keys/<user_id>/eval_context.bin

# 3) 写输入包
#    case-*.ct 打包成  <data>/tasks/<task_id>/input.zip

# 4) 创建任务
curl -s -X POST http://127.0.0.1:58996/api/v1/tasks \
  -H 'Content-Type: application/json' -H 'X-User-Id: testuser' \
  -d '{"user_id":"testuser","model_id":"resnet20","task_id":"task-abc123",
       "callback_url":"http://<taa-host>:59999/callback","cancel_on_disconnect":false}'

# 5) 拿结果
curl -s 'http://127.0.0.1:58996/api/v1/tasks/task-abc123/results/download' \
  -H 'X-User-Id: testuser' -o output.zip
```

### 终端里看推理过程

```bash
curl -N 'http://127.0.0.1:58996/api/v1/tasks/task-abc123/logs' -H 'X-User-Id: testuser'
```

纯文本逐行追加（可直接接到 WebSocket / 终端组件），内容含 `Importing eval_context`、
`Model ... loaded`、每个 case 的进度条与 `Case ... done`、`Released GPU device memory`，
最后一行固定为 `===== task <task_id> end status=<completed|failed> =====`，然后自动断开。
`follow=false` 只回放到当前时刻。

---

## 5. 浏览器客户端与任务参数包

浏览器侧用 WASM 包，**不需要 Node，也不需要本地代理**。`client/latti-e2e-0.1.2.zip`
解压出 `latti-e2e-0.1.2/`：

```
latti-e2e-0.1.2/
├── WASM-0.1.2.zip                      # 浏览器客户端运行时（Dedicated Worker + Go/WASM）
├── resnet20-task-0.1.2.zip             # tasks/resnet20/client/（config + 前后处理 js）
├── resnet20-data-0.1.2.zip             # 10 张测试图 + label.csv
├── retina-task-degree8-02-0.1.2.zip    # tasks/retina_degree8_02/client/
├── retina-data-degree8-02-0.1.2.zip    # Retina 测试图
├── manifest.json                       # 包清单（tasks / datasets 对应关系）
└── SHA256SUMS
```

- `WASM-0.1.2.zip` 解出的 `dist/` 作为静态资源托管（`.wasm` 必须返回 `application/wasm`；
  页面须为 HTTPS 或 `http://localhost`），导入 `dist/index.js`，调
  `openBrowserClient({ clientDirectory, keyDirectory })`。密钥落在
  `keyDirectory/N16QP1546H192H32/{secret/full_context.bin, public/eval_context.bin}`
  （内置 BTP 预设 `param0`；eval ≈3.10 GiB，full ≈24.3 MiB）。
- `*-task-*.zip` 解出的 `tasks/<name>/client/` 就是 `clientDirectory`，内含
  `task_config.json`、`ckks_parameter.json`、`preprocess.js`、`postprocess.js`；
  其 `ckks_parameter.json` 与服务端模型目录逐字节一致
  （`resnet20`，sha256 `c985b737…`；
  客户端 `retina_degree8_02` ↔ 服务端 `retina`，sha256 `157248129f…`）。
- `*-data-*.zip` 是验证数据（`images/001..010.png` + `label.csv`）。

调用顺序：

```js
await preprocess_batch({ inputDirectory: imageDirectory, outputDirectory: csvDirectory });
const client = await openBrowserClient({ clientDirectory, keyDirectory });
await client.restore();                        // 首次改为 await client.setup()
const cts = await client.encrypt_batch({       // 001.csv → 001.ct.bin
  inputName: 'input', inputDirectory: csvDirectory, outputDirectory: encryptedInputDirectory });
// ① public/eval_context.bin → keys/<user_id>/eval_context.bin
// ② 每个 001.ct.bin 改名为 zip 条目 001.ct（case_id = 文件名主名），打成 input.zip
// ③ POST /tasks；完成后取回 output.zip，解出 001.result.bin
await client.decrypt_batch({                   // 001.result.bin → 001.csv
  outputName: 'output', inputDirectory: encryptedResultDirectory, outputDirectory: logitsDirectory });
await client.close();
```

- `inputName` / `outputName` 必须等于 `task_config.json` 的 `task_input_id[0]` /
  `task_output_id[0]`（`resnet20` 即 `input` / `output`；`retina` 是多输入，
  `input_0` / `input_1` / `input_2`，zip 条目为 `<case_id>__<input_name>.ct`）。
- 磁盘命名：`001.png → 001.csv → 001.ct.bin → 001.csv`；批量接口只读所选目录**根层**的
  `.csv`（加密）/ `.ct.bin`（解密），按文件名字符串顺序处理。
- `full_context.bin` 含本地私钥，**绝不上传**；只上传 `eval_context.bin`。

---

## 6. 一句话总结

TAA：**把公钥和密文放进约定目录 → 调 `POST /tasks` → 收回调 → 取走 `output.zip`**；
FHE：**只读写这些目录、跑推理、回调通知**。
