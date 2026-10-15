# 实施计划：模型下发改用 URL 密钥信封

日期：2026-10-14
对应 spec：`.claude/specs/2026-10-14-model-import-url-key-cipher-design.md`
分支：`feat/import-model-url-key`（基于数据侧分支 `feat/import-url-key-envelope`）

## 步骤

1. **抽出共享解析**：`internal/controller/import_urlkey.go` 新增
   `unwrapDataKeyCipherFromURL`，把数据侧 `importHandler` 里内联的
   「`SplitDataKeyCipher` → `ParseWrappedDataKeyHex` → `UnwrapKeySM2`」搬进去，
   错误文本逐字保持（`dataKeyCipher 解封失败: ` 前缀由 helper 补）。
2. **数据 handler 改用 helper**：`importHandler` 只留一次调用 + 400 分支，行为等价。
3. **模型 handler 接入**：
   - 解析放在请求字段校验之后、`hasSavedModel()`/phase1 公钥/`ModelImported`/下载之前；
   - 解析后 `req.ResourceURL = <剥离后 URL>`，使下载、日志、legacy 解析分支与异步成功路径
     的记录写入都拿到同一个（不含信封的）URL；
   - `processImportedResource(..., dataKey)` 取代 `nil`。
4. **新增测试** `internal/controller/import_model_urlkey_test.go`：端到端、下载前拦截、
   legacy 回退、异步失败上报四类（见 spec §6）。
5. **文档同步**：`docs/api-design.md`、`docs/architecture-design.md`、`api/openapi.yaml`、
   `README.md`；数据侧 spec 的非目标一行标注被取代。
6. **收尾**：spec/plan 落 `.claude/`（`.claude/` 在 .gitignore 里，入库需 `git add -f`）；
   Conventional Commits、英文、无任何 AI 署名。

## 验收

- `go build ./...` 通过；
- `go test ./internal/controller/ ./internal/resource/ ./pkg/crypto/ ./tools/platform-mock/...` 全绿；
- 新增 4 个测试在**去掉改造**（`processImportedResource(..., nil)` 且不解析 URL）时失败——
  即测试确实钉住了新行为；
- 数据侧既有测试（含 `import_urlkey_test.go` 的全部断言）保持不变并通过，证明抽取 helper
  没有改变对外文案与错误码；
- 未跑真实平台联调（需要 172.16.10.178 的 Pod 与平台侧配合），由用户侧验证。

## 验证记录

1. `go build ./...` 通过；`gofmt -l` 对本次改动的三个 Go 文件无输出。
2. 回归（本次改动涉及的全部包，一次跑完）：

   ```
   ok  taa/internal/controller            18.392s
   ok  taa/internal/resource               0.129s
   ok  taa/pkg/crypto                      0.061s
   ok  taa/tools/platform-mock/internal    0.696s
   ```

   其中数据侧 `import_urlkey_test.go` 未改一行且全过，说明把内联块抽成
   `unwrapDataKeyCipherFromURL` 没有改变状态码、错误码与文案。
3. 变异校验（证明新测试钉住的是新行为，不是恒真）：

   | 变异 | 结果 |
   | --- | --- |
   | 模型 handler 把 `dataKey` 丢掉（`processImportedResource(..., nil)`，即等价于功能关闭） | `TestModelImportDecryptsWithDataKeyCipherFromURL` **FAIL**（`decrypted model archive was not extracted into .../models`）；恢复后 PASS |
   | 不写回 `req.ResourceURL`（保留原始带信封的 URL） | `TestModelImportDecryptsWithDataKeyCipherFromURL` **FAIL**（`saved model URL = "...?sign=a%2Fb&dataKeyCipher=330fee..."`）；这正是改造过程中真实出现过的一次失败，写回后修复 |
   | 去掉「剥离后为空」的拦截（`if false && ...`） | `TestModelImportRejectsKeyEnvelopeWithoutDownloadAddress` **FAIL**（`status=200 ... msg=模型参数命令已导入，等待数据重新导入后执行训练, want 400`）——即请求带着密钥被静默丢弃；恢复后 PASS。该拦截来自对抗性评审的 F3，属新增修复 |

4. 未做：真实平台联调（需要 172.16.10.178 上的 Pod 与平台侧配合下发一个带
   `?dataKeyCipher=` 的模型 URL），由用户侧验证。

5. 已知与本改动无关：`TestConcurrency_DataImportAllowedWhileAuditing` 偶发失败
   （`TempDir RemoveAll cleanup: ... results: directory not empty`，异步流水线活过
   `t.TempDir()` 清理），本轮 4 次运行中命中 1 次，属既有已知抖动，非本次引入。


## 2026-10-15 追加：版本布局的配套

解密侧的版本布局兼容（`route.go` 的 `decryptCiphertextWithDataKey`）由 `913b54f`
落到主分支，但当时只有单元测试背书，缺两处配套；本次补齐。

| 改动 | 文件 | 理由 |
| --- | --- | --- |
| 版本号常量上提到共享包 | `pkg/crypto/sm4.go` 新增 `SM4FileVersion`；`internal/controller/route.go` 删掉本地 `sm4FileVersion`，改用 `teecrypto.SM4FileVersion` | 生产端（mock）与消费端（TAA）此后共用同一处定义，不会各写一份再漂移 |
| mock 按生产布局产出 | `tools/platform-mock/internal/handlers_upload.go` 的 `urlkey` 模式写 `版本(1) ‖ nonce ‖ 密文 ‖ tag` | 此前 mock 写无版本布局，本地端到端跑的不是生产格式，兼容代码在联调里从未被执行 |
| mock 用例跟上 | `tools/platform-mock/internal/server_test.go` 的 urlkey 用例：长度断言 +1，并断言首字节为版本号、去掉首字节后可解出明文 | 让 mock 的产出格式有断言钉住，而不是靠注释 |
| 数据路径补用例 | `internal/controller/import_urlkey_test.go` 新增 `TestImportAcceptsVersionedSm4File` | 生产上真正在跑的是数据下发；此前版本布局只有模型端点的用例 |

验证：

- `go build`（`CGO_ENABLED=0 GOOS=linux` 静态构建 TAA、mock）通过；`gofmt -l` 对本次改动的
  文件无输出（列出的 `attestation_format.go` 等为既有未格式化文件，非本次引入）。
- 回归：`internal/controller` ok、`pkg/crypto` ok、`tools/platform-mock/internal` ok。
- 变异校验：把重试条件改为恒假（`if false && err != nil && ...`）后，
  `TestImportAcceptsVersionedSm4File` 与 `TestModelImportAcceptsVersionedSm4File` 同时 FAIL
  （`解密失败(密钥错误或数据被篡改): cipher: message authentication failed`），恢复后 PASS。
