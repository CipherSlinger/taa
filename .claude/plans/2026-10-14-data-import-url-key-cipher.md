# 数据下发 URL 密钥信封协议 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 `/v1/taa/import` 支持新协议——`resourceUrl` 形如 `<下载链接>?dataKeyCipher=<hex>`，下载链接只含 SM4-GCM 密文，密钥信封从 URL 参数取得；未携带该参数时完全回退到现有逻辑。

**Architecture:** 解析与剥离放在 `internal/resource`（纯字符串处理，不改写其余 query 参数）；hex 布局兼容放在 `pkg/crypto`（`SM2WrappedKeySize` 与 `0x04` 前缀的定义处）；控制器在同步段解析并**提前解封**得到 16 字节数据密钥，把 `dataKey` 显式传给异步解密路径，非空走新分支、空则调现有 `resolvePlaintextResource` 回退。platform-mock 增加 `urlkey` 上传模式以便本地联调。

**Tech Stack:** Go 1.22，标准库 `net/url` 不用于重编码（逐段字符串处理），国密 SM2/SM4-GCM 走 `pkg/crypto`（底层 `github.com/tjfoc/gmsm`）。

**Spec:** `.claude/specs/2026-10-14-data-import-url-key-cipher-design.md`

**Worktree:** `.claude/worktrees/import-url-key-envelope`，分支 `feat/import-url-key-envelope`。所有命令都在该目录下执行。

**环境注记（本 worktree 特有，勿提交）：**
- `go.work` 被 `.git/info/exclude` 排除，本 worktree 已手工补一份（内容与主检出一致），**不要 `git add` 它**。
- `teellm` 与 `teellm/teetls` 子模块已从本地对象库克隆到 pinned commit；不要跑 `git submodule update`，远端没有那两个 commit。

---

## File Structure

| 文件 | 职责 | 动作 |
| --- | --- | --- |
| `internal/resource/urlkey.go` | 从资源 URL 剥离 `dataKeyCipher`，返回可下载 URL 与 hex 值 | 新建 |
| `internal/resource/urlkey_test.go` | 上述函数的 `t.Run` 子测试（含错误分支的文案断言） | 新建 |
| `pkg/crypto/seal.go` | 新增 `ParseWrappedDataKeyHex`（hex → 113B 信封，兼容两种布局） | 修改 |
| `pkg/crypto/wrappedkey_test.go` | 上述函数的 `t.Run` 子测试 | 新建 |
| `internal/controller/route.go` | 新增 `decryptCiphertextWithDataKey`（数据密钥 + 纯密文文件 → 明文临时文件） | 修改 |
| `internal/controller/import_processing.go` | `processImportedResource` 增加 `dataKey` 参数；新增 `resolvePlaintextResourceWithDataKey`；新增解密分支 | 修改 |
| `internal/controller/handler_task.go` | `importHandler` 解析 URL、提前解封、传参；`modelImportHandler` 传 `nil` | 修改 |
| `internal/controller/import_urlkey_test.go` | 新协议端到端、下载前拦截、回退与范围护栏 | 新建 |
| `tools/platform-mock/internal/handlers_upload.go` | `encryptMode` 三态；`urlkey` 模式只写密文、信封进 URL | 修改 |
| `tools/platform-mock/internal/store.go` | `uploadedFileRecord` 增加 `dataKeyCipher` | 修改 |
| `tools/platform-mock/internal/server_test.go` | `urlkey` 上传往返测试 | 修改 |
| `tools/platform-mock/internal/static/index.html` | 加密开关换成三选一下拉 | 修改 |
| `tools/platform-mock/internal/static/js/app.js` | 上传时按模式提交 `encryptMode` 并展示信封 | 修改 |
| `docs/api-design.md` | §4.2 补 `dataKeyCipher` 规格 | 修改 |
| `api/openapi.yaml` | `/v1/taa/import` 描述与 `resourceUrl` 注释 | 修改 |
| `docs/architecture-design.md` | §5.2 解密段描述 | 修改 |

---

### Task 1: URL 解析与剥离

**Files:**
- Create: `internal/resource/urlkey.go`
- Test: `internal/resource/urlkey_test.go`

- [x] **Step 1: 写失败测试**

创建 `internal/resource/urlkey_test.go`：

```go
package resource

import "testing"

func TestSplitDataKeyCipher(t *testing.T) {
	const hexValue = "04aabbcc"

	t.Run("no query string leaves the URL untouched", func(t *testing.T) {
		raw := "http://host/files/data.sm4"
		clean, hex, found, err := SplitDataKeyCipher(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found {
			t.Fatalf("found = true, want false")
		}
		if clean != raw {
			t.Fatalf("clean = %q, want %q", clean, raw)
		}
		if hex != "" {
			t.Fatalf("hex = %q, want empty", hex)
		}
	})

	t.Run("sole parameter is stripped and the query mark is dropped", func(t *testing.T) {
		clean, hex, found, err := SplitDataKeyCipher("http://host/files/data.sm4?dataKeyCipher=" + hexValue)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found || hex != hexValue {
			t.Fatalf("found=%v hex=%q, want true/%q", found, hex, hexValue)
		}
		if clean != "http://host/files/data.sm4" {
			t.Fatalf("clean = %q", clean)
		}
	})

	t.Run("other parameters keep their order and escaping", func(t *testing.T) {
		raw := "http://host/files/data.sm4?sign=a%2Fb&dataKeyCipher=" + hexValue + "&expires=99"
		clean, hex, found, err := SplitDataKeyCipher(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found || hex != hexValue {
			t.Fatalf("found=%v hex=%q", found, hex)
		}
		want := "http://host/files/data.sm4?sign=a%2Fb&expires=99"
		if clean != want {
			t.Fatalf("clean = %q, want %q", clean, want)
		}
	})

	t.Run("fragment is preserved", func(t *testing.T) {
		clean, _, found, err := SplitDataKeyCipher("http://host/f.sm4?dataKeyCipher=" + hexValue + "#part")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !found || clean != "http://host/f.sm4#part" {
			t.Fatalf("found=%v clean=%q", found, clean)
		}
	})

	t.Run("a parameter whose value merely contains the name is left alone", func(t *testing.T) {
		raw := "http://host/f.sm4?sign=dataKeyCipher"
		clean, _, found, err := SplitDataKeyCipher(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if found || clean != raw {
			t.Fatalf("found=%v clean=%q, want false/%q", found, clean, raw)
		}
	})

	t.Run("duplicate parameter is rejected", func(t *testing.T) {
		_, _, _, err := SplitDataKeyCipher("http://host/f.sm4?dataKeyCipher=aa&dataKeyCipher=bb")
		if err == nil {
			t.Fatal("expected error for duplicate parameter")
		}
	})

	t.Run("empty value is rejected", func(t *testing.T) {
		_, _, _, err := SplitDataKeyCipher("http://host/f.sm4?dataKeyCipher=")
		if err == nil {
			t.Fatal("expected error for empty value")
		}
	})
}
```

- [x] **Step 2: 跑测试确认失败**

Run: `go test ./internal/resource/ -run TestSplitDataKeyCipher -v`
Expected: 编译失败，`undefined: SplitDataKeyCipher`

- [x] **Step 3: 实现**

创建 `internal/resource/urlkey.go`：

```go
package resource

import (
	"fmt"
	"strings"
)

// dataKeyCipherParam is the query parameter that carries the SM2 data key envelope
// on a data-delivery resource URL.
const dataKeyCipherParam = "dataKeyCipher"

// SplitDataKeyCipher strips the dataKeyCipher parameter from a resource URL and
// returns the downloadable URL together with the parameter's raw hex value.
//
// found is false when the URL carries no such parameter; the caller then falls
// back to the legacy format. Only two cases return an error: the parameter
// appears more than once (which one to use would be ambiguous), or its value is
// empty.
//
// The strip is segment-by-segment string surgery: the bytes, order and escaping
// of every other query segment are preserved verbatim, so a signed download URL
// is never rewritten.
func SplitDataKeyCipher(rawURL string) (cleanURL, hexValue string, found bool, err error) {
	base, query, fragment := splitURLParts(rawURL)
	if query == "" {
		return rawURL, "", false, nil
	}

	segments := strings.Split(query, "&")
	kept := make([]string, 0, len(segments))
	for _, seg := range segments {
		eq := strings.Index(seg, "=")
		key := seg
		if eq >= 0 {
			key = seg[:eq]
		}
		if key != dataKeyCipherParam {
			kept = append(kept, seg)
			continue
		}
		if found {
			return "", "", false, fmt.Errorf("URL 中 %s 参数重复出现，无法判定使用哪一个", dataKeyCipherParam)
		}
		value := ""
		if eq >= 0 {
			value = seg[eq+1:]
		}
		if value == "" {
			return "", "", false, fmt.Errorf("URL 中 %s 参数值为空", dataKeyCipherParam)
		}
		found = true
		hexValue = value
	}
	if !found {
		return rawURL, "", false, nil
	}

	clean := base
	if len(kept) > 0 {
		clean += "?" + strings.Join(kept, "&")
	}
	return clean + fragment, hexValue, true, nil
}

// splitURLParts cuts a URL into base, query and fragment (the fragment keeps its
// leading '#'). An empty query means the URL has no query part.
func splitURLParts(rawURL string) (base, query, fragment string) {
	rest := rawURL
	if i := strings.Index(rest, "#"); i >= 0 {
		fragment = rest[i:]
		rest = rest[:i]
	}
	if i := strings.Index(rest, "?"); i >= 0 {
		return rest[:i], rest[i+1:], fragment
	}
	return rest, "", fragment
}
```

- [x] **Step 4: 跑测试确认通过**

Run: `go test ./internal/resource/ -run TestSplitDataKeyCipher -v`
Expected: `--- PASS: TestSplitDataKeyCipher` 及全部子测试 PASS

- [x] **Step 5: 提交**

```bash
git add internal/resource/urlkey.go internal/resource/urlkey_test.go
git commit -m "feat(resource): split the data key cipher out of a resource URL"
```

> **执行记录（2026-10-14）**：已实现并提交 `eb886af`。代码质量审查提出两条 Important，均已修：
> 1. `SplitDataKeyCipher` 的文档补上"出错时三个返回值均为零值，调用方必须先查 `err` 再查 `found`"——
>    否则下游若只判 `found`，就会静默回退到 legacy，带着仍含 `dataKeyCipher` 的 URL 去下载。
> 2. 原测试对两个错误分支无判别力（对调错误文案后仍全绿），且 `?dataKeyCipher`（无 `=`）
>    这条分支零覆盖。现三个错误子测试各自断言文案（"重复"／"值为空"），子测试共 8 个；
>    已用对调文案实验验证：对调后三个错误子测试全部失败，还原后通过（复查代理独立复现，并逐字节核验还原）。
>
> 审查另建议给提交加归属尾行（`Co-Authored-By`），与本项目规则冲突，未采纳。

---

### Task 2: 信封 hex 解析（两种布局）

**Files:**
- Modify: `pkg/crypto/seal.go`
- Test: `pkg/crypto/wrappedkey_test.go`

- [x] **Step 1: 写失败测试**

创建 `pkg/crypto/wrappedkey_test.go`：

```go
package crypto

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseWrappedDataKeyHex(t *testing.T) {
	priv, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	dataKey, err := GenerateSM4Key()
	if err != nil {
		t.Fatalf("GenerateSM4Key: %v", err)
	}
	wrapped, err := WrapKeySM2(&priv.PublicKey, dataKey)
	if err != nil {
		t.Fatalf("WrapKeySM2: %v", err)
	}
	if len(wrapped) != SM2WrappedKeySize {
		t.Fatalf("wrapped length = %d, want %d", len(wrapped), SM2WrappedKeySize)
	}

	t.Run("112 bytes without the prefix gets it restored", func(t *testing.T) {
		got, err := ParseWrappedDataKeyHex(hex.EncodeToString(wrapped[1:]))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != string(wrapped) {
			t.Fatalf("restored envelope differs from the original")
		}
	})

	t.Run("113 bytes with the prefix is accepted as-is", func(t *testing.T) {
		got, err := ParseWrappedDataKeyHex(hex.EncodeToString(wrapped))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(got) != string(wrapped) {
			t.Fatalf("envelope differs from the original")
		}
	})

	t.Run("the parsed envelope unwraps back to the data key", func(t *testing.T) {
		got, err := ParseWrappedDataKeyHex(hex.EncodeToString(wrapped[1:]))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		key, err := UnwrapKeySM2(priv, got)
		if err != nil {
			t.Fatalf("UnwrapKeySM2: %v", err)
		}
		if string(key) != string(dataKey) {
			t.Fatalf("unwrapped key differs from the original")
		}
	})

	t.Run("113 bytes with a wrong first byte is rejected", func(t *testing.T) {
		bad := append([]byte{0x03}, wrapped[1:]...)
		_, err := ParseWrappedDataKeyHex(hex.EncodeToString(bad))
		if err == nil {
			t.Fatal("expected error for a 113-byte envelope without the 0x04 prefix")
		}
	})

	t.Run("wrong lengths are rejected", func(t *testing.T) {
		for _, n := range []int{0, 111, 114} {
			if _, err := ParseWrappedDataKeyHex(hex.EncodeToString(make([]byte, n))); err == nil {
				t.Fatalf("length %d: expected error", n)
			}
		}
	})

	t.Run("invalid hex is rejected", func(t *testing.T) {
		if _, err := ParseWrappedDataKeyHex("zz"); err == nil {
			t.Fatal("expected error for invalid hex")
		}
		if _, err := ParseWrappedDataKeyHex("abc"); err == nil {
			t.Fatal("expected error for odd-length hex")
		}
	})

	t.Run("the error message carries the offending length", func(t *testing.T) {
		_, err := ParseWrappedDataKeyHex(hex.EncodeToString(make([]byte, 114)))
		if err == nil || !strings.Contains(err.Error(), "114") {
			t.Fatalf("err = %v, want it to mention 114", err)
		}
	})
}
```

- [x] **Step 2: 跑测试确认失败**

Run: `go test ./pkg/crypto/ -run TestParseWrappedDataKeyHex -v`
Expected: 编译失败，`undefined: ParseWrappedDataKeyHex`

- [x] **Step 3: 实现**

在 `pkg/crypto/seal.go` 的 import 块加入 `"encoding/hex"`（其余保持不变）：

```go
import (
	"encoding/hex"
	"errors"
	"fmt"
)
```

在 `OpenSM2SM4GCM` 之后追加：

```go
// sm2CipherPointPrefix is the leading byte of the uncompressed point C1 in an
// SM2 ciphertext.
const sm2CipherPointPrefix = 0x04

// ParseWrappedDataKeyHex decodes a hex-encoded SM2 data key envelope and returns
// an SM2WrappedKeySize byte envelope ready for UnwrapKeySM2.
//
// The platform may deliver either layout: 112 bytes (C1 || C3 || C2, without the
// uncompressed point prefix) or 113 bytes (with the 0x04 prefix). The former gets
// the prefix restored, the latter is accepted as-is.
func ParseWrappedDataKeyHex(hexValue string) ([]byte, error) {
	raw, err := hex.DecodeString(hexValue)
	if err != nil {
		return nil, fmt.Errorf("teecrypto: 数据密钥信封不是合法 hex: %w", err)
	}
	switch len(raw) {
	case SM2WrappedKeySize - 1:
		wrapped := make([]byte, 0, SM2WrappedKeySize)
		wrapped = append(wrapped, sm2CipherPointPrefix)
		return append(wrapped, raw...), nil
	case SM2WrappedKeySize:
		if raw[0] != sm2CipherPointPrefix {
			return nil, fmt.Errorf("teecrypto: 数据密钥信封首字节为 0x%02x，应为 0x%02x", raw[0], sm2CipherPointPrefix)
		}
		return raw, nil
	default:
		return nil, fmt.Errorf("teecrypto: 数据密钥信封长度无效: %d 字节（应为 %d 或 %d）",
			len(raw), SM2WrappedKeySize-1, SM2WrappedKeySize)
	}
}
```

- [x] **Step 4: 跑测试确认通过**

Run: `go test ./pkg/crypto/ -run TestParseWrappedDataKeyHex -v`
Expected: 全部子测试 PASS

- [x] **Step 5: 提交**

```bash
git add pkg/crypto/seal.go pkg/crypto/wrappedkey_test.go
git commit -m "feat(crypto): parse a hex data key envelope in either layout"
```

> **执行记录（2026-10-14）**：已实现并提交 `4269bb5`。规格审查逐字节比对一致、无多余无遗漏。
> 代码质量审查结论为可合并，无 Critical／Important；两处变异实验（112 字节分支补错前缀、default 分支返回 raw）均被测试捕获。
>
> 审查暴露一个不显然的依赖事实，已补进文档注释：**gmsm v1.4.1 的 `sm2.Decrypt` 无条件执行 `data = data[1:]`，从不校验第 0 字节**
> （`sm2.go:314-333` 各分支皆如此），因此「能 unwrap」不能证明前缀补对了——实测把 112 分支改成补 `0x03`，
> 往返子测试依然通过。`seal.go` 里那句 `raw[0] != sm2CipherPointPrefix` 是全仓库对该值**唯一**的前缀闸门，
> 注释已写明，避免后人误以为 `UnwrapKeySM2` 会兜底而删掉字节相等断言。
>
> 未采纳的 Minor：把 `sm2.go:307/314` 的 `4` 字面量换成新常量（超出本任务文件范围）；
> 解码前置长度检查（会把 `"zzzz"` 从「非 hex」误判为「长度错」，诊断力下降）；长度循环改 `t.Errorf`
> （首个失败之后才多出输出，三种长度本就都能被捕获）。

---

### Task 3: 控制器解密链路与端到端打通

**Files:**
- Modify: `internal/controller/route.go`（import 块 + `decryptResourceToTempFile` 之后）
- Modify: `internal/controller/import_processing.go:26-45`
- Modify: `internal/controller/handler_task.go`（import 块、`importHandler`、`modelImportHandler`）
- Test: `internal/controller/import_urlkey_test.go`（新建）

- [x] **Step 1: 写失败测试**

创建 `internal/controller/import_urlkey_test.go`：

```go
package controller

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	teecrypto "taa/pkg/crypto"
)

// urlKeyResource seals a plaintext archive into the new shape: the envelope goes
// into the URL, the ciphertext is downloaded on its own.
func urlKeyResource(t *testing.T, pub *teecrypto.SM2PublicKey, plaintext []byte) (ciphertext []byte, hexValue string) {
	t.Helper()
	env, err := teecrypto.SealSM2(pub, plaintext)
	if err != nil {
		t.Fatalf("SealSM2: %v", err)
	}
	return env.Ciphertext, hex.EncodeToString(env.WrappedKey[1:])
}

func TestImportDecryptsWithDataKeyCipherFromURL(t *testing.T) {
	state, server := setupTestServer(t)

	archive := buildTarGzArchive(t, map[string]archiveEntry{
		"data/sample.txt": {mode: 0o644, data: []byte("training data\n")},
	})
	ciphertext, keyHex := urlKeyResource(t, &state.SM2PrivateKey.PublicKey, archive)

	var hits int32
	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if got := r.URL.Query().Get("dataKeyCipher"); got != "" {
			t.Errorf("download URL must not carry dataKeyCipher, got %q", got)
		}
		if got := r.URL.Query().Get("sign"); got != "a/b" {
			t.Errorf("sign = %q, want %q (other parameters must survive)", got, "a/b")
		}
		_, _ = w.Write(ciphertext)
	}))
	defer fileServer.Close()

	resourceURL := fileServer.URL + "/data.sm4?sign=a%2Fb&dataKeyCipher=" + keyHex

	resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": resourceURL,
		"requestId":   "req-urlkey-ok",
		"taskId":      "task-urlkey-ok",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("import: status=%d error=%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}

	waitForIdle(t, state)

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("download hits = %d, want 1", got)
	}

	sum := teecrypto.SM3Sum(archive)
	dataDir := filepath.Join(state.Security.DataDir, hex.EncodeToString(sum[:]))
	if _, err := os.Stat(filepath.Join(dataDir, "data", "sample.txt")); err != nil {
		t.Fatalf("decrypted archive was not extracted into %s: %v", dataDir, err)
	}
}
```

- [x] **Step 2: 跑测试确认失败**

Run: `go test ./internal/controller/ -run TestImportDecryptsWithDataKeyCipherFromURL -v`
Expected: FAIL —— `resourceUrl` 被原样下载，服务端收到 `dataKeyCipher` 参数且响应体是纯密文，解密失败，数据目录不存在

- [x] **Step 3: 新增按数据密钥解密的函数**

在 `internal/controller/route.go` 的 import 块加入 `"errors"`（其余不变）：

```go
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"taa/internal/codeaudit"
	"taa/internal/config"
	"taa/internal/resource"
	"taa/internal/runtime"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
)
```

在 `decryptResourceToTempFile` 函数之后追加：

```go
// decryptCiphertextWithDataKey decrypts a ciphertext-only resource file with an
// SM4 data key supplied from outside.
//
// Unlike decryptResourceToTempFile there is no SM2 key envelope prefix inside the
// file: the envelope came from the dataKeyCipher parameter of the delivery URL and
// was already unwrapped into dataKey upstream. The plaintext is written to a temp
// file whose path is returned; the caller removes it.
func (s *TAAState) decryptCiphertextWithDataKey(dataKey []byte, ciphertextPath string) (string, error) {
	f, err := os.Open(ciphertextPath)
	if err != nil {
		return "", fmt.Errorf("打开密文文件: %w", err)
	}
	defer f.Close()

	ciphertext, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("读取密文: %w", err)
	}
	if len(ciphertext) == 0 {
		return "", errors.New("密文为空")
	}

	plaintext, err := teecrypto.Decrypt(dataKey, ciphertext)
	ciphertext = nil // 及时释放密文内存
	if err != nil {
		return "", err
	}

	out, err := os.CreateTemp("", "taa-plaintext-*")
	if err != nil {
		plaintext = nil
		return "", fmt.Errorf("创建明文临时文件: %w", err)
	}
	plainPath := out.Name()
	if _, err := out.Write(plaintext); err != nil {
		_ = out.Close()
		_ = os.Remove(plainPath)
		plaintext = nil
		return "", fmt.Errorf("写入明文临时文件: %w", err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(plainPath)
		return "", fmt.Errorf("关闭明文临时文件: %w", err)
	}
	return plainPath, nil
}
```

- [x] **Step 4: 新增按数据密钥解密的判定包装**

在 `internal/controller/import_processing.go` 中，紧跟 `resolvePlaintextResource` 之后追加：

```go
// resolvePlaintextResourceWithDataKey resolves a ciphertext-only resource using the
// data key envelope carried by the delivery URL.
//
// It sits next to the legacy path in resolvePlaintextResource. The envelope was
// already unwrapped into dataKey by the caller during the synchronous phase, and
// there is no archive-magic probing here: carrying an envelope declares the payload
// to be ciphertext, so failing to open it is a failure and never a silent
// re-classification as plaintext. The error carries the TAA public key so the
// platform can tell which key should have wrapped the envelope.
func (s *TAAState) resolvePlaintextResourceWithDataKey(dataKey []byte, ciphertextPath string) (string, bool, error) {
	decryptedPath, err := s.decryptCiphertextWithDataKey(dataKey, ciphertextPath)
	if err != nil {
		s.Logs.Add(LogError, "decrypt", "数据密钥解密失败: %v", err)
		if pubKey := s.getTAAPublicKeyPEM(); pubKey != "" {
			return "", false, pkgerrors.Wrap(pkgerrors.CodeInternal,
				fmt.Sprintf("解密资源失败: %v, taaPublicKey: %s", err, pubKey), err)
		}
		return "", false, pkgerrors.Wrap(pkgerrors.CodeInternal, fmt.Sprintf("解密资源失败: %v", err), err)
	}
	s.Logs.Add(LogInfo, "decrypt", "使用 URL 携带的数据密钥信封解密成功 -> %s", decryptedPath)
	return decryptedPath, true, nil
}
```

- [x] **Step 5: 让异步段接受数据密钥**

在 `internal/controller/import_processing.go` 中，把函数签名改为：

```go
func (s *TAAState) processImportedResource(req importRequest, phase int, isModel bool, ciphertextPath string, dataKey []byte) {
```

并把解密步骤：

```go
	StepSeparator("Decrypt")
	s.setCurrentOp("decrypting")
	plaintextPath, isDecrypted, err := s.resolvePlaintextResource(req.ResourceURL, ciphertextPath, "decrypt")
```

替换为：

```go
	StepSeparator("Decrypt")
	s.setCurrentOp("decrypting")
	var plaintextPath string
	var isDecrypted bool
	var err error
	if len(dataKey) > 0 {
		plaintextPath, isDecrypted, err = s.resolvePlaintextResourceWithDataKey(dataKey, ciphertextPath)
	} else {
		plaintextPath, isDecrypted, err = s.resolvePlaintextResource(req.ResourceURL, ciphertextPath, "decrypt")
	}
```

（紧随其后的 `if err != nil { ... }` 块保持不变。）

- [x] **Step 6: 同步段解析 URL 并提前解封**

在 `internal/controller/handler_task.go` 的 import 块加入 resource 包：

```go
import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"taa/internal/resource"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
)
```

在 `importHandler` 中，紧跟「requestId 和 taskId 不能同时为空」校验之后插入：

```go
	// Encrypted data resources use the shape "envelope in the URL, ciphertext
	// downloaded on its own": resourceUrl looks like
	// <download link>?dataKeyCipher=<hex C1C3C2>.
	// The envelope is unwrapped before the download, so a malformed value or a key
	// mismatch surfaces without first pulling the whole ciphertext.
	downloadURL, dataKeyCipherHex, hasDataKeyCipher, err := resource.SplitDataKeyCipher(req.ResourceURL)
	if err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, err.Error(), err))
		return
	}
	var dataKey []byte
	if hasDataKeyCipher {
		wrapped, err := teecrypto.ParseWrappedDataKeyHex(dataKeyCipherHex)
		if err != nil {
			writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, err.Error(), err))
			return
		}
		dataKey, err = teecrypto.UnwrapKeySM2(s.SM2PrivateKey, wrapped)
		if err != nil {
			writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument,
				fmt.Sprintf("dataKeyCipher 解封失败: %v", err), err))
			return
		}
	}
```

随后把下载调用与日志改为使用剥离后的 URL：

```go
	s.Logs.Add(LogInfo, "import", "开始下载资源: %s", downloadURL)
	ciphertextPath, size, err := s.downloadToTempFile(downloadURL)
```

（`downloadURL` 不含 `dataKeyCipher`，因此信封不会进日志或导入索引；`req.ResourceURL` 保持原值不再用于下载。）

最后把异步调用改为传递数据密钥：

```go
	s.runAsyncSafe("processImportedResource", release, func() {
		s.processImportedResource(req, phase, false, ciphertextPath, dataKey)
	})
```

在 `modelImportHandler` 中，模型下发仍走整文件信封，异步调用改为传 `nil`：

```go
	s.runAsyncSafe("processImportedResource", release, func() {
		s.processImportedResource(req, phase, true, ciphertextPath, nil)
	})
```

- [x] **Step 7: 跑测试确认通过**

Run: `go test ./internal/controller/ -run TestImportDecryptsWithDataKeyCipherFromURL -v`
Expected: PASS

- [x] **Step 8: 跑相关包回归**

Run: `go test ./internal/controller/ ./internal/resource/ ./pkg/crypto/ 2>&1 | tail -5`
Expected: 三个包全 `ok`

- [x] **Step 9: 提交**

```bash
git add internal/controller/route.go internal/controller/import_processing.go internal/controller/handler_task.go internal/controller/import_urlkey_test.go
git commit -m "feat(import): decrypt data resources with the URL-carried key envelope"
```

> **执行记录（2026-10-14）**：已实现并提交 `6ea68c1`（4 文件，+180/-6）。规格审查逐字符一致，并单独核验了解析块的 `err` 绑定非遮蔽（函数级声明，后续 `release, err :=` 复用而非重声明）。
>
> 质量审查结论「可合并」，**生产代码零缺陷**，三条指定变异（下载改用 `req.ResourceURL`、异步段传 `nil`、`hasDataKeyCipher` 体置空）全部被测试拦住，各自还原后哈希逐位一致。已核：FD 与临时文件在所有早退路径都不泄漏（明文临时文件 0600）；`dataKey` 与信封 hex 不进日志、不进导入索引、不进响应体；解封位于 `tryAcquireTask` 之前无 TOCTOU、失败请求不占槽也不泄漏 `release`。
>
> **唯一一条 Important 是覆盖缺口，正是 Task 4 的内容**：三条「下载前拒绝」分支（split 报错、hex/长度非法、解封失败）在本提交尚无测试，审查者另跑的两条变异（`if err != nil` → `if false`、删掉解封错误分支）当时都没能让测试失败。Task 4 的表驱动测试必须让这两条变异转为失败——这是 Task 4 的验收标准，不只是"跑绿"。
>
> 未采纳的 Minor：`dataKey` 未清零（全仓库对使用后的密钥都不擦除，`= nil` 只是释放内存而非擦除，加了反而制造"已擦除"的错觉）；`decryptCiphertextWithDataKey` 挂在 `*TAAState` 上不用 `s`；`logScope` 写死为 `"decrypt"`（均为观感，无行为影响）。
>
> 相邻观察（非本提交缺陷）：`handler_system.go:216/219-220` 的 `getResourceInfo` 会把原始 `resourceUrl` 整条写进日志并原样下载。新形态限定在 `/v1/taa/import` 是刻意设计，Task 7 的文档已如实写明该端点会把参数转发出去并失败。

---

### Task 4: 下载前拦截与回退护栏

**Files:**
- Test: `internal/controller/import_urlkey_test.go`（追加）

- [x] **Step 1: 写失败测试**

在 `internal/controller/import_urlkey_test.go` 追加：

```go
func TestImportRejectsBadDataKeyCipherBeforeDownloading(t *testing.T) {
	state, server := setupTestServer(t)
	_ = state

	var hits int32
	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte("ciphertext"))
	}))
	defer fileServer.Close()

	cases := []struct {
		name      string
		query     string
		wantInMsg string
	}{
		{"duplicate parameter", "?dataKeyCipher=aa&dataKeyCipher=bb", "重复出现"},
		{"empty value", "?dataKeyCipher=", "值为空"},
		{"invalid hex", "?dataKeyCipher=zz", "hex"},
		{"wrong length", "?dataKeyCipher=0011", "长度无效"},
		{"envelope for another key", "?dataKeyCipher=" + otherKeyEnvelopeHex(t), "解封失败"},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			atomic.StoreInt32(&hits, 0)
			id := fmt.Sprintf("urlkey-reject-%d", i)
			resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
				"resourceUrl": fileServer.URL + "/data.sm4" + tc.query,
				"requestId":   "req-" + id,
				"taskId":      "task-" + id,
			})
			api := decodeResponse(t, resp)
			if resp.StatusCode != http.StatusBadRequest || api.Error == 0 {
				t.Fatalf("status=%d error=%d msg=%s, want 400", resp.StatusCode, api.Error, api.Msg)
			}
			if !strings.Contains(api.Msg, tc.wantInMsg) {
				t.Fatalf("msg = %q, want it to contain %q", api.Msg, tc.wantInMsg)
			}
			if got := atomic.LoadInt32(&hits); got != 0 {
				t.Fatalf("download hits = %d, want 0: a bad envelope must fail before downloading", got)
			}
		})
	}
}

// otherKeyEnvelopeHex builds an envelope wrapped for a different SM2 public key,
// so that unwrapping against TAA's key fails.
func otherKeyEnvelopeHex(t *testing.T) string {
	t.Helper()
	other, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("GenerateSM2KeyPair: %v", err)
	}
	env, err := teecrypto.SealSM2(&other.PublicKey, []byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("SealSM2: %v", err)
	}
	return hex.EncodeToString(env.WrappedKey[1:])
}

func TestImportFallsBackToLegacyFormatWithoutDataKeyCipher(t *testing.T) {
	state, server := setupTestServer(t)

	archive := buildTarGzArchive(t, map[string]archiveEntry{
		"data/legacy.txt": {mode: 0o644, data: []byte("legacy\n")},
	})
	sealed := sealForTAA(t, state.SM2PrivateKey, archive)

	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(sealed)
	}))
	defer fileServer.Close()

	resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": fileServer.URL + "/data.tar.gz.enc",
		"requestId":   "req-legacy-format",
		"taskId":      "task-legacy-format",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("import: status=%d error=%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}

	waitForIdle(t, state)

	sum := teecrypto.SM3Sum(archive)
	dataDir := filepath.Join(state.Security.DataDir, hex.EncodeToString(sum[:]))
	if _, err := os.Stat(filepath.Join(dataDir, "data", "legacy.txt")); err != nil {
		t.Fatalf("legacy whole-file envelope was not extracted into %s: %v", dataDir, err)
	}
}

func TestImportURLKeyDecryptFailureReportsPublicKey(t *testing.T) {
	state, server := setupTestServer(t)

	type reportPayload struct {
		Code   int     `json:"code"`
		Msg    *string `json:"msg"`
		Report string  `json:"report"`
	}
	reportResCh := make(chan reportPayload, 1)
	platformServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/taa/reportRes" {
			var payload reportPayload
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode report payload: %v", err)
			} else {
				reportResCh <- payload
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer platformServer.Close()

	state.mu.Lock()
	state.PlatformIP = platformServer.URL
	state.mu.Unlock()

	// The envelope itself is valid but does not pair with the response body: the
	// envelope layer passes, GCM authentication fails, and the failure lands in the
	// asynchronous report.
	_, keyHex := urlKeyResource(t, &state.SM2PrivateKey.PublicKey, []byte("data"))

	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tampered-ciphertext-bytes"))
	}))
	defer fileServer.Close()

	resp := postJSON(t, server.URL+"/v1/taa/import", map[string]any{
		"resourceUrl": fileServer.URL + "/data.sm4?dataKeyCipher=" + keyHex,
		"requestId":   "req-urlkey-gcm-fail",
		"taskId":      "task-urlkey-gcm-fail",
	})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusOK || api.Error != 0 {
		t.Fatalf("import: expected 200/0, got %d/%d msg=%s", resp.StatusCode, api.Error, api.Msg)
	}

	select {
	case payload := <-reportResCh:
		if payload.Code != 1 {
			t.Fatalf("reportRes code = %d, want 1", payload.Code)
		}
		if payload.Msg == nil || !strings.Contains(*payload.Msg, "解密资源失败") {
			t.Fatalf("reportRes msg = %v, want decrypt failure", payload.Msg)
		}
		if !strings.Contains(*payload.Msg, "taaPublicKey:") || !strings.Contains(*payload.Msg, "-----BEGIN PUBLIC KEY-----") {
			t.Fatalf("reportRes msg missing taaPublicKey, got: %v", *payload.Msg)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the urlkey decrypt failure report")
	}
}
```

并把该文件 import 块补上 `"encoding/json"`、`"fmt"`、`"strings"`、`"time"`（`encoding/hex`、`net/http`、`net/http/httptest`、`os`、`path/filepath`、`sync/atomic`、`testing`、`teecrypto "taa/pkg/crypto"` 已列出）。

- [x] **Step 2: 跑测试确认通过（不需要改生产代码）**

Run: `go test ./internal/controller/ -run 'TestImportRejectsBadDataKeyCipherBeforeDownloading|TestImportFallsBackToLegacyFormatWithoutDataKeyCipher|TestImportURLKeyDecryptFailureReportsPublicKey' -v`
Expected: 全部 PASS

若「envelope for another key」一例的 `hits` 不为 0，说明提前解封没有生效，回到 Task 3 Step 6 检查解析块的位置是否在校验之后、下载之前。
若 `TestImportURLKeyDecryptFailureReportsPublicKey` 超时，说明新分支把失败吞掉了没有走 `reportImportFailure`，检查 `resolvePlaintextResourceWithDataKey` 的返回值是否被 `processImportedResource` 的 `if err != nil` 接住。

- [x] **Step 3: 范围护栏——模型下发与资源信息仍解整文件信封**

Run: `go test ./internal/controller/ -run 'TestResourceInfoHandlerDecryptsWithoutEncSuffix|TestPhase1ModelImportFailureReportsModelImport' -v 2>&1 | tail -20`
Expected: PASS（这两个接口的解密路径未被本次改动触及）

- [x] **Step 4: 提交**

```bash
git add internal/controller/import_urlkey_test.go
git commit -m "test(import): cover download-time rejection and the legacy fallback"
```

> **执行记录（2026-10-14）**：已实现并提交 `fba012f`（1 文件，仅测试，+157/-0 相对本任务起点）。规格审查逐行一致：相对 `6ea68c1` 零删除行，Task 3 的 `urlKeyResource` 与 `TestImportDecryptsWithDataKeyCipherFromURL` 逐字节未动；五个表用例、`hits == 0` 断言、四个新 import 均与规格一致；提交信息无正文、无 trailer。
>
> **Task 3 遗留的两条变异在本提交转为失败**（本任务的验收标准，不只是"跑绿"）：`handler_task.go:110` 的 `if err != nil` → `if false` 使 `duplicate_parameter` 与 `empty_value` 报 `status=500 error=500 msg=Get "": unsupported protocol scheme ""`；丢弃 `UnwrapKeySM2` 错误使 `envelope_for_another_key` 报 `status=200`。审查者独立复现两条，还原后 `handler_task.go` 的 sha256 回到 `b48d601d…`，工作区无残留。
>
> 质量审查结论「可合并」，六条全为 Minor、无 Important/Critical。采纳 4 条后 amend 为 `fba012f`，复核确认四条全部闭合且未削弱其他断言：断言收紧为 `数据密钥信封长度无效`（原先 `长度无效` 由 `seal.go:146` 与 `seal.go:38` 同时发出，无法区分二者）；篡改载荷由 25B 补到 39B，真正走到 `gcm.Open` 的标签校验（原先 25B 撞的是 `密文长度不足`，与注释自称的 "GCM authentication fails" 不符）；删掉 `reportPayload` 中从未读取的 `Report` 字段；`state, server := … ; _ = state` 改为 `_, server := …`。
>
> 未采纳 2 条：`reportResCh` 缓冲 1 配 10s 超时在"多上报一次"时会挂起（该路径只上报一次，要触发需不存在的代码路径；改成丢弃式发送只是把假想的挂起换成静默丢弃）；五个子测试共用 `hits`/`fileServer`（`t.Run` 顺序执行、无 `t.Parallel()`，安全）。
>
> 一处推定更正：`crypto.Decrypt` 的长度判据是严格 `< nonceSize+overhead`（即 `< 28`），28 字节本身已通过并进入 `gcm.Open`。实测 25/26/27 → `密文长度不足`，28 及以上 → `cipher: message authentication failed`。

---

### Task 5: platform-mock 后端 urlkey 模式

**Files:**
- Modify: `tools/platform-mock/internal/store.go:101-108`
- Modify: `tools/platform-mock/internal/handlers_upload.go`
- Test: `tools/platform-mock/internal/server_test.go`（追加）

- [x] **Step 1: 写失败测试**

在 `tools/platform-mock/internal/server_test.go` 末尾追加（该文件已 import `bytes`、`encoding/json`、`net/http`、`os`、`path/filepath`、`strings`、`testing`、`taa/pkg/crypto`，无需新增 import）：

```go
func TestUploadURLKeyModeSplitsEnvelopeIntoTheURL(t *testing.T) {
	privKey, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("generate SM2 key pair: %v", err)
	}
	pubPEM, err := crypto.MarshalSM2PublicKeyPEM(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal SM2 public key PEM: %v", err)
	}

	uploadDir := filepath.Join(t.TempDir(), "uploads")
	server := newUploadTestServer(t, uploadDir)
	defer server.Close()

	rawContent := []byte("dataset bytes for the urlkey protocol")

	// 1. urlkey mode: the name gains .sm4 rather than .enc, and the response
	// carries the envelope hex
	status, api := postMultipartUploadWithFields(t, server.URL+"/api/upload", "dataset.tar.gz", rawContent, map[string]string{
		"encryptMode": "urlkey",
		"publicKey":   string(pubPEM),
	})
	if status != http.StatusOK || api.Error != 0 {
		t.Fatalf("urlkey upload failed: status=%d, api=%+v", status, api)
	}
	resMap, ok := api.Result.(map[string]any)
	if !ok {
		t.Fatalf("result is not map: %+v", api.Result)
	}
	if orig, _ := resMap["originalName"].(string); orig != "dataset.tar.gz.sm4" {
		t.Fatalf("originalName = %q, want dataset.tar.gz.sm4", orig)
	}
	if enc, _ := resMap["encrypted"].(bool); !enc {
		t.Fatalf("encrypted flag = %v, want true", resMap["encrypted"])
	}
	keyHex, _ := resMap["dataKeyCipher"].(string)
	if keyHex == "" {
		t.Fatal("dataKeyCipher missing from the upload response")
	}
	fileURL, _ := resMap["url"].(string)
	if !strings.Contains(fileURL, "?dataKeyCipher="+keyHex) {
		t.Fatalf("url = %q, want it to carry dataKeyCipher", fileURL)
	}

	// 2. Only ciphertext hits the disk: no plaintext and no envelope
	// (ciphertext = nonce 12B + plaintext + tag 16B)
	storedName, _ := resMap["filename"].(string)
	cipherBytes, err := os.ReadFile(filepath.Join(uploadDir, storedName))
	if err != nil {
		t.Fatalf("read stored file: %v", err)
	}
	if bytes.Contains(cipherBytes, rawContent) {
		t.Fatal("stored file still contains the plaintext")
	}
	if want := len(rawContent) + 12 + 16; len(cipherBytes) != want {
		t.Fatalf("stored size = %d, want %d: only the ciphertext should be stored, without the %d-byte envelope",
			len(cipherBytes), want, crypto.SM2WrappedKeySize)
	}

	// 3. Take the envelope back out of the URL and unwrap the data key to recover
	// the plaintext
	wrapped, err := crypto.ParseWrappedDataKeyHex(keyHex)
	if err != nil {
		t.Fatalf("ParseWrappedDataKeyHex: %v", err)
	}
	dataKey, err := crypto.UnwrapKeySM2(privKey, wrapped)
	if err != nil {
		t.Fatalf("UnwrapKeySM2: %v", err)
	}
	decrypted, err := crypto.Decrypt(dataKey, cipherBytes)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, rawContent) {
		t.Fatalf("decrypted = %q, want %q", string(decrypted), string(rawContent))
	}

	// 4. The legacy encrypt=true still uses the whole-file envelope and carries no
	// dataKeyCipher
	status, api = postMultipartUploadWithFields(t, server.URL+"/api/upload", "legacy.tar.gz", rawContent, map[string]string{
		"encrypt":   "true",
		"publicKey": string(pubPEM),
	})
	if status != http.StatusOK || api.Error != 0 {
		t.Fatalf("legacy encrypted upload failed: status=%d, api=%+v", status, api)
	}
	legacyMap := api.Result.(map[string]any)
	if orig, _ := legacyMap["originalName"].(string); orig != "legacy.tar.gz.enc" {
		t.Fatalf("legacy originalName = %q, want legacy.tar.gz.enc", orig)
	}
	// The response body is a map[string]any, so the field is always present:
	// assert on the empty value rather than on nil.
	if v, _ := legacyMap["dataKeyCipher"].(string); v != "" {
		t.Fatalf("legacy mode must not carry dataKeyCipher, got %q", v)
	}
}
```

- [x] **Step 2: 跑测试确认失败**

Run: `go test ./tools/platform-mock/... -run TestUploadURLKeyModeSplitsEnvelopeIntoTheURL -v`
Expected: FAIL —— `originalName = "dataset.tar.gz", want dataset.tar.gz.sm4`（未识别的 encryptMode 落到不加密）

- [x] **Step 3: 给上传记录加字段** —— **已跳过（本步骤是计划缺陷，见执行记录）**

`tools/platform-mock/internal/store.go`，把 `uploadedFileRecord` 改为：

```go
type uploadedFileRecord struct {
	Filename      string    `json:"filename"`
	OriginalName  string    `json:"originalName"`
	Size          int64     `json:"size"`
	URL           string    `json:"url"`
	UploadedAt    time.Time `json:"uploadedAt"`
	Encrypted     bool      `json:"encrypted"`
	DataKeyCipher string    `json:"dataKeyCipher,omitempty"`
}
```

- [x] **Step 4: 实现三态加密模式**

`tools/platform-mock/internal/handlers_upload.go`：

(a) import 块加入 `"encoding/hex"`。

(b) 把

```go
		encryptVal := strings.TrimSpace(r.FormValue("encrypt"))
		shouldEncrypt := strings.EqualFold(encryptVal, "true") || encryptVal == "1" || strings.EqualFold(encryptVal, "on")

		var (
			fileSize int64
			filename string
			filePath string
		)

		if shouldEncrypt {
```

替换为：

```go
		// encryptMode is none / envelope (whole-file envelope, the legacy format) /
		// urlkey (envelope in the URL, the new protocol). The legacy encrypt=true
		// field maps to envelope for backward compatibility.
		encryptMode := strings.ToLower(strings.TrimSpace(r.FormValue("encryptMode")))
		if encryptMode != "none" && encryptMode != "envelope" && encryptMode != "urlkey" {
			encryptVal := strings.TrimSpace(r.FormValue("encrypt"))
			if strings.EqualFold(encryptVal, "true") || encryptVal == "1" || strings.EqualFold(encryptVal, "on") {
				encryptMode = "envelope"
			} else {
				encryptMode = "none"
			}
		}
		shouldEncrypt := encryptMode != "none"

		var (
			fileSize      int64
			filename      string
			filePath      string
			dataKeyCipher string
		)

		if shouldEncrypt {
```

(c) 加密分支里，把

```go
			cipherBytes, err := crypto.SealSM2SM4GCM(pubKey, fileBytes)
			if err != nil {
				writeEnvelope(w, http.StatusInternalServerError, "SM2+SM4-GCM 加密失败: "+err.Error(), nil, http.StatusInternalServerError)
				return
			}

			if !strings.HasSuffix(strings.ToLower(originalName), ".enc") {
				originalName += ".enc"
			}

			filename = fmt.Sprintf("%d_%s", time.Now().UnixNano(), originalName)
			filePath = filepath.Join(uploadDir, filename)

			if err := os.WriteFile(filePath, cipherBytes, 0o644); err != nil {
				writeEnvelope(w, http.StatusInternalServerError, "保存加密文件失败: "+err.Error(), nil, http.StatusInternalServerError)
				return
			}
			fileSize = int64(len(cipherBytes))
```

整段替换为（urlkey 分支在前，原逻辑原样留在 else 里，`filename`/`filePath` 两行在两个分支各自赋值，与下方非加密分支的写法一致）：

```go
			if encryptMode == "urlkey" {
				// New protocol: the file holds nothing but ciphertext, and the SM2 key
				// envelope is hex-encoded onto the download URL.
				env, err := crypto.SealSM2(pubKey, fileBytes)
				if err != nil {
					writeEnvelope(w, http.StatusInternalServerError, "SM2+SM4-GCM 加密失败: "+err.Error(), nil, http.StatusInternalServerError)
					return
				}

				if !strings.HasSuffix(strings.ToLower(originalName), ".sm4") {
					originalName += ".sm4"
				}

				filename = fmt.Sprintf("%d_%s", time.Now().UnixNano(), originalName)
				filePath = filepath.Join(uploadDir, filename)

				if err := os.WriteFile(filePath, env.Ciphertext, 0o644); err != nil {
					writeEnvelope(w, http.StatusInternalServerError, "保存加密文件失败: "+err.Error(), nil, http.StatusInternalServerError)
					return
				}
				// Deliver the 112-byte C1C3C2 form (no uncompressed point prefix);
				// TAA accepts either layout.
				dataKeyCipher = hex.EncodeToString(env.WrappedKey[1:])
				fileSize = int64(len(env.Ciphertext))
			} else {
				cipherBytes, err := crypto.SealSM2SM4GCM(pubKey, fileBytes)
				if err != nil {
					writeEnvelope(w, http.StatusInternalServerError, "SM2+SM4-GCM 加密失败: "+err.Error(), nil, http.StatusInternalServerError)
					return
				}

				if !strings.HasSuffix(strings.ToLower(originalName), ".enc") {
					originalName += ".enc"
				}

				filename = fmt.Sprintf("%d_%s", time.Now().UnixNano(), originalName)
				filePath = filepath.Join(uploadDir, filename)

				if err := os.WriteFile(filePath, cipherBytes, 0o644); err != nil {
					writeEnvelope(w, http.StatusInternalServerError, "保存加密文件失败: "+err.Error(), nil, http.StatusInternalServerError)
					return
				}
				fileSize = int64(len(cipherBytes))
			}
```

(d) 把生成 URL 与返回体的一段：

```go
		host := platformIP(addr)
		fileURL := fmt.Sprintf("http://%s/files/%s", host, filename)
```

改为：

```go
		host := platformIP(addr)
		fileURL := fmt.Sprintf("http://%s/files/%s", host, filename)
		if dataKeyCipher != "" {
			fileURL += "?dataKeyCipher=" + dataKeyCipher
		}
```

并把返回体改为：

```go
		writeEnvelope(w, http.StatusOK, "文件上传成功", map[string]any{
			"filename":      filename,
			"originalName":  originalName,
			"size":          fileSize,
			"url":           fileURL,
			"encrypted":     shouldEncrypt,
			"dataKeyCipher": dataKeyCipher,
			"uploadedAt":    time.Now().UTC(),
		}, 0)
```

并把同一函数内的日志行 `log.Printf("file uploaded: %s → %s (encrypted=%v)", originalName, fileURL, shouldEncrypt)` 改为 `log.Printf("file uploaded: %s → %s (mode=%s)", originalName, fileURL, encryptMode)`。

- [x] **Step 5: 跑测试确认通过**

Run: `go test ./tools/platform-mock/... 2>&1 | tail -5`
Expected: `ok taa/tools/platform-mock/internal`（含新增测试）

- [x] **Step 6: 提交**

```bash
git add tools/platform-mock/internal/store.go tools/platform-mock/internal/handlers_upload.go tools/platform-mock/internal/server_test.go
git commit -m "feat(mock): add a urlkey upload mode that ships the envelope in the URL"
```

> **执行记录（2026-10-14）**：已实现并提交 `64b6092`（2 文件：`handlers_upload.go` +95/-26、`server_test.go` +159）。规格审查 ✅ 逐字一致：三态块、urlkey 分支、`?dataKeyCipher=` 拼接、七个响应键、日志改 `(mode=%s)` 均与规格相同；`else` 分支与替换前逐行比对除缩进外**零文本差异**，`.sm4` 后缀只出现在 urlkey 分支，落盘的是 `env.Ciphertext`、hex 编码的是 `env.WrappedKey[1:]`。
>
> **偏差一：Step 3 未执行，`store.go` 未改动。** 该步骤的前提是上传处理器返回 `uploadedFileRecord`；实际返回 `map[string]any`，而 `uploadedFileRecord` 的唯一构造点是 `listUploadedFiles`（扫盘，无法获知信封）。全目录仅 3 处引用（定义、该构造点、测试读取），**不存在任何可赋值站点**，加进去必然是死字段。`dataKeyCipher` 由 Step 4(d) 的响应 map 承载，与规格自述一致。实现者与规格审查者各自独立复核了这个判断。（因此 Step 6 的 `git add` 行里列出的 `store.go` 实际未提交。）
>
> **偏差二：测试多了一条断言。** 计划给的测试文本无法锁住实现里那句注释所声称的"下发 112 字节 C1C3C2"：实现者实测把 `hex.EncodeToString(env.WrappedKey[1:])` 改成完整的 113 字节 `env.WrappedKey`，测试**照样通过**——因为 `ParseWrappedDataKeyHex` 两种布局都收，所以该测试在结构上分辨不出二者（它校验的是端到端契约，不是布局约定）。已补一条解码长度断言（`crypto.SM2WrappedKeySize - 1`）并追加 `encoding/hex` import；变异取证：改成 113 字节后以 `dataKeyCipher decodes to 113 bytes, want 112` 失败。
>
> 质量审查结论「可合并」，一条 Important 已修：`encryptMode=envelope` 当时**零覆盖**，而 Task 6 之后它就是 mock UI 的真实输入。审查者用实测证明后果——删掉守卫里的 `&& encryptMode != "envelope"` 后整套测试仍全绿，探针显示此时 `encryptMode=envelope` 请求返回 `encrypted:false`、无后缀、**明文落盘**，即模式字符串集里打错一个字就会在 UI 将要驱动的那条路径上静默关掉加密。已补表驱动 `TestUploadEncryptModeMapping` 四行（envelope / none / envelope 压过 legacy `encrypt=false` / 未知值回落 none）；复核：变异下两个 envelope 子测试转为 FAIL，而 `None`、未知值两行与原 `TestUploadURLKeyModeSplitsEnvelopeIntoTheURL` 仍绿——最后一条正是缺口先前存在的原因。第四行的额外价值是钉住"显式 `encryptMode` 短路 legacy 字段"，而这正是 Task 6 依赖的契约（`<select>` 替换同一表单上的旧开关，两个字段并存是真实过渡态）。
>
> 未采纳 2 条 Minor：加密两分支去重（本提交的承重属性是 legacy 路径可证未变，规格审查已认证 `else` 分支逐字节等同，为省约 12 行放弃该属性不划算，且这是低频 dev mock）；`env.WrappedKey[1:]` 的长度防御（`WrapKeySM2` 在 nil error 下保证 113 字节，且新断言已在 mock 的契约边界把解码长度钉死为 112）。另记一处审查者指出但未采纳的对称性缺口：`encryptMode=none` 压过陈旧 `encrypt=true` 这一方向未单独成行——同一条件已被第四行证明，为一个方向再走一轮 amend+复核不值。
>
> 相邻观察（非本提交缺陷，故意不动）：`listUploadedFiles` 的 `Encrypted` 只看 `.enc` 后缀，对 `.sm4` 文件会报 `false`，且文件列表没有任何途径暴露信封。日志行故意打印含 `dataKeyCipher` 的完整 `fileURL`——这是本地联调 mock 的既定用途，不脱敏。

---

### Task 6: platform-mock 前端三态下拉

**Files:**
- Modify: `tools/platform-mock/internal/static/index.html:143-151`
- Modify: `tools/platform-mock/internal/static/js/app.js:255-305`

- [x] **Step 1: 替换开关为下拉**

`tools/platform-mock/internal/static/index.html`，把

```html
      <div style="margin: 10px 0 6px; display: flex; align-items: center; gap: 12px;">
        <label class="switch-label" for="uploadEncryptSwitch">
          <span class="switch-wrapper">
            <input type="checkbox" id="uploadEncryptSwitch">
            <span class="switch-slider"></span>
          </span>
          <span>启用加密</span>
        </label>
      </div>
```

替换为：

```html
      <div style="margin: 10px 0 6px; display: flex; align-items: center; gap: 12px;">
        <label for="uploadEncryptMode">加密方式</label>
        <select id="uploadEncryptMode">
          <option value="none">不加密</option>
          <option value="envelope">整文件信封（WrappedKey ‖ Ciphertext）</option>
          <option value="urlkey">URL 密钥信封（密文单文件 + ?dataKeyCipher）</option>
        </select>
      </div>
```

- [x] **Step 2: 上传逻辑按模式提交**

`tools/platform-mock/internal/static/js/app.js`，把 `uploadFile()` 里

```js
  const encryptSwitch = document.getElementById('uploadEncryptSwitch');
  const isEncrypted = encryptSwitch && encryptSwitch.checked;
  if (isEncrypted) {
    formData.append('encrypt', 'true');
    if (lastRegisterData && lastRegisterData.taaPublicKey) {
      formData.append('publicKey', lastRegisterData.taaPublicKey);
    }
  }
```

替换为：

```js
  const encryptSelect = document.getElementById('uploadEncryptMode');
  const encryptMode = (encryptSelect && encryptSelect.value) || 'none';
  const isEncrypted = encryptMode !== 'none';
  formData.append('encryptMode', encryptMode);
  if (isEncrypted && lastRegisterData && lastRegisterData.taaPublicKey) {
    formData.append('publicKey', lastRegisterData.taaPublicKey);
  }
```

紧随其后的 `uploadMeta` 改成记录模式本身（`encrypted` 布尔被 `encryptMode` 取代，信息不减，且能区分新旧两种形态）：

```js
  const uploadMeta = {
    fileName: file.name,
    fileSize: file.size,
    encryptMode: encryptMode,
    publicKey: isEncrypted ? (lastRegisterData && lastRegisterData.taaPublicKey ? '(配置已指定公钥)' : '未提供公钥') : '不加密',
  };
```

并把该函数中

```js
      const encNote = data.result.encrypted ? ' (已使用 TAA 注册公钥加密)' : '';
      showResult('uploadResult', true, `文件上传成功${encNote}\n\n文件名: ${data.result.originalName}\n保存名: ${data.result.filename}\n大小: ${data.result.size} bytes\nURL: ${data.result.url}`);
```

替换为：

```js
      const encNote = data.result.encrypted ? ' (已使用 TAA 注册公钥加密)' : '';
      const keyNote = data.result.dataKeyCipher ? `\n信封 (dataKeyCipher): ${data.result.dataKeyCipher}` : '';
      showResult('uploadResult', true, `文件上传成功${encNote}\n\n文件名: ${data.result.originalName}\n保存名: ${data.result.filename}\n大小: ${data.result.size} bytes\nURL: ${data.result.url}${keyNote}`);
```

- [x] **Step 3: 验证没有遗留引用**

Run: `grep -rn "uploadEncryptSwitch" tools/platform-mock/internal/static/`
Expected: 无输出

- [x] **Step 4: 跑 mock 测试**

Run: `go test ./tools/platform-mock/... 2>&1 | tail -3`
Expected: `ok`

- [x] **Step 5: 提交**

```bash
git add tools/platform-mock/internal/static/index.html tools/platform-mock/internal/static/js/app.js
git commit -m "feat(mock): pick the upload encryption mode from a select"
```

> **执行记录（2026-10-14）**：已实现并提交 `87e81ec`（3 文件：`index.html` +13/-7、`app.js` +18/-9、`server_test.go` +16）。规格审查 ✅ 逐字一致：HTML 块与三处 JS 替换均与规格 byte-for-byte（含 `id`、选项顺序、`‖` 经码点确认为 U+2016）；`components.css` 未改动，其 `.switch-*` 规则仍由 `importModelUsePublicKeySwitch`（`index.html:224-227`）使用；提交信息无正文、无 trailer。
>
> 跨端一致性已核：HTML 三个 `<option value>`、JS 转发的值、后端守卫（`handlers_upload.go:251-252`）三者同为 `none`/`envelope`/`urlkey`，无错配。另核：裸 `<select>` 并非无样式默认控件——`components.css:321` 有全局 `input, textarea, select` 规则（含 `select:focus` 于 `:355`），标签也命中全局 `label` 规则（`:371-377`），与它替换掉的 `.switch-label` 提供的字重/颜色一致；仓库内没有别的 `<select>` 也没有 `.select` 类，即该全局元素规则本身就是既定约定。
>
> 质量审查结论「可合并」，无 Important。**采纳一条建议并把一次性的 grep 升级为常驻断言**：计划 Step 3 的 `grep -rn "uploadEncryptSwitch"` 只护当下、不护将来，而本仓库 mock 测试本就有"对嵌入的前端 bundle 断言遗留标记不存在、必需标记存在"的既定写法（`server_test.go:1868-1952`），故新增 `TestUploadEncryptModeSelectReplacesLegacySwitch`（`indexHTML` 与 `frontendBundle` 均为 `server.go:32-60` 的 `init()` 从 `//go:embed all:static` 构建的包级变量）。判别力经两次取证：把 `uploadEncryptSwitch` 临时塞回 `index.html` 使首条断言以 `indexHTML should not contain the legacy uploadEncryptSwitch control` 失败，还原后 blob 哈希回到 `d95c0fc…`。
>
> **复核又抓出我这一版断言的一半是空的**：`frontendBundle` 由 `indexHTML` 加 JS 拼成，而 `id="uploadEncryptMode"` 本身就含 `encryptMode`、选项文案含 `?dataKeyCipher`，所以 token 循环即使 `app.js` 退回发旧字段 `encrypt` 也照样通过。已收紧为 HTML 无法满足的 JS 专有形式 `append('encryptMode'` 与 `result.dataKeyCipher`，并取证：把 `app.js` 的该行改回 `append('encrypt', …)`、`result.dataKeyCipher` 改名为 `kc` 后，两条 token 同时失败；还原后 `app.js` 哈希逐位一致。
>
> 未采纳 2 条：新加的 `keyNote` 行实际不会被渲染（`RESULT_INTERACTION_KEYS['uploadResult'] = 'upload'`，故 `openStoredResult` 走 `openInteractionDrawer`，而 `recordInteraction` 已先写入 `primaryContent: data`，使 `showResult` 的 `primaryContent == null` 守卫为假，字符串只留在 `resultBodies` 里没人读）——我独立复核了这条链路并确认成立，但**按计划保留**：被它修改的兄弟行 `encNote` 具有完全相同的性质，说明这是既有渲染路径的属性而非本次改动引入，改这条路径超出本任务范围；信封实际通过交互抽屉里的 JSON 正文与 URL 字段可见。另一条是窄视口下 `flex` 行可能溢出（`width:100%` 的 select 其 min-content 受最长选项文案撑开）——目标本就是桌面联调工具，审查者自己也判为无关。
>
> **同时修正了 Task 7 Step 3 的计划产物（尚未执行）**：要换上的新方框显示宽度为 54/61/60/62/59/52（旧的为 56/57/57/58/56），右边界参差，换上会比原来更歪。已按显示宽度重新生成，六行统一为 58 列，且 `┬` 仍保持在列索引 19，使下方 `▼` 连接符位置不变。

---

### Task 7: 文档同步

**Files:**
- Modify: `docs/api-design.md`（§4.2）
- Modify: `api/openapi.yaml`（`/v1/taa/import`）
- Modify: `docs/architecture-design.md`（§5.2）

- [x] **Step 1: 补 api-design §4.2**

(a) 在 `docs/api-design.md` 的 §4.2 参数表里，把

```markdown
| `resourceUrl` | `string` | 是 | 数据资源下载地址 |
```

改为：

```markdown
| `resourceUrl` | `string` | 是 | 数据资源下载地址。密态资源可携带 `?dataKeyCipher=<hex>` 参数承载 SM2 数据密钥信封，见下方说明 |
```

(b) 在 `> **type 字段被完全忽略**` 引用块之后、`**请求示例**：` 之前（`docs/api-design.md:856` 附近）插入：

```markdown
> **密态资源的两种形态**（**仅本接口**；`/v1/taa/getResourceInfo` 与 `/v1/taa/importModel` 不解析该参数，仍按整文件信封处理）：
> 1. **URL 密钥信封（当前协议）**：`resourceUrl` 形如 `<下载链接>?dataKeyCipher=<hex>`。
>    `dataKeyCipher` 是 SM2 数据密钥信封的 hex 编码（C1C3C2 布局，112 字节不带未压缩点前缀，
>    或 113 字节带 `0x04` 前缀，两者都接受）；**下载链接指向的响应体只含 SM4-GCM 密文**。
>    TAA 在下载前解析并剥离该参数，用 TAA 自身 SM2 私钥解出 16 字节数据密钥后再下载密文；
>    参数重复出现、值为空、hex 非法、长度非法或信封解不开，均在校验阶段返回 400，**不发起下载**。
>    其余 query 参数（含签名类参数）逐字节保留，不被重编码；被剥离的 `dataKeyCipher` 不进日志、
>    不进导入索引，因此也不会被转发到实际下载请求。
> 2. **整文件信封（兼容形态）**：URL 不带 `dataKeyCipher` 时沿用原逻辑——
>    文件内容为 `WrappedKey(113B) ‖ Ciphertext`，或 `.enc` 后缀强制解密，
>    或按压缩包魔数判定为明文直通。
>
> 信封与密文之间没有显式绑定：SM4-GCM 认证标签是两者唯一的关联，而它只认数据密钥——换上的密文若不是用同一数据密钥加密的，校验必然失败。
>
> 把带 `dataKeyCipher` 的 URL 交给 `getResourceInfo` 或 `importModel`，该参数会被原样转发到下载请求（并在日志中出现），
> 随后因解不开整文件信封而失败。
```

并把「其余 400 场景」一行的内容改为：

```markdown
其余 400 场景：`requestId` 和 `taskId` 同时为空；`requestId` 或 `taskId` 已存在或正在处理中；`dataKeyCipher` 重复、为空、hex 非法、长度非法或信封解不开。
```

- [x] **Step 2: 补 openapi**

(a) `api/openapi.yaml:105-107`，`/v1/taa/import` 的 `description`（`>-` 折叠块）末尾追加一行：

```yaml
        密态资源支持两种形态（仅本接口；/v1/taa/getResourceInfo 与 /v1/taa/importModel 不解析该参数）：
        resourceUrl 形如 <下载链接>?dataKeyCipher=<hex C1C3C2> 时，
        下载链接只含 SM4-GCM 密文，密钥信封由该参数给出，TAA 在下载前解析并解封，参数非法即返回 400 且不发起下载；
        未携带该参数时沿用原逻辑：整文件信封（WrappedKey || Ciphertext）、.enc 后缀强制解密、明文压缩包按魔数直通。
```

(b) `api/openapi.yaml:136`，把

```yaml
          description: 参数错误（resourceUrl 为空；requestId/taskId 同时为空；requestId 或 taskId 已存在或正在处理中）
```

改为：

```yaml
          description: 参数错误（resourceUrl 为空；requestId/taskId 同时为空；requestId 或 taskId 已存在或正在处理中；dataKeyCipher 重复、为空、hex 非法、长度非法或信封解不开）
```

(c) `api/openapi.yaml:613-615`，`ImportRequest.resourceUrl` 把

```yaml
        resourceUrl:
          type: string
          description: 加密数据资源的 HTTP(S) 下载地址
```

改为：

```yaml
        resourceUrl:
          type: string
          description: 加密数据资源的 HTTP(S) 下载地址。密态资源可携带 ?dataKeyCipher=<hex> 参数承载 SM2 数据密钥信封（C1C3C2 布局，112 或 113 字节），该参数不会被转发到下载请求；其余 query 参数原样保留
```

- [x] **Step 3: 补 architecture §5.2**

`docs/architecture-design.md` 中 `### 5.2 导入流程 (`/v1/taa/import`)` 的解密方框：

```text
          ┌─── 解密 ───────────────────────────────────┐
          │  拆分: WrappedKey || SM4-GCM 密文           │
          │  SM2 私钥解包 → SM4 会话密钥 (16B)          │
          │  SM4-GCM 解密 → 明文归档包                   │
          └────────┬───────────────────────────────────┘
```

替换为（`docs/architecture-design.md:262-266`，旧 5 行换新 6 行）：

```text
          ┌─── 解密 ───────────────────────────────────┐
          │  信封来源: URL 参数 dataKeyCipher / 文件头 │
          │  下载体: 密文 (URL) / 信封+密文 (文件)     │
          │  SM2 私钥解包信封 → SM4 数据密钥 (16B)     │
          │  SM4-GCM 解密 → 明文归档包                 │
          └────────┬───────────────────────────────────┘
```

并在紧随其后的 ``` 闭合围栏之后、`### 5.3 导出流程 (\`/v1/taa/export\`)` 之前追加一段（§5.2 图后原本没有正文段落，这句就是唯一说明）：

```markdown
> 携带 `dataKeyCipher` 时，信封在**下载前**就已解封（见 `internal/controller/handler_task.go`）：格式非法或公钥不匹配直接返回 400，不消耗下载带宽；解密失败仍属异步阶段，经 `reportRes` 上报。
```

- [x] **Step 4: 提交**

```bash
git add docs/api-design.md api/openapi.yaml docs/architecture-design.md
git commit -m "docs(api): document the URL-carried data key envelope"
```

> **执行记录（2026-10-14）**：已实现并提交 `5407ec5`（3 文件：`api/openapi.yaml` +8/-2、`docs/api-design.md` +21/-2、`docs/architecture-design.md` +9/-3）。该 SHA 是 amend 后的结果——首次提交为 `112c992`，质量审查提出修正后原地 amend，`git log -1 --format=%B` 仍是单行 subject、无正文无 trailer（分支未 push，amend 安全）。
>
> 规格审查 ✅：把四组编辑逐段抽成期望文本后与提交内的 blob 做 `diff`，八处全部 identical；`‖` 经码点确认在 `api-design` 为 U+2016、在 `openapi.yaml` 为 ASCII `||`（分别按规格），方框字符集合与原图一致，`git show --check` 无空白告警，YAML 可解析。§4.3 的「其余 400 场景」与另两个端点的 `'400'` 描述经比对逐字节未动。
>
> **计划缺陷（本任务内被发现并修正）**：计划的 Step 1 sanity check 写「api-design 应出现 5 次 `dataKeyCipher`」，实测 7 次。是计划漏算——要插入的那段 blockquote 自身就有 5 行含该词，加表格行与 400 行共 7。文本本身无误，已按实测记录。
>
> 质量审查：1 Important + 5 Minor。**Important 成立且是计划产物**：新方框上行写「信封来源: … / 文件头」、下行写「下载链接只含 SM4-GCM 密文」，两种形态矛盾——文件头形态的下载体是 `WrappedKey(113B) ‖ Ciphertext`，不是纯密文。修补前我先量了显示宽度（非字节长度），发现方框还背着第二个问题：改前「解密」框本就内部参差（边框 56，内容行 57/57/58），而本次改动把它变成六行整齐的 58，却比下方「解压」框（56）宽 2 列——而这两个框改前是对齐的。故未采纳审查者给的两条措辞建议，而是把方框**恢复为 56 列**并重写该行，一次解决 Important 与 Minor 4：
>
> ```text
>           ┌─── 解密 ───────────────────────────────────┐
>           │  信封来源: URL 参数 dataKeyCipher / 文件头 │
>           │  下载体: 密文 (URL) / 信封+密文 (文件)     │
>           │  SM2 私钥解包信封 → SM4 数据密钥 (16B)     │
>           │  SM4-GCM 解密 → 明文归档包                 │
>           └────────┬───────────────────────────────────┘
> ```
>
> 六行均为 56 显示列，且上下边框与 `112c992^` **逐字节相同**（故根本不出现在 diff 里），`┬`/`▼` 仍在第 19 列，箭头对位未受影响；「解压」框刻意不动——它对着自己的边框本就参差（内容 58/56/56/57 对 56 宽的边框），与本次协议变更无关，加宽它只是把参差搬个位置。审查者复核后同意，并判替代方案优于其原提案。
>
> 已采纳 3 条 Minor：`必然校验失败` 过头（GCM 标签只认数据密钥、不认信封，若平台复用同一数据密钥则换密文仍可通过，已改为「信封与密文之间没有显式绑定…换上的密文若不是用同一数据密钥加密的，校验必然失败」）；`openapi.yaml` 追加行只写了回退三分支中的一支（`resolvePlaintextResource` 还有 `.enc` 强制解密与明文魔数直通，已补全）；结尾段与头部重复声明「仅本接口」，已删重复只留误用后果。未采纳 Minor 6（在 §4.1/§4.3 加交叉引用）：§4.2 头部与 OpenAPI 描述已两处声明范围，可发现性足够，逐端点加注属全文档约定变更而非本次协议变更，审查者亦同意。
>
> 复核结论 **mergeable**，无新增阻塞项；审查者另行确认四处改动未引入新的准确性/一致性/清晰度问题，且 `git diff 112c992 5407ec5` 仅含那三个文档、两者父提交同为 `09ec221`，故首轮对代码的全部核验（剥离完整、下载前 400、112/113 两布局、异步 reportRes、其余 query 逐字节保留）继续成立。
>
> **本任务同时修正了计划自身的产物**（与上述提交无关，仅改计划文件）：① Task 7 Step 3 的替换方框文本同步为上面这版（原计划文本会把已被证伪的那行重新引入）；② Step 1(b) 的两句措辞、Step 2(a) 的回退分支句同步为审查后的最终文本；③ Task 8 Step 3 原写「日志为本次 7 个提交」，而记账提交会使条数持续增长，已改为按提交主题逐条核对、不按固定条数。执行实现子代理曾把 ③ 这条并发改动当成「第四个被改文件」上报——它确实不是实现代理所为（是协调者本人在其运行期间改的），实现代理正确地既未还原也未纳入提交。

---

### Task 8: 全量验证与收尾

- [ ] **Step 1: 全量测试**

Run: `go test ./... 2>&1 | grep -v "^ok\|no test files" | head -20`
Expected: 无输出（全绿）

> 已知偶发：`internal/controller` 的并发相关用例约有 7.5% 波动率，与本改动无关；若只在并发用例上失败，重跑一次确认。

- [ ] **Step 2: 构建校验**

Run: `CGO_ENABLED=0 GOOS=linux go build -o /tmp/taa-urlkey ./cmd/taa && ls -l /tmp/taa-urlkey`
Expected: 生成静态二进制，无报错

- [ ] **Step 3: 确认工作区只含预期改动**

Run: `git status --short && git log --oneline master..HEAD`
Expected: 无未提交改动（`go.work` 与子模块不进版本控制）；`master..HEAD` 只含本计划产生的提交——每个 Task 一条实现提交加一条 `docs(import): record Task N completion in the plan`。逐条核对提交主题与 Task 一一对应，不要按固定条数（本计划执行期间条数会随记账提交增长）

- [ ] **Step 4: 回到主检出合并**

由用户确认后执行：在 worktree 中把分支合回 `master`，删除 worktree 与分支（`ExitWorktree` 时选 remove，或手工 `git merge --no-ff feat/import-url-key-envelope`）。

---

## 附：验证清单（对应 spec）

| spec 要求 | 覆盖任务 |
| --- | --- |
| URL 逐段剥离、保住其余参数与转义 | Task 1 |
| 112/113 两种 hex 布局 | Task 2 |
| 下载前解封、信封错→400 且不下载 | Task 3 / Task 4 |
| 密文为空 / GCM 失败 → 异步上报 | Task 4（`TestImportURLKeyDecryptFailureReportsPublicKey`） |
| 无 `dataKeyCipher` 完全回退 | Task 4 |
| `importModel` / `getResourceInfo` 不受影响 | Task 4 Step 3 |
| platform-mock 可端到端联调 | Task 5 / Task 6 |
| 文档同步 | Task 7 |
