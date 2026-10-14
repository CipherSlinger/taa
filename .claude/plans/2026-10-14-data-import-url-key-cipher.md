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
| `internal/resource/urlkey_test.go` | 上述函数的表驱动测试 | 新建 |
| `pkg/crypto/seal.go` | 新增 `ParseWrappedDataKeyHex`（hex → 113B 信封，兼容两种布局） | 修改 |
| `pkg/crypto/wrappedkey_test.go` | 上述函数的表驱动测试 | 新建 |
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

- [ ] **Step 1: 写失败测试**

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

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/resource/ -run TestSplitDataKeyCipher -v`
Expected: 编译失败，`undefined: SplitDataKeyCipher`

- [ ] **Step 3: 实现**

创建 `internal/resource/urlkey.go`：

```go
package resource

import (
	"fmt"
	"strings"
)

// dataKeyCipherParam 是数据下发 URL 上承载 SM2 数据密钥信封的 query 参数名。
const dataKeyCipherParam = "dataKeyCipher"

// SplitDataKeyCipher 从资源 URL 中剥离 dataKeyCipher 参数，
// 返回可直接下载的 URL 与该参数的原始 hex 值。
//
// found 为 false 表示 URL 未携带该参数，调用方应回退到旧格式处理。
// 只有两种情况返回错误：参数出现多次（含义有歧义），或参数值为空。
//
// 剥离是逐段字符串操作：其余 query 段的字节、顺序与转义一律保持原样，
// 因此带签名的下载链接不会被改写。
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

// splitURLParts 把 URL 切成 base、query 与 fragment（fragment 含开头的 '#'）。
// query 为空串表示 URL 没有 query 段。
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

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./internal/resource/ -run TestSplitDataKeyCipher -v`
Expected: `--- PASS: TestSplitDataKeyCipher` 及全部子测试 PASS

- [ ] **Step 5: 提交**

```bash
git add internal/resource/urlkey.go internal/resource/urlkey_test.go
git commit -m "feat(resource): split the data key cipher out of a resource URL"
```

---

### Task 2: 信封 hex 解析（两种布局）

**Files:**
- Modify: `pkg/crypto/seal.go`
- Test: `pkg/crypto/wrappedkey_test.go`

- [ ] **Step 1: 写失败测试**

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

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./pkg/crypto/ -run TestParseWrappedDataKeyHex -v`
Expected: 编译失败，`undefined: ParseWrappedDataKeyHex`

- [ ] **Step 3: 实现**

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
// sm2CipherPointPrefix 是 SM2 密文中未压缩点 C1 的起始字节。
const sm2CipherPointPrefix = 0x04

// ParseWrappedDataKeyHex 解析 hex 编码的 SM2 数据密钥信封，
// 返回可直接交给 UnwrapKeySM2 的 SM2WrappedKeySize 字节信封。
//
// 平台可能下发两种布局：112 字节（C1 ‖ C3 ‖ C2，不含未压缩点前缀）与
// 113 字节（含 0x04 前缀）。前者补回前缀，后者原样接受。
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

- [ ] **Step 4: 跑测试确认通过**

Run: `go test ./pkg/crypto/ -run TestParseWrappedDataKeyHex -v`
Expected: 全部子测试 PASS

- [ ] **Step 5: 提交**

```bash
git add pkg/crypto/seal.go pkg/crypto/wrappedkey_test.go
git commit -m "feat(crypto): parse a hex data key envelope in either layout"
```

---

### Task 3: 控制器解密链路与端到端打通

**Files:**
- Modify: `internal/controller/route.go`（import 块 + `decryptResourceToTempFile` 之后）
- Modify: `internal/controller/import_processing.go:26-45`
- Modify: `internal/controller/handler_task.go`（import 块、`importHandler`、`modelImportHandler`）
- Test: `internal/controller/import_urlkey_test.go`（新建）

- [ ] **Step 1: 写失败测试**

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

// urlKeyResource 把明文归档封成「信封进 URL、密文单独下载」的形态。
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

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./internal/controller/ -run TestImportDecryptsWithDataKeyCipherFromURL -v`
Expected: FAIL —— `resourceUrl` 被原样下载，服务端收到 `dataKeyCipher` 参数且响应体是纯密文，解密失败，数据目录不存在

- [ ] **Step 3: 新增按数据密钥解密的函数**

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
// decryptCiphertextWithDataKey 用外部提供的 SM4 数据密钥解密「仅含密文」的资源文件。
//
// 与 decryptResourceToTempFile 的区别：密文文件里不再有 SM2 密钥信封前缀，
// 信封由下发 URL 的 dataKeyCipher 参数单独给出，并已在上游解封为 dataKey。
// 明文写入临时文件，返回明文文件路径，调用方负责删除。
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

- [ ] **Step 4: 新增按数据密钥解密的判定包装**

在 `internal/controller/import_processing.go` 中，紧跟 `resolvePlaintextResource` 之后追加：

```go
// resolvePlaintextResourceWithDataKey 用数据下发 URL 携带的数据密钥信封解开「仅含密文」的资源。
//
// 与 resolvePlaintextResource 的旧格式路径并列：信封已由调用方在同步段解封为 dataKey，
// 这里不再做压缩包魔数探测——URL 携带了信封即声明这是密文，解不开就按失败处理，
// 不静默改判为明文。失败时错误信息附带 TAA 公钥，便于平台确认该用哪把公钥加密信封。
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

- [ ] **Step 5: 让异步段接受数据密钥**

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

- [ ] **Step 6: 同步段解析 URL 并提前解封**

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
	// 数据下发的密态资源采用「信封进 URL、密文单独下载」的形态：
	// resourceUrl 形如 <下载链接>?dataKeyCipher=<hex C1C3C2>。
	// 信封在下载前就解封：格式非法或公钥不匹配无需先拉完整份密文才暴露。
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

- [ ] **Step 7: 跑测试确认通过**

Run: `go test ./internal/controller/ -run TestImportDecryptsWithDataKeyCipherFromURL -v`
Expected: PASS

- [ ] **Step 8: 跑相关包回归**

Run: `go test ./internal/controller/ ./internal/resource/ ./pkg/crypto/ 2>&1 | tail -5`
Expected: 三个包全 `ok`

- [ ] **Step 9: 提交**

```bash
git add internal/controller/route.go internal/controller/import_processing.go internal/controller/handler_task.go internal/controller/import_urlkey_test.go
git commit -m "feat(import): decrypt data resources with the URL-carried key envelope"
```

---

### Task 4: 下载前拦截与回退护栏

**Files:**
- Test: `internal/controller/import_urlkey_test.go`（追加）

- [ ] **Step 1: 写失败测试**

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

// otherKeyEnvelopeHex 生成一个用别的 SM2 公钥封装的信封，用来触发解封失败。
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

	// 信封本身合法，但响应体与信封不配对：信封层通过，GCM 认证失败，落到异步上报。
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

- [ ] **Step 2: 跑测试确认通过（不需要改生产代码）**

Run: `go test ./internal/controller/ -run 'TestImportRejectsBadDataKeyCipherBeforeDownloading|TestImportFallsBackToLegacyFormatWithoutDataKeyCipher|TestImportURLKeyDecryptFailureReportsPublicKey' -v`
Expected: 全部 PASS

若「envelope for another key」一例的 `hits` 不为 0，说明提前解封没有生效，回到 Task 3 Step 6 检查解析块的位置是否在校验之后、下载之前。
若 `TestImportURLKeyDecryptFailureReportsPublicKey` 超时，说明新分支把失败吞掉了没有走 `reportImportFailure`，检查 `resolvePlaintextResourceWithDataKey` 的返回值是否被 `processImportedResource` 的 `if err != nil` 接住。

- [ ] **Step 3: 范围护栏——模型下发与资源信息仍解整文件信封**

Run: `go test ./internal/controller/ -run 'TestResourceInfoHandlerDecryptsWithoutEncSuffix|TestPhase1ModelImportFailureReportsModelImport' -v 2>&1 | tail -20`
Expected: PASS（这两个接口的解密路径未被本次改动触及）

- [ ] **Step 4: 提交**

```bash
git add internal/controller/import_urlkey_test.go
git commit -m "test(import): cover download-time rejection and the legacy fallback"
```

---

### Task 5: platform-mock 后端 urlkey 模式

**Files:**
- Modify: `tools/platform-mock/internal/store.go:101-108`
- Modify: `tools/platform-mock/internal/handlers_upload.go`
- Test: `tools/platform-mock/internal/server_test.go`（追加）

- [ ] **Step 1: 写失败测试**

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

	// 1. urlkey 模式：文件名补 .sm4 而非 .enc，响应带回信封 hex
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

	// 2. 落盘的是纯密文：既不含明文，也不含信封（密文 = nonce 12B + 明文 + tag 16B）
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

	// 3. 从 URL 取回信封，用私钥解出数据密钥即可还原明文
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

	// 4. 旧的 encrypt=true 仍走整文件信封，且不带 dataKeyCipher
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
	// 响应体是 map[string]any，字段恒在，因此这里判空值而非判 nil。
	if v, _ := legacyMap["dataKeyCipher"].(string); v != "" {
		t.Fatalf("legacy mode must not carry dataKeyCipher, got %q", v)
	}
}
```

- [ ] **Step 2: 跑测试确认失败**

Run: `go test ./tools/platform-mock/... -run TestUploadURLKeyModeSplitsEnvelopeIntoTheURL -v`
Expected: FAIL —— `originalName = "dataset.tar.gz", want dataset.tar.gz.sm4`（未识别的 encryptMode 落到不加密）

- [ ] **Step 3: 给上传记录加字段**

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

- [ ] **Step 4: 实现三态加密模式**

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
		// encryptMode：none / envelope（整文件信封，旧格式）/ urlkey（信封进 URL，新协议）。
		// 旧的 encrypt=true 字段按 envelope 处理，保持向后兼容。
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
				// 新协议：文件里只放密文，SM2 密钥信封 hex 化后随下载 URL 一起下发。
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
				// 下发 112 字节的 C1C3C2 形式（不含未压缩点前缀）；TAA 侧两种布局都接受。
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

- [ ] **Step 5: 跑测试确认通过**

Run: `go test ./tools/platform-mock/... 2>&1 | tail -5`
Expected: `ok taa/tools/platform-mock/internal`（含新增测试）

- [ ] **Step 6: 提交**

```bash
git add tools/platform-mock/internal/store.go tools/platform-mock/internal/handlers_upload.go tools/platform-mock/internal/server_test.go
git commit -m "feat(mock): add a urlkey upload mode that ships the envelope in the URL"
```

---

### Task 6: platform-mock 前端三态下拉

**Files:**
- Modify: `tools/platform-mock/internal/static/index.html:143-151`
- Modify: `tools/platform-mock/internal/static/js/app.js:255-305`

- [ ] **Step 1: 替换开关为下拉**

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

- [ ] **Step 2: 上传逻辑按模式提交**

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

- [ ] **Step 3: 验证没有遗留引用**

Run: `grep -rn "uploadEncryptSwitch" tools/platform-mock/internal/static/`
Expected: 无输出

- [ ] **Step 4: 跑 mock 测试**

Run: `go test ./tools/platform-mock/... 2>&1 | tail -3`
Expected: `ok`

- [ ] **Step 5: 提交**

```bash
git add tools/platform-mock/internal/static/index.html tools/platform-mock/internal/static/js/app.js
git commit -m "feat(mock): pick the upload encryption mode from a select"
```

---

### Task 7: 文档同步

**Files:**
- Modify: `docs/api-design.md`（§4.2）
- Modify: `api/openapi.yaml`（`/v1/taa/import`）
- Modify: `docs/architecture-design.md`（§5.2）

- [ ] **Step 1: 补 api-design §4.2**

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
> **密态资源的两种形态**：
> 1. **URL 密钥信封（当前协议）**：`resourceUrl` 形如 `<下载链接>?dataKeyCipher=<hex>`。
>    `dataKeyCipher` 是 SM2 数据密钥信封的 hex 编码（C1C3C2 布局，112 字节不带未压缩点前缀，
>    或 113 字节带 `0x04` 前缀，两者都接受）；**下载链接指向的响应体只含 SM4-GCM 密文**。
>    TAA 在下载前解析并剥离该参数，用 TAA 自身 SM2 私钥解出 16 字节数据密钥后再下载密文；
>    参数重复出现、值为空、hex 非法、长度非法或信封解不开，均在校验阶段返回 400，**不发起下载**。
>    其余 query 参数（含签名类参数）逐字节保留，不被重编码。
> 2. **整文件信封（兼容形态）**：URL 不带 `dataKeyCipher` 时沿用原逻辑——
>    文件内容为 `WrappedKey(113B) ‖ Ciphertext`，或 `.enc` 后缀强制解密，
>    或按压缩包魔数判定为明文直通。
>
> 信封与密文的绑定是隐式的：换掉密文而沿用信封，SM4-GCM 认证标签必然校验失败。
```

并把「其余 400 场景」一行的内容改为：

```markdown
其余 400 场景：`requestId` 和 `taskId` 同时为空；`requestId` 或 `taskId` 已存在或正在处理中；`dataKeyCipher` 重复、为空、hex 非法、长度非法或信封解不开。
```

- [ ] **Step 2: 补 openapi**

(a) `api/openapi.yaml:105-107`，`/v1/taa/import` 的 `description`（`>-` 折叠块）末尾追加一行：

```yaml
        密态资源支持两种形态：resourceUrl 形如 <下载链接>?dataKeyCipher=<hex C1C3C2> 时，
        下载链接只含 SM4-GCM 密文，密钥信封由该参数给出，TAA 在下载前解析并解封，参数非法即返回 400 且不发起下载；
        未携带该参数时按整文件信封（WrappedKey || Ciphertext）处理。
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

- [ ] **Step 3: 补 architecture §5.2**

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
          ┌─── 解密 ─────────────────────────────────┐
          │  信封来源: URL 参数 dataKeyCipher / 文件头      │
          │  下载链接只含 SM4-GCM 密文                     │
          │  SM2 私钥解包信封 → SM4 数据密钥 (16B)           │
          │  SM4-GCM 解密 → 明文归档包                    │
          └────────┬───────────────────────────────┘
```

并在紧随其后的 ``` 闭合围栏之后、`### 5.3 导出流程 (\`/v1/taa/export\`)` 之前追加一段（§5.2 图后原本没有正文段落，这句就是唯一说明）：

```markdown
> 携带 `dataKeyCipher` 时，信封在**下载前**就已解封（见 `internal/controller/handler_task.go`）：格式非法或公钥不匹配直接返回 400，不消耗下载带宽；解密失败仍属异步阶段，经 `reportRes` 上报。
```

- [ ] **Step 4: 提交**

```bash
git add docs/api-design.md api/openapi.yaml docs/architecture-design.md
git commit -m "docs(api): document the URL-carried data key envelope"
```

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
Expected: 无未提交改动（`go.work` 与子模块不进版本控制），日志为本次 7 个提交

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
