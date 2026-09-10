package crypto

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestTarGzRoundTrip(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"a.txt":     "hello world",
		"sub/b.txt": "nested file",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(srcDir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	archivePath := filepath.Join(t.TempDir(), "test.tar.gz")
	if err := CreateTarGzArchive([]string{srcDir}, archivePath); err != nil {
		t.Fatalf("创建归档失败: %v", err)
	}

	info, err := os.Stat(archivePath)
	if err != nil {
		t.Fatalf("归档文件不存在: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("归档文件为空")
	}

	extractDir := t.TempDir()
	if err := ExtractTarGzArchive(archivePath, extractDir); err != nil {
		t.Fatalf("解压失败: %v", err)
	}

	baseName := filepath.Base(srcDir)
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(extractDir, baseName, name))
		if err != nil {
			t.Fatalf("读取解压文件 %s 失败: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("文件 %s 内容不匹配: got %q, want %q", name, got, want)
		}
	}
}

func TestTarGzEmptySources(t *testing.T) {
	err := CreateTarGzArchive(nil, "/dev/null")
	if err == nil {
		t.Fatal("空源列表应返回错误")
	}
}

func TestExtractTarGzReader(t *testing.T) {
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "test.txt"), []byte("reader test"), 0644); err != nil {
		t.Fatal(err)
	}

	archivePath := filepath.Join(t.TempDir(), "reader.tar.gz")
	if err := CreateTarGzArchive([]string{srcDir}, archivePath); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	extractDir := t.TempDir()
	if err := ExtractTarGzReader(bytes.NewReader(data), extractDir); err != nil {
		t.Fatalf("ExtractTarGzReader 失败: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(extractDir, filepath.Base(srcDir), "test.txt"))
	if err != nil {
		t.Fatalf("读取解压文件失败: %v", err)
	}
	if string(got) != "reader test" {
		t.Fatalf("内容不匹配: got %q", got)
	}
}

func TestZipExtract(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, err := zw.Create("z.txt")
	if err != nil {
		t.Fatal(err)
	}
	content := "zip test content"
	fw.Write([]byte(content))
	zw.Close()

	extractDir := t.TempDir()
	if err := ExtractZipArchive(buf.Bytes(), extractDir); err != nil {
		t.Fatalf("解压 zip 失败: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(extractDir, "z.txt"))
	if err != nil {
		t.Fatalf("读取解压文件失败: %v", err)
	}
	if string(got) != content {
		t.Fatalf("内容不匹配: got %q, want %q", got, content)
	}
}

func TestHMACSM3DifferentKeys(t *testing.T) {
	data := []byte("test message")
	key1 := []byte("key-one")
	key2 := []byte("key-two")

	h1 := HMACSM3(key1, data)
	h2 := HMACSM3(key2, data)
	if h1 == h2 {
		t.Fatal("不同密钥的 HMAC 结果应不同")
	}

	// 同一密钥+数据应确定性
	h3 := HMACSM3(key1, data)
	if h1 != h3 {
		t.Fatal("相同输入的 HMAC 结果应相同")
	}
}

func TestSM3SumDeterministic(t *testing.T) {
	data := []byte("deterministic check")
	d1 := SM3Sum(data)
	d2 := SM3Sum(data)
	if d1 != d2 {
		t.Fatal("SM3 摘要应确定性")
	}
}
