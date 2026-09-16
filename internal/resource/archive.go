package resource

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	filetree "taa/pkg/filetree"
	pkgerrors "taa/pkg/errors"
	"taa/pkg/utils"
)

const (
	// DefaultMaxExtractBytes 解压累计最大安全配额 (2 GB)
	DefaultMaxExtractBytes int64 = 2 << 30
)

// ResourceURLHasEncSuffix 检查资源 URL 路径是否以 .enc 结尾
func ResourceURLHasEncSuffix(resourceURL string) bool {
	path := resourceURL
	if u, err := url.Parse(resourceURL); err == nil && u.Path != "" {
		path = u.Path
	}
	return strings.HasSuffix(strings.ToLower(path), ".enc")
}

// IsArchiveFile 检查文件是否为已知明文压缩包格式（ZIP / GZIP / TAR）
func IsArchiveFile(filePath string) (bool, error) {
	return filetree.IsArchiveFile(filePath)
}

// ExtractArchiveToDir 解压归档文件到指定目标目录（先解压到临时目录，成功后原子重命名替换）
func ExtractArchiveToDir(dst, filePath string) error {
	if strings.TrimSpace(dst) == "" {
		return fmt.Errorf("target destination dir is required")
	}

	parent := filepath.Dir(dst)
	base := filepath.Base(dst)
	tmpDir, err := os.MkdirTemp(parent, base+".extract-*")
	if err != nil {
		return fmt.Errorf("create temp extraction dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := ExtractArchiveFile(tmpDir, filePath); err != nil {
		return err
	}

	if err := ChmodScripts(tmpDir); err != nil {
		return fmt.Errorf("chmod scripts: %w", err)
	}

	if err := os.RemoveAll(dst); err != nil {
		return fmt.Errorf("clear target dir: %w", err)
	}
	if err := os.Rename(tmpDir, dst); err != nil {
		return fmt.Errorf("move extracted package into target dir: %w", err)
	}
	return nil
}

// EnsureArchiveExtractedIntoDir 确保归档安全解压至 dst 目录（幂等，若已存在且为目录则跳过）
func EnsureArchiveExtractedIntoDir(dst, archivePath string) (bool, error) {
	if info, err := os.Stat(dst); err == nil {
		if info.IsDir() {
			return false, nil
		}
		return false, pkgerrors.New(pkgerrors.CodeConflict, fmt.Sprintf("target exists and is not a directory: %s", dst))
	} else if !os.IsNotExist(err) {
		return false, pkgerrors.Wrap(pkgerrors.CodeInternal, "stat destination failed", err)
	}

	parent := filepath.Dir(dst)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return false, pkgerrors.Wrap(pkgerrors.CodeInternal, fmt.Sprintf("create parent extraction dir: %s", parent), err)
	}
	base := filepath.Base(dst)
	tmpDir, err := os.MkdirTemp(parent, base+".extract-*")
	if err != nil {
		return false, pkgerrors.Wrap(pkgerrors.CodeInternal, "create temp extraction dir", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := ExtractArchiveFile(tmpDir, archivePath); err != nil {
		return false, pkgerrors.Wrap(pkgerrors.CodeInternal, "extract archive failed", err)
	}

	if err := os.Rename(tmpDir, dst); err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, pkgerrors.Wrap(pkgerrors.CodeInternal, fmt.Sprintf("move extracted package into %s", dst), err)
	}
	return true, nil
}

// ExtractArchiveFile 从磁盘文件解压，根据 magic bytes 自动检测格式
func ExtractArchiveFile(dst, filePath string) error {
	log.Printf("extractArchiveFile: dst=%s, filePath=%s", dst, filePath)

	hdr := make([]byte, 512)
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	n, _ := f.Read(hdr)
	f.Close()
	hdr = hdr[:n]

	log.Printf("extractArchiveFile: read %d bytes header, first 4 bytes: %x", n, hdr[:min(4, len(hdr))])

	if n >= 2 {
		// ZIP: starts with "PK" (0x50 0x4B)
		if hdr[0] == 0x50 && hdr[1] == 0x4B {
			log.Printf("extractArchiveFile: detected ZIP format")
			data, err := os.ReadFile(filePath)
			if err != nil {
				return err
			}
			return ExtractZipArchive(dst, data)
		}
		// gzip: starts with 0x1F 0x8B — 流式读取
		if hdr[0] == 0x1F && hdr[1] == 0x8B {
			log.Printf("extractArchiveFile: detected gzip format, extracting...")
			f, err := os.Open(filePath)
			if err != nil {
				return err
			}
			defer f.Close()
			gz, err := gzip.NewReader(f)
			if err != nil {
				return err
			}
			defer gz.Close()
			err = ExtractTarStream(dst, gz)
			if err != nil {
				return err
			}
			count := 0
			_ = filepath.Walk(dst, func(path string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() {
					count++
				}
				return nil
			})
			log.Printf("extractArchiveFile: gzip extraction complete, %d files extracted to %s", count, dst)
			return nil
		}
	}
	// tar: check for "ustar" magic at offset 257 — 流式读取
	if n >= 263 && string(hdr[257:262]) == "ustar" {
		f, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer f.Close()
		return ExtractTarStream(dst, f)
	}

	// Fallback: 尝试 zip 和流式 tar.gz/tar
	if data, err := os.ReadFile(filePath); err == nil {
		if err := ExtractZipArchive(dst, data); err == nil {
			return nil
		}
	}
	if f, err := os.Open(filePath); err == nil {
		if gz, err := gzip.NewReader(f); err == nil {
			err = ExtractTarStream(dst, gz)
			_ = gz.Close()
			_ = f.Close()
			if err == nil {
				return nil
			}
		} else {
			_ = f.Close()
		}
	}
	if f, err := os.Open(filePath); err == nil {
		err = ExtractTarStream(dst, f)
		_ = f.Close()
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("unsupported archive format or extract failed")
}

// ExtractZipArchive 解压 ZIP 内存字节到目标目录，执行配额上限与目录逃逸校验
func ExtractZipArchive(dst string, data []byte) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	baseAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	var totalExtractedBytes int64
	for _, f := range r.File {
		target, err := SafeJoinWithBase(dst, baseAbs, f.Name)
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		remain := DefaultMaxExtractBytes - totalExtractedBytes
		if remain < 0 {
			_ = rc.Close()
			_ = utils.CleanDir(dst)
			return fmt.Errorf("解压累计字节超过上限 %d bytes", DefaultMaxExtractBytes)
		}
		written, err := WriteExtractedFileWithLimit(target, rc, f.Mode(), remain)
		_ = rc.Close()
		if err != nil {
			_ = utils.CleanDir(dst)
			return err
		}
		totalExtractedBytes += written
	}
	return nil
}

// ExtractTarStream 从流中解压 TAR 包，拦截软链接逃逸与超大解压炸弹
func ExtractTarStream(dst string, src io.Reader) error {
	baseAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	var totalExtractedBytes int64
	tr := tar.NewReader(src)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		target, err := SafeJoinWithBase(dst, baseAbs, hdr.Name)
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, hdr.FileInfo().Mode()); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			remain := DefaultMaxExtractBytes - totalExtractedBytes
			if remain < 0 {
				_ = utils.CleanDir(dst)
				return fmt.Errorf("解压累计字节超过上限 %d bytes", DefaultMaxExtractBytes)
			}
			written, err := WriteExtractedFileWithLimit(target, tr, hdr.FileInfo().Mode(), remain)
			if err != nil {
				_ = utils.CleanDir(dst)
				return err
			}
			totalExtractedBytes += written
		case tar.TypeSymlink, tar.TypeLink:
			return fmt.Errorf("unsupported archive entry type for %s", hdr.Name)
		default:
			// 忽略其他非关键条目
		}
	}
}

// WriteExtractedFileWithLimit 带大小配额限制写入文件
func WriteExtractedFileWithLimit(target string, src io.Reader, mode os.FileMode, maxBytes int64) (int64, error) {
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return 0, err
	}
	lr := io.LimitReader(src, maxBytes+1)
	n, err := io.Copy(out, lr)
	closeErr := out.Close()
	if err != nil {
		_ = os.Remove(target)
		return n, err
	}
	if closeErr != nil {
		_ = os.Remove(target)
		return n, closeErr
	}
	if n > maxBytes {
		_ = os.Remove(target)
		return n, fmt.Errorf("解压数据超过配额上限 %d bytes", DefaultMaxExtractBytes)
	}
	return n, nil
}

// SafeJoinWithBase 防 Zip-Slip 跨目录越界安全拼接
func SafeJoinWithBase(baseDir, baseAbs, name string) (string, error) {
	normalized := strings.ReplaceAll(name, "\\", "/")
	cleaned := filepath.Clean(filepath.FromSlash(normalized))
	if cleaned == "." || cleaned == string(filepath.Separator) {
		return baseDir, nil
	}
	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("archive entry has absolute path: %s", name)
	}
	full := filepath.Join(baseDir, cleaned)
	fullAbs, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	if fullAbs != baseAbs && !strings.HasPrefix(fullAbs, baseAbs+string(filepath.Separator)) {
		return "", fmt.Errorf("archive entry escapes destination: %s", name)
	}
	return full, nil
}

// ChmodScripts 为解压目录下所有 .sh 脚本补充执行权限
func ChmodScripts(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(info.Name()) == ".sh" {
			mode := info.Mode() | 0o111
			if err := os.Chmod(path, mode); err != nil {
				return fmt.Errorf("chmod %s: %w", path, err)
			}
			log.Printf("chmodScripts: added +x to %s (was %o, now %o)", path, info.Mode(), mode)
		}
		return nil
	})
}
