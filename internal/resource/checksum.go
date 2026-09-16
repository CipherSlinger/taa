package resource

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
)

// HashFileSM3 计算指定文件的 SM3 哈希十六进制字符串
func HashFileSM3(filePath string) (string, error) {
	_, hex, err := teecrypto.HashFileSM3(filePath)
	if err != nil {
		return "", pkgerrors.Wrap(pkgerrors.CodeInternal, fmt.Sprintf("计算文件哈希失败: %s", filePath), err)
	}
	return hex, nil
}

// BuildDirectoryChecksum 计算目录树的校验和（默认 SM3），规范化忽略软链接与非普通文件，按相对路径字典序排序
func BuildDirectoryChecksum(dir, algorithm string) (map[string]any, error) {
	if algorithm == "" {
		algorithm = "sm3"
	}
	if strings.TrimSpace(dir) == "" {
		return map[string]any{"size": int64(0), "algorithm": algorithm, "value": "N/A"}, nil
	}

	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{"size": int64(0), "algorithm": algorithm, "value": "N/A"}, nil
		}
		return nil, fmt.Errorf("stat directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", dir)
	}

	h := teecrypto.NewSM3()
	files := make([]string, 0)
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var totalSize int64
	buf := make([]byte, 64*1024)
	for _, fpath := range files {
		rel, err := filepath.Rel(dir, fpath)
		if err != nil {
			return nil, fmt.Errorf("resolve relative path for %s: %w", fpath, err)
		}
		h.Write([]byte(filepath.ToSlash(rel)))
		h.Write([]byte{0})

		info, err := os.Lstat(fpath)
		if err != nil {
			return nil, fmt.Errorf("stat file %s: %w", fpath, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		totalSize += info.Size()

		f, err := os.Open(fpath)
		if err != nil {
			return nil, fmt.Errorf("open file %s: %w", fpath, err)
		}
		for {
			n, readErr := f.Read(buf)
			if n > 0 {
				if _, writeErr := h.Write(buf[:n]); writeErr != nil {
					_ = f.Close()
					return nil, fmt.Errorf("hash file %s: %w", fpath, writeErr)
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				_ = f.Close()
				return nil, fmt.Errorf("read file %s: %w", fpath, readErr)
			}
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("close file %s: %w", fpath, err)
		}
	}

	return map[string]any{
		"size":      totalSize,
		"algorithm": algorithm,
		"value":     fmt.Sprintf("%x", h.Sum(nil)),
	}, nil
}
