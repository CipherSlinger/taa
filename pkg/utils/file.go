// Package utils 提供与业务无关的通用文件、字符串、随机数与时间处理工具函数。
package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// SafeFilename 过滤文件名或路径片段中的非法字符与路径遍历尝试（如 ".."、"/"、"\"），
// 仅保留字母、数字、点、减号与下划线。若结果为空则回退为 "default"。
func SafeFilename(value string) string {
	value = strings.TrimSpace(value)
	mapped := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '-'
	}, value)
	mapped = strings.Trim(mapped, ".-")
	if mapped == "" {
		return "default"
	}
	return mapped
}

// CopyFile 将单个文件从 src 复制到 dst 并保留权限与执行位。
func CopyFile(dst, src string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src file %s: %w", src, err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("ensure dst parent dir for %s: %w", dst, err)
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("open dst file %s: %w", dst, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy content from %s to %s: %w", src, dst, err)
	}
	return out.Sync()
}

// CopyDir 将 srcDir 下的所有内容（文件、子目录、软链接）递归复制到 dstDir。
// 如果 dstDir 不存在，将以 0755 权限自动创建。
func CopyDir(dstDir, srcDir string) error {
	srcDir = filepath.Clean(srcDir)
	dstDir = filepath.Clean(dstDir)
	if srcDir == dstDir {
		return nil
	}

	srcInfo, err := os.Stat(srcDir)
	if err != nil {
		return fmt.Errorf("stat srcDir %s: %w", srcDir, err)
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("srcDir %s is not a directory", srcDir)
	}

	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return fmt.Errorf("mkdir dstDir %s: %w", dstDir, err)
	}

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if relPath == "." {
			return nil
		}

		targetPath := filepath.Join(dstDir, relPath)

		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("read link %s: %w", path, err)
			}
			return os.Symlink(linkTarget, targetPath)
		}

		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode().Perm())
		}

		return CopyFile(targetPath, path, info.Mode().Perm())
	})
}

// CleanDir 清空指定目录下的所有子文件和子目录，保留该目录本身。
func CleanDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(dir, 0o755)
		}
		return err
	}
	for _, entry := range entries {
		p := filepath.Join(dir, entry.Name())
		if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}
	return nil
}

// EnsureDir 确保目录存在，不存在则递归创建。
func EnsureDir(dir string, perm os.FileMode) error {
	if perm == 0 {
		perm = 0o755
	}
	return os.MkdirAll(dir, perm)
}
