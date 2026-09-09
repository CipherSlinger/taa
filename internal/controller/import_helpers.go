package controller

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	teecrypto "taa/crypto"
)

func sm3HexOfFile(path string) (string, error) {
	_, hex, err := teecrypto.HashFileSM3(path)
	if err != nil {
		return "", err
	}
	return hex, nil
}

func dataDirForHash(root, hash string) string {
	return filepath.Join(root, strings.TrimSpace(hash))
}

func resultDirForRequestTask(root, requestID, taskID string) string {
	return filepath.Join(root, safeFilenamePart(requestID)+"-"+safeFilenamePart(taskID))
}

func ensureArchiveExtractedIntoDir(dst, archivePath string) (bool, error) {
	if info, err := os.Stat(dst); err == nil {
		if info.IsDir() {
			return false, nil
		}
		return false, fmt.Errorf("target exists and is not a directory: %s", dst)
	} else if !os.IsNotExist(err) {
		return false, err
	}

	parent := filepath.Dir(dst)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return false, fmt.Errorf("create parent extraction dir: %w", err)
	}
	base := filepath.Base(dst)
	tmpDir, err := os.MkdirTemp(parent, base+".extract-*")
	if err != nil {
		return false, fmt.Errorf("create temp extraction dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := extractArchiveFile(tmpDir, archivePath); err != nil {
		return false, err
	}

	if err := os.Rename(tmpDir, dst); err != nil {
		if os.IsExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("move extracted package into %s: %w", dst, err)
	}
	return true, nil
}

func (s *TAAState) resolveTrainingRecord(req importRequest, isModel bool) (ImportIndexRecord, error) {
	store, err := s.importIndexStore()
	if err == nil {
		if !isModel {
			if record, err := store.Lookup(req.RequestID, req.TaskID); err == nil {
				return record, nil
			}
		}
		if req.TaskID != "" {
			if record, ok := store.LookupByTaskID(req.TaskID); ok {
				return record, nil
			}
		}
		if req.RequestID != "" {
			if record, ok := store.LookupByRequestID(req.RequestID); ok {
				return record, nil
			}
		}
	}

	s.mu.RLock()
	cur := s.CurrentDataRecord
	s.mu.RUnlock()
	if cur.RequestID != "" || cur.TaskID != "" || cur.DataDir != "" {
		return cur, nil
	}

	return ImportIndexRecord{
		RequestID: req.RequestID,
		TaskID:    req.TaskID,
		DataDir:   s.Security.DataDir,
		ResultDir: resultDirForRequestTask(s.Security.ResultDir, req.RequestID, req.TaskID),
	}, nil
}

// copyDir 将 srcDir 下的所有内容（文件、子目录、软链接）递归拷贝到 dstDir。
// 如果 dstDir 不存在，将以 0755 权限自动创建。
func copyDir(dstDir, srcDir string) error {
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

		return copyFile(targetPath, path, info.Mode().Perm())
	})
}

// copyFile 复制单个文件并保留权限
func copyFile(dst, src string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

// cleanDirContents 清空 dir 目录下的所有文件和子目录，保留 dir 目录本身
func cleanDirContents(dir string) error {
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
			return err
		}
	}
	return nil
}
