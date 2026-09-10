package controller

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
	"taa/pkg/utils"
)

func sm3HexOfFile(path string) (string, error) {
	_, hex, err := teecrypto.HashFileSM3(path)
	if err != nil {
		return "", pkgerrors.Wrap(pkgerrors.CodeInternal, fmt.Sprintf("计算文件哈希失败: %s", path), err)
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

	if err := extractArchiveFile(tmpDir, archivePath); err != nil {
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
	return utils.CopyDir(dstDir, srcDir)
}

// copyFile 复制单个文件并保留权限
func copyFile(dst, src string, perm os.FileMode) error {
	return utils.CopyFile(dst, src, perm)
}

// cleanDirContents 清空 dir 目录下的所有文件和子目录，保留 dir 目录本身
func cleanDirContents(dir string) error {
	return utils.CleanDir(dir)
}
