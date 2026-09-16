package controller

import (
	"os"
	"path/filepath"
	"strings"

	"taa/internal/resource"
	"taa/pkg/utils"
)

func sm3HexOfFile(path string) (string, error) {
	return resource.HashFileSM3(path)
}

func dataDirForHash(root, hash string) string {
	return filepath.Join(root, strings.TrimSpace(hash))
}

func resultDirForRequestTask(root, requestID, taskID string) string {
	return filepath.Join(root, safeFilenamePart(requestID)+"-"+safeFilenamePart(taskID))
}

func ensureArchiveExtractedIntoDir(dst, archivePath string) (bool, error) {
	return resource.EnsureArchiveExtractedIntoDir(dst, archivePath)
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
