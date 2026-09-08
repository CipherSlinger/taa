package controller

import (
	"fmt"
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
