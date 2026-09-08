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
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	h := teecrypto.NewSM3()
	buf := make([]byte, 64*1024)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			if _, err := h.Write(buf[:n]); err != nil {
				return "", fmt.Errorf("hash %s: %w", path, err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", fmt.Errorf("read %s: %w", path, readErr)
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
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
