package controller

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"taa/internal/resource"
)

// processImportedResourceDataAnalysis lands an imported resource on a
// data-anaylsis instance and reports the outcome. It never trains, audits,
// checksums, or writes the import index: those belong to the tee pipeline.
func (s *TAAState) processImportedResourceDataAnalysis(req importRequest, plaintextPath string) {
	s.setCurrentOp("saving")
	s.Logs.Add(LogInfo, "import", "data-anaylsis: 开始落盘: dataResourceCode=%s, fileName=%s",
		req.DataAnalysisResourceCode, req.DataAnalysisFileName)

	if err := s.saveDataAnalysisResource(req, plaintextPath); err != nil {
		s.Logs.Add(LogError, "import", "data-anaylsis: 落盘失败: %v", err)
		s.reportDataAnalysisResult(req, 1, err.Error())
		return
	}

	s.Logs.Add(LogInfo, "import", "data-anaylsis: 落盘完成: dataResourceCode=%s", req.DataAnalysisResourceCode)
	s.reportDataAnalysisResult(req, 0, "数据导入成功")
}

// saveDataAnalysisResource extracts a package or copies a single file into
// <outputRoot>/<dataResourceCode>/.
//
// The name and code were already validated as single path elements when the
// delivery URL was parsed; SafeJoinWithBase is applied again here as defence in
// depth, since these values decide where bytes are written.
func (s *TAAState) saveDataAnalysisResource(req importRequest, plaintextPath string) error {
	// Imported data lands under storage.data, one subdirectory per resource code.
	// The default template points it at the Jupyter system-auth data directory.
	root := strings.TrimSpace(s.Security.DataDir)
	if root == "" {
		return fmt.Errorf("数据目录未配置 (storage.data)")
	}
	// ExtractArchiveToDir stages into a temp directory under the parent, so the
	// root has to exist even before the per-resource directory does.
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("创建数据落盘根目录失败: %w", err)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("解析数据落盘根目录失败: %w", err)
	}
	targetDir, err := resource.SafeJoinWithBase(root, rootAbs, req.DataAnalysisResourceCode)
	if err != nil {
		return fmt.Errorf("dataResourceCode 路径校验失败: %w", err)
	}

	archive, err := isArchiveFile(plaintextPath)
	if err != nil {
		return fmt.Errorf("检测资源格式失败: %w", err)
	}
	if archive && !isDocumentContainerFileName(req.DataAnalysisFileName) {
		// ExtractArchiveToDir extracts into a sibling temp directory and only
		// then replaces targetDir, so a failed extraction leaves the previous
		// contents intact.
		if err := resource.ExtractArchiveToDir(targetDir, plaintextPath); err != nil {
			return fmt.Errorf("解压资源失败: %w", err)
		}
		return nil
	}

	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return fmt.Errorf("创建数据目录失败: %w", err)
	}
	targetDirAbs, err := filepath.Abs(targetDir)
	if err != nil {
		return fmt.Errorf("解析数据目录失败: %w", err)
	}
	target, err := resource.SafeJoinWithBase(targetDir, targetDirAbs, req.DataAnalysisFileName)
	if err != nil {
		return fmt.Errorf("fileName 路径校验失败: %w", err)
	}
	if err := writeFileAtomic(target, plaintextPath, 0o644); err != nil {
		return fmt.Errorf("保存文件失败: %w", err)
	}
	return nil
}

// reportDataAnalysisResult reports through the same reportRes channel the tee
// path uses, with an empty report body: this instance type has no training
// report schema to describe.
func (s *TAAState) reportDataAnalysisResult(req importRequest, code int, msg string) {
	s.reportTrainingAsync(req.RequestID, req.TaskID, code, msg, "")
	s.setCurrentOp("idle")
}

// documentContainerExts are ZIP containers that are documents, not archives to
// unpack. A file with one of these extensions is saved verbatim even though its
// magic bytes are a ZIP header.
var documentContainerExts = map[string]struct{}{
	".docx": {}, ".docm": {}, ".dotx": {}, ".dotm": {},
	".xlsx": {}, ".xlsm": {}, ".xltx": {}, ".xltm": {}, ".xlsb": {},
	".pptx": {}, ".pptm": {}, ".potx": {}, ".potm": {}, ".ppsx": {}, ".ppsm": {},
	".odt": {}, ".ods": {}, ".odp": {}, ".odg": {}, ".odf": {},
	".ott": {}, ".ots": {}, ".otp": {}, ".otg": {},
	".epub": {},
}

func isDocumentContainerFileName(name string) bool {
	_, ok := documentContainerExts[strings.ToLower(filepath.Ext(name))]
	return ok
}

// writeFileAtomic copies src to a temp file beside dst and renames it into
// place, so a failed copy never leaves a truncated destination and an existing
// symlink is replaced rather than followed.
func writeFileAtomic(dst, src string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if tmpName != "" {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	tmpName = ""
	return nil
}
