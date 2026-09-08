package controller

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	teecrypto "taa/crypto"
	"taa/internal/codeaudit"
)

func (s *TAAState) processImportedResource(req importRequest, phase int, isModel bool, ciphertextPath string) {
	startedAt := time.Now().UTC()
	PhaseSeparator(fmt.Sprintf("Phase %d Import: taskId=%s", phase, req.TaskID))
	s.Logs.Add(LogInfo, "import", "收到资源导入请求: taskId=%s, requestId=%s, phase=%d, isModel=%v", req.TaskID, req.RequestID, phase, isModel)

	defer os.Remove(ciphertextPath)

	StepSeparator("Decrypt")
	s.setCurrentOp("decrypting")
	plaintextPath := ciphertextPath
	if resourceURLHasEncSuffix(req.ResourceURL) {
		s.Logs.Add(LogInfo, "decrypt", "资源 URL 以 .enc 结尾，开始解密资源: %s", ciphertextPath)
		decryptedPath, err := s.decryptResourceToTempFile(ciphertextPath)
		if err != nil {
			s.Logs.Add(LogError, "decrypt", "解密失败: %v", err)
			s.setCurrentOp("idle")
			s.reportImportFailure(req, phase, isModel, startedAt, fmt.Sprintf("解密资源失败: %v", err))
			return
		}
		plaintextPath = decryptedPath
		defer os.Remove(plaintextPath)
		s.Logs.Add(LogInfo, "decrypt", "解密成功 -> %s", plaintextPath)
	} else {
		s.Logs.Add(LogInfo, "decrypt", "资源 URL 非 .enc 后缀，跳过解密: %s", req.ResourceURL)
	}

	s.mu.Lock()
	if isModel {
		s.ModelImported = true
	} else {
		switch phase {
		case 1:
			s.DataImported = true
		case 2:
			s.DataImported = true
		case 3:
			s.TrainingDataImported = true
		}
	}
	s.mu.Unlock()

	targetDir := s.Security.DataDir
	if isModel {
		targetDir = s.Security.ModelDir
	}

	reportResultDir := filepath.Join(s.Security.ResultDir, "train")
	if phase == 1 {
		reportResultDir = filepath.Join(s.Security.ResultDir, "debug")
	}
	reportDataDir := s.Security.DataDir

	s.Logs.Add(LogInfo, "extract", "开始解压到: %s", targetDir)
	if err := extractArchiveToDir(targetDir, plaintextPath); err != nil {
		s.Logs.Add(LogError, "extract", "解压失败: %v", err)
		s.setCurrentOp("idle")
		s.reportImportFailure(req, phase, isModel, startedAt, fmt.Sprintf("解压资源失败: %v", err))
		return
	}
	s.Logs.Add(LogInfo, "extract", "解压成功")

	// 模型导入：解压完成后对模型代码执行安全审计，并将审计结果上报平台。
	if isModel {
		s.auditAndReportModelImport(req)
	}

	shouldTrain := false
	if phase == 1 {
		s.mu.RLock()
		modelImported := s.ModelImported
		dataImported := s.DataImported
		bothImported := modelImported && dataImported
		s.mu.RUnlock()
		if !bothImported {
			s.Logs.Add(LogInfo, "import", "阶段1: 等待模型和数据都导入完成后执行训练 (modelImported=%v, dataImported=%v)",
				modelImported, dataImported)
			s.setCurrentOp("idle")
			return
		}
		shouldTrain = true
	} else {
		if isModel {
			s.Logs.Add(LogInfo, "import", "阶段%d: 模型导入完成，等待数据导入后执行训练", phase)
			s.setCurrentOp("idle")
			return
		}
		shouldTrain = true
	}

	if !shouldTrain {
		s.setCurrentOp("idle")
		return
	}

	s.mu.RLock()
	runtimeConfigRaw := s.RuntimeConfig
	s.mu.RUnlock()
	cfg, env, err := parseRuntimeConfig(runtimeConfigRaw)
	if err != nil {
		s.Logs.Add(LogError, "train", "%v", err)
		s.setCurrentOp("idle")
		s.reportImportFailure(req, phase, isModel, startedAt, err.Error())
		return
	}

	StepSeparator("Run runtimeConfig")
	s.setCurrentOp("training")
	trainOutputDir := reportResultDir
	s.Logs.Add(LogInfo, "train", "开始执行 runtimeConfig: commands=%d, envKeys=%v, 数据目录: %s, 输出目录: %s", len(cfg.Commands), envKeys(env), s.Security.DataDir, trainOutputDir)
	if output, err := runRuntimeConfig(cfg, env, s.Security.ModelDir, s.Security.DataDir, trainOutputDir, req.TaskID, startedAt.UTC().Format(time.RFC3339)); err != nil {
		s.Logs.Add(LogError, "train", "执行 runtimeConfig 失败: %v\noutput: %s", err, output)
		s.setCurrentOp("idle")
		s.reportImportFailure(req, phase, isModel, startedAt, fmt.Sprintf("执行 runtimeConfig 失败: %v", err))
		return
	}
	s.Logs.Add(LogInfo, "train", "runtimeConfig 执行成功")

	StepSeparator("Build & Upload Report")
	s.setCurrentOp("reporting")
	s.Logs.Add(LogInfo, "report", "生成训练报告: taskId=%s", req.TaskID)
	finishedAt := time.Now().UTC()
	report, err := s.buildAndSaveTrainingReport(req.TaskID, startedAt, finishedAt, "succeeded", 0, "", s.getLastAudit(), true, true, reportResultDir, reportDataDir)
	if err != nil {
		s.Logs.Add(LogError, "report", "生成训练报告失败: %v", err)
		s.setCurrentOp("idle")
		return
	}
	s.Logs.Add(LogInfo, "report", "训练报告生成成功并写入 training_report.json (%d bytes)", len(report))

	s.Logs.Add(LogInfo, "report", "上报训练结果到平台: code=0, taskId=%s", req.TaskID)

	s.mu.Lock()
	s.TrainingDone = true
	s.mu.Unlock()

	s.reportTrainingAsync(req.RequestID, req.TaskID, 0, "", string(report))
	s.setCurrentOp("idle")
	s.Logs.Add(LogInfo, "import", "资源导入流程完成: taskId=%s", req.TaskID)
}

// auditAndReportModelImport 对解压后的模型代码执行安全审计（静态扫描 + 可选 LLM 语义验证），
// 并将审计结果通过 /v1/taa/reportModelImport 上报平台。
func (s *TAAState) auditAndReportModelImport(req importRequest) {
	s.setLastAudit(nil)
	if !s.Security.ScanEnabled {
		s.Logs.Add(LogInfo, "audit", "安全扫描未启用，跳过模型代码审计")
		return
	}

	cfg := s.Security.LLM
	StepSeparator("Code Audit")
	s.setCurrentOp("auditing")
	s.Logs.Add(LogInfo, "audit", "开始模型代码审计: dir=%s, llmEnabled=%v, policy=%s, failClosed=%v",
		s.Security.ModelDir, cfg.Enabled, cfg.Policy, cfg.FailClosed)

	// fail-closed：LLM 启用且要求不可用时阻断时，先探测 LLM 可用性；
	// 若不可用则直接判定失败，避免降级为纯静态扫描静默放行。
	if cfg.Enabled && cfg.FailClosed && !llmAvailable(cfg.Endpoint, cfg.Model) {
		s.Logs.Add(LogError, "audit", "LLM 服务不可用，按 fail-closed 策略上报失败: endpoint=%s model=%s", cfg.Endpoint, cfg.Model)
		s.reportModelImportAsync(req.RequestID, req.TaskID, 2, "LLM 服务不可用，按 fail-closed 策略上报失败", "")
		s.setCurrentOp("idle")
		return
	}

	audit, err := codeaudit.GenerateAuditReport(context.Background(), s.Security.ModelDir, cfg, newLLMClient(cfg))
	if err != nil {
		s.Logs.Add(LogError, "audit", "模型代码审计失败: %v", err)
		s.reportModelImportAsync(req.RequestID, req.TaskID, 2, fmt.Sprintf("代码审计失败: %v", err), "")
		s.setCurrentOp("idle")
		return
	}
	s.setLastAudit(audit)

	code := 0
	msg := audit.Conclusion.Summary
	if !audit.Conclusion.Passed {
		code = 2
	}
	s.Logs.Add(LogInfo, "audit", "审计完成: passed=%v, riskLevel=%s, totalFindings=%d",
		audit.Conclusion.Passed, audit.Conclusion.RiskLevel, audit.Conclusion.Statistics.TotalFindings)

	s.reportModelImportAsync(req.RequestID, req.TaskID, code, msg, auditReportJSON(audit))
	s.setCurrentOp("idle")
}

// reportModelImportAsync 异步将模型代码审计结果上报平台，避免阻塞导入流程。
func (s *TAAState) reportModelImportAsync(requestID, taskID string, code int, msg, report string) {
	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()
	log.Printf("reportModelImportAsync: scheduling audit report upload, platformIP=%s, dockerID=%s, requestID=%s, taskID=%s, code=%d, reportLen=%d",
		platformIP, dockerID, requestID, taskID, code, len(report))
	go func() {
		if err := ReportModelImport(context.Background(), platformIP, dockerID, requestID, taskID, code, msg, report); err != nil {
			log.Printf("reportModelImportAsync: report audit result failed: requestID=%s taskID=%s, err=%v", requestID, taskID, err)
		} else {
			log.Printf("reportModelImportAsync: report audit result succeeded: requestID=%s taskID=%s", requestID, taskID)
		}
	}()
}

// newLLMClient 根据配置创建 LLM 客户端；未启用或未配置端点时返回 nil（仅静态扫描）。
func newLLMClient(cfg codeaudit.LLMConfig) codeaudit.LLMClient {
	if cfg.Enabled && cfg.Endpoint != "" {
		return codeaudit.NewOllamaClient(cfg.Endpoint, cfg.Model, cfg.Timeout)
	}
	return nil
}

// auditReportJSON is implemented in codeaudit_projection.go.

// llmAvailable 探测 Ollama 服务是否就绪且模型已加载。
// 仅用于 fail-closed 预检，使用较短的超时避免长时间阻塞。
func llmAvailable(endpoint, model string) bool {
	if strings.TrimSpace(endpoint) == "" {
		return false
	}
	base := endpoint
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(strings.TrimRight(base, "/") + "/api/tags")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, _ := io.ReadAll(resp.Body)
	return strings.Contains(string(body), model) || model == ""
}

func (s *TAAState) reportImportFailure(req importRequest, phase int, isModel bool, startedAt time.Time, reason string) {
	s.Logs.Add(LogError, "import", "导入失败: %s", reason)
	s.clearImportedState(isModel, phase)
	if isModel {
		s.reportModelImportAsync(req.RequestID, req.TaskID, 1, reason, "")
		s.setCurrentOp("idle")
		return
	}
	resultDir := filepath.Join(s.Security.ResultDir, "train")
	if phase == 1 {
		resultDir = filepath.Join(s.Security.ResultDir, "debug")
	}
	s.reportTrainingFailureFromResult(req, startedAt, reason, s.getLastAudit(), true, true, resultDir, s.Security.DataDir)
	s.setCurrentOp("idle")
}

func resourceURLHasEncSuffix(resourceURL string) bool {
	path := resourceURL
	if u, err := url.Parse(resourceURL); err == nil && u.Path != "" {
		path = u.Path
	}
	return strings.HasSuffix(strings.ToLower(path), ".enc")
}

func (s *TAAState) clearImportedState(isModel bool, phase int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if isModel {
		s.ModelImported = false
		s.RuntimeConfig = ""
		return
	}
	switch phase {
	case 1, 2:
		s.DataImported = false
	case 3:
		s.TrainingDataImported = false
	}
}

func (s *TAAState) reportTrainingFailureFromResult(req importRequest, startedAt time.Time, reason string, audit *codeaudit.AuditReport, includeAudit bool, includeDataDir bool, resultDir, dataDir string) {
	s.Logs.Add(LogError, "import", "训练流程失败: %s", reason)
	s.Logs.Add(LogInfo, "report", "生成失败报告: taskId=%s", req.TaskID)
	finishedAt := time.Now().UTC()
	report, err := s.buildAndSaveTrainingReport(req.TaskID, startedAt, finishedAt, "failed", 1, reason, audit, includeAudit, includeDataDir, resultDir, dataDir)
	if err != nil {
		s.Logs.Add(LogError, "report", "生成失败报告失败: %v", err)
		return
	}
	s.Logs.Add(LogInfo, "report", "上报训练失败结果到平台: code=1, taskId=%s", req.TaskID)

	s.mu.Lock()
	s.TrainingDone = false
	s.mu.Unlock()

	s.reportTrainingAsync(req.RequestID, req.TaskID, 1, reason, string(report))
	s.setCurrentOp("idle")
}

func extractArchiveToDir(dst, filePath string) error {
	if strings.TrimSpace(dst) == "" {
		return fmt.Errorf("MODEL_DIR is required")
	}

	parent := filepath.Dir(dst)
	base := filepath.Base(dst)
	tmpDir, err := os.MkdirTemp(parent, base+".extract-*")
	if err != nil {
		return fmt.Errorf("create temp extraction dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := extractArchiveFile(tmpDir, filePath); err != nil {
		return err
	}

	// 给所有 .sh 文件补可执行权限（兼容 Windows 打包的归档）
	if err := chmodScripts(tmpDir); err != nil {
		return fmt.Errorf("chmod scripts: %w", err)
	}

	if err := os.RemoveAll(dst); err != nil {
		return fmt.Errorf("clear model dir: %w", err)
	}
	if err := os.Rename(tmpDir, dst); err != nil {
		return fmt.Errorf("move extracted package into model dir: %w", err)
	}
	return nil
}

// extractArchiveFile 从磁盘文件解压，根据 magic bytes 自动检测格式。
// tar/tar.gz 流式读取；zip 需要随机访问，加载到内存。
func extractArchiveFile(dst, filePath string) error {
	log.Printf("extractArchiveFile: dst=%s, filePath=%s", dst, filePath)

	// 读取文件头部用于格式检测。
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
			return extractZipArchive(dst, data)
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
			err = extractTarStream(dst, gz)
			if err != nil {
				return err
			}
			// Count extracted files
			count := 0
			filepath.Walk(dst, func(path string, info os.FileInfo, err error) error {
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
		return extractTarStream(dst, f)
	}

	// Fallback: 尝试 zip（需要内存）和流式 tar.gz/tar
	// 先尝试 zip
	if data, err := os.ReadFile(filePath); err == nil {
		if err := extractZipArchive(dst, data); err == nil {
			return nil
		}
	}
	// 尝试流式 tar.gz
	if f, err := os.Open(filePath); err == nil {
		if gz, err := gzip.NewReader(f); err == nil {
			err = extractTarStream(dst, gz)
			gz.Close()
			f.Close()
			if err == nil {
				return nil
			}
		} else {
			f.Close()
		}
	}
	// 尝试流式 tar
	if f, err := os.Open(filePath); err == nil {
		err = extractTarStream(dst, f)
		f.Close()
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("unsupported archive format or extract failed")
}

func extractZipArchive(dst string, data []byte) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	baseAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	for _, f := range r.File {
		target, err := safeJoinWithBase(dst, baseAbs, f.Name)
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
		err = writeExtractedFile(target, rc, f.Mode())
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func writeExtractedFile(target string, src io.Reader, mode os.FileMode) error {
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, src); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// chmodScripts walks a directory and adds the executable bit (+x) to all .sh files.
// This fixes archives created on Windows or without proper Unix permissions.
func chmodScripts(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(info.Name()) == ".sh" {
			mode := info.Mode() | 0o111 // add execute bit for owner/group/other
			if err := os.Chmod(path, mode); err != nil {
				return fmt.Errorf("chmod %s: %w", path, err)
			}
			log.Printf("chmodScripts: added +x to %s (was %o, now %o)", path, info.Mode(), mode)
		}
		return nil
	})
}

func extractTarStream(dst string, src io.Reader) error {
	baseAbs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	tr := tar.NewReader(src)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		target, err := safeJoinWithBase(dst, baseAbs, hdr.Name)
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
			if err := writeExtractedFile(target, tr, hdr.FileInfo().Mode()); err != nil {
				return err
			}
		case tar.TypeSymlink, tar.TypeLink:
			return fmt.Errorf("unsupported archive entry type for %s", hdr.Name)
		default:
			// Ignore other entry types.
		}
	}
}

func safeJoinWithBase(baseDir, baseAbs, name string) (string, error) {
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

func (s *TAAState) buildAndSaveTrainingReport(taskID string, startedAt, finishedAt time.Time, status string, exitCode int, failureReason string, audit *codeaudit.AuditReport, includeAudit bool, includeDataDir bool, resultDir, dataDir string) ([]byte, error) {
	trainingResult, err := loadTrainingResult(filepath.Join(resultDir, "training_result.json"))
	if err != nil {
		return nil, err
	}

	dataset, err := s.loadResourceDataset(context.Background(), dataDir, includeDataDir)
	if err != nil {
		return nil, err
	}
	trainingResult["dataset"] = dataset

	modelChecksum, err := buildDirectoryChecksum(s.Security.ModelDir, "sm3")
	if err != nil {
		return nil, err
	}

	report, err := buildTrainingReport(taskID, startedAt, finishedAt, status, exitCode, failureReason, modelChecksum, trainingResult, audit, includeAudit)
	if err != nil {
		return nil, err
	}
	if err := writeJSONFile(filepath.Join(resultDir, "training_report.json"), report); err != nil {
		return nil, err
	}
	return json.Marshal(report)
}

func buildDirectoryChecksum(dir, algorithm string) (map[string]any, error) {
	if strings.TrimSpace(dir) == "" {
		return map[string]any{"size": 0, "algorithm": algorithm, "value": "N/A"}, nil
	}

	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{"size": 0, "algorithm": algorithm, "value": "N/A"}, nil
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
					f.Close()
					return nil, fmt.Errorf("hash file %s: %w", fpath, writeErr)
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				f.Close()
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

func loadTrainingResult(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("read training_result.json: %w", err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parse training_result.json: %w", err)
	}
	if result == nil {
		result = map[string]any{}
	}
	return result, nil
}

func buildTrainingReport(taskID string, startedAt, finishedAt time.Time, status string, exitCode int, failureReason string, modelChecksum map[string]any, trainingResult map[string]any, audit *codeaudit.AuditReport, includeAudit bool) (map[string]any, error) {
	if taskID == "" {
		taskID = "task-20260825-001"
	}
	if status == "" {
		status = "succeeded"
	}
	if status != "succeeded" && strings.TrimSpace(failureReason) == "" {
		failureReason = "训练流程失败"
	}

	trainingTaskSource := objectField(trainingResult, "training_task")
	trainingTask := make(map[string]any, len(trainingTaskSource)+7)
	for key, value := range trainingTaskSource {
		if value != nil {
			trainingTask[key] = value
		}
	}
	trainingTask["task_id"] = taskID
	trainingTask["started_at"] = startedAt.UTC().Format(time.RFC3339)
	trainingTask["finished_at"] = finishedAt.UTC().Format(time.RFC3339)
	trainingTask["duration_seconds"] = durationSeconds(startedAt, finishedAt)
	trainingTask["status"] = status
	trainingTask["exit_code"] = exitCode
	trainingTask["failure_reason"] = nullableString(failureReason)

	trainingTaskMetrics := objectField(trainingTaskSource, "metrics")
	if len(trainingTaskMetrics) == 0 {
		trainingTaskMetrics = objectField(trainingResult, "metrics")
	}
	if len(trainingTaskMetrics) > 0 {
		trainingTask["metrics"] = trainingTaskMetrics
	}

	if modelChecksum != nil {
		trainingTask["model_checksum"] = modelChecksum
	}

	report := map[string]any{
		"report_id":      newTrainingReportID(finishedAt),
		"generated_at":   finishedAt.UTC().Format(time.RFC3339),
		"schema_version": "1.0",
		"training_task":  trainingTask,
		"dataset":        objectField(trainingResult, "dataset"),
	}

	if includeAudit && audit != nil {
		if projected := projectCodeAuditSection(audit); projected != nil {
			report["codeaudit"] = projected
		}
	}

	return report, nil
}

func objectField(src map[string]any, key string) map[string]any {
	if src == nil {
		return map[string]any{}
	}
	if v, ok := src[key].(map[string]any); ok {
		return v
	}
	return map[string]any{}
}

func durationSeconds(startedAt, finishedAt time.Time) int64 {
	if startedAt.IsZero() || finishedAt.IsZero() {
		return 0
	}
	d := int64(finishedAt.Sub(startedAt).Seconds())
	if d < 0 {
		return 0
	}
	return d
}

func writeJSONFile(path string, payload any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create report dir: %w", err)
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report json: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

func newTrainingReportID(now time.Time) string {
	stamp := now.UTC().Format("20060102-150405")
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("train-report-%s-00000000", stamp)
	}
	return fmt.Sprintf("train-report-%s-%x", stamp, b[:])
}

func nullableString(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}
