package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"taa/internal/attestation"
	teecrypto "taa/pkg/crypto"
	pkgerrors "taa/pkg/errors"
)

type switchRequest struct {
	Phase int `json:"phase"`
}

type getAttestationRequest struct {
	RequestID string `json:"requestId"`
}

type resourceInfoRequest struct {
	ResourceURL string `json:"resourceUrl"`
}

type reportResPlatformRequest struct {
	RequestID string  `json:"requestId"`
	Code      int     `json:"code"`
	Msg       *string `json:"msg"`
}

type logsRequest struct {
	Since *string `json:"since"` // optional ISO8601 timestamp
}

// ── Handler: /v1/taa/health ──────────────────────────────

func (s *TAAState) healthHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	phase := s.CurrentPhase
	modelImported := s.ModelImported
	trainingRunning := s.TrainingRunning
	currentOp := s.CurrentOp
	s.mu.RUnlock()

	writeEnvelope(w, http.StatusOK, "ok", map[string]any{
		"phase":           phase,
		"phaseName":       phaseName(phase),
		"modelImported":   modelImported,
		"trainingRunning": trainingRunning,
		"currentOp":       currentOp,
	}, 0)
}

// ── Handler: /v1/taa/logs ────────────────────────────────

func (s *TAAState) logsHandler(w http.ResponseWriter, r *http.Request) {
	var req logsRequest
	_ = json.NewDecoder(r.Body).Decode(&req) // ignore decode error — body may be empty

	var entries []LogEntry
	if req.Since != nil && *req.Since != "" {
		t, err := time.Parse(time.RFC3339, *req.Since)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("since 时间格式错误: %v", err))
			return
		}
		entries = s.Logs.Since(t)
	} else {
		entries = s.Logs.Drain()
	}

	s.mu.RLock()
	currentOp := s.CurrentOp
	s.mu.RUnlock()

	writeEnvelope(w, http.StatusOK, "ok", map[string]any{
		"logs":      entries,
		"currentOp": currentOp,
		"total":     len(entries),
	}, 0)
}

// ── Handler: /v1/taa/status ────────────────────────────��─

func (s *TAAState) statusHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	phase := s.CurrentPhase
	modelImported := s.ModelImported
	trainingRunning := s.TrainingRunning
	currentOp := s.CurrentOp
	s.mu.RUnlock()

	writeEnvelope(w, http.StatusOK, "ok", map[string]any{
		"phase":           phase,
		"phaseName":       phaseName(phase),
		"modelImported":   modelImported,
		"trainingRunning": trainingRunning,
		"currentOp":       currentOp,
		"logCount":        s.Logs.Count(),
	}, 0)
}

// ── Handler: /v1/taa/switch ──────────────────────────────

func (s *TAAState) switchHandler(w http.ResponseWriter, r *http.Request) {
	var req switchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, fmt.Sprintf("请求解析失败: %v", err), err))
		return
	}

	if req.Phase < 1 || req.Phase > 4 {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, fmt.Sprintf("无效的阶段值: %d，有效范围 1-4", req.Phase)))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isTrainingBusyLocked() || s.ActiveTaskID != "" || (s.CurrentOp != "" && s.CurrentOp != "idle") {
		task, op := s.activeTaskInfoLocked()
		writeErr(w, http.StatusConflict, pkgerrors.New(pkgerrors.CodeConflict,
			fmt.Sprintf("当前已有任务正在执行中 (taskId: %s, op: %s)，严禁切换运行阶段", task, op)))
		return
	}

	current := s.CurrentPhase
	s.CurrentPhase = req.Phase
	s.activeToken = 0
	s.ActiveTaskID = ""
	s.ActiveRequestID = ""
	s.activeTask = nil
	s.Logs.Add(LogInfo, "phase", "阶段切换: %d(%s) -> %d(%s)", current, phaseName(current), req.Phase, phaseName(req.Phase))

	if err := s.sealStateLocked(); err != nil {
		s.Logs.Add(LogError, "phase", "持久化阶段切换状态失败: %v", err)
	}

	writeEnvelope(w, http.StatusOK, "阶段切换成功", nil, 0)
}

// ── Handler: /v1/taa/getAttestation ──────────────────────

func (s *TAAState) buildAttestationResult(ctx context.Context, attestationFile string, userData []byte) ([]byte, string, bool, string) {
	generateCtx, generateCancel := context.WithTimeout(ctx, 30*time.Second)
	defer generateCancel()

	if err := attestation.Generate(generateCtx, attestation.Config{
		OutputPath: attestationFile,
		UserData:   userData,
	}); err != nil {
		log.Printf("get attestation failed: generate report: %v", err)
		return nil, "", false, "获取报告失败: " + err.Error()
	}

	reportData, err := os.ReadFile(attestationFile)
	if err != nil {
		log.Printf("get attestation failed: read report: %v", err)
		return nil, "", false, "获取报告失败: " + err.Error()
	}

	reportValues, err := attestation.ExtractReportValues(attestationFile)
	if err != nil {
		log.Printf("get attestation failed: extract report values: %v", err)
		return nil, "", false, "获取报告失败: " + err.Error()
	}

	formattedValues, err := formatAttestationValuesUserDataPEM(reportValues, userData)
	if err != nil {
		log.Printf("get attestation failed: format userdata as PEM: %v", err)
		return nil, "", false, "获取报告失败: " + err.Error()
	}

	verifiedPass := false
	var verifyMsg string
	if _, verifyErr := attestation.VerifyReport(reportData, s.HRKCertPath, s.HSKCekCertPath); verifyErr != nil {
		log.Printf("get attestation self-verification failed: %v", verifyErr)
		verifyMsg = "自检验证失败: " + verifyErr.Error()
	} else {
		log.Printf("get attestation self-verification passed")
		verifiedPass = true
		verifyMsg = "success"
	}

	return reportData, formattedValues, verifiedPass, verifyMsg
}

func (s *TAAState) getAttestationHandler(w http.ResponseWriter, r *http.Request) {
	var req getAttestationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, fmt.Sprintf("请求解析失败: %v", err), err))
		return
	}

	if req.RequestID == "" {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "requestId 不能为空"))
		return
	}

	s.mu.RLock()
	attestationFile := s.AttestationFile
	userData := s.UserData
	s.mu.RUnlock()

	// 同一时刻只允许一个 attestation 重新生成
	s.attestMu.Lock()
	defer s.attestMu.Unlock()

	reportData, reportValues, verifiedPass, msg := s.buildAttestationResult(r.Context(), attestationFile, userData)
	attestationBase64 := ""
	if len(reportData) > 0 {
		attestationBase64 = base64.StdEncoding.EncodeToString(reportData)
	}

	if verifiedPass {
		log.Printf("attestation report regenerated: requestId=%s report=%d bytes", req.RequestID, len(reportData))
	} else {
		log.Printf("attestation report downgraded: requestId=%s report=%d bytes msg=%s", req.RequestID, len(reportData), msg)
	}

	writeEnvelope(w, http.StatusOK, msg, map[string]any{
		"requestId":         req.RequestID,
		"verifiedPass":      verifiedPass,
		"attestation":       attestationBase64,
		"attestationValues": reportValues,
	}, 0)
}

// ── Handler: /v1/taa/getResourceInfo ──────────────────────

func (s *TAAState) resourceInfoHandler(w http.ResponseWriter, r *http.Request) {
	var req resourceInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, fmt.Sprintf("请求解析失败: %v", err), err))
		return
	}
	if req.ResourceURL == "" {
		writeErr(w, http.StatusBadRequest, pkgerrors.New(pkgerrors.CodeInvalidArgument, "resourceUrl 不能为空"))
		return
	}

	s.Logs.Add(LogInfo, "getResourceInfo", "收到资源信息获取请求: resourceUrl=%s", req.ResourceURL)

	s.setCurrentOp("downloading")
	s.Logs.Add(LogInfo, "getResourceInfo", "开始下载资源: %s", req.ResourceURL)
	ciphertextPath, size, err := downloadToTempFile(req.ResourceURL)
	if err != nil {
		s.Logs.Add(LogError, "getResourceInfo", "下载资源失败: %v", err)
		s.setCurrentOp("idle")
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("资源下载失败: %v", err))
		return
	}
	s.Logs.Add(LogInfo, "getResourceInfo", "下载完成 (%d bytes) -> %s", size, ciphertextPath)
	defer os.Remove(ciphertextPath)

	s.setCurrentOp("decrypting")
	plaintextPath, isDecrypted, err := s.resolvePlaintextResource(req.ResourceURL, ciphertextPath, "getResourceInfo")
	if err != nil {
		s.setCurrentOp("idle")
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if isDecrypted {
		defer os.Remove(plaintextPath)
	}

	s.setCurrentOp("analyzing")
	_, hash, err := teecrypto.HashFileSM3(plaintextPath)
	if err != nil {
		s.Logs.Add(LogError, "getResourceInfo", "计算资源压缩包哈希失败: %v", err)
		s.setCurrentOp("idle")
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("计算资源哈希失败: %v", err))
		return
	}

	dataDir := dataDirForHash(s.Security.DataDir, hash)
	extracted, err := ensureArchiveExtractedIntoDir(dataDir, plaintextPath)
	if err != nil {
		s.Logs.Add(LogError, "getResourceInfo", "展开 hash 数据目录失败: %v", err)
		s.setCurrentOp("idle")
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("解压资源失败: %v", err))
		return
	}
	if extracted {
		s.Logs.Add(LogInfo, "getResourceInfo", "hash 数据目录保存完成: %s (hash=%s)", dataDir, hash)
	} else {
		s.Logs.Add(LogInfo, "getResourceInfo", "hash 数据目录已存在，复用: %s (hash=%s)", dataDir, hash)
	}

	output, err := buildResourceInfoJSON(dataDir, plaintextPath)
	if err != nil {
		s.Logs.Add(LogError, "getResourceInfo", "生成资源树失败: %v", err)
		s.setCurrentOp("idle")
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("生成资源信息失败: %v", err))
		return
	}

	s.setCurrentOp("idle")
	s.Logs.Add(LogInfo, "getResourceInfo", "资源树分析完成，数据已持久化备份至 %s", dataDir)
	writeEnvelope(w, http.StatusOK, "ok", string(output), 0)
}
