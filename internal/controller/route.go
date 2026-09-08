package controller

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	teecrypto "taa/crypto"
	"taa/internal/attestation"
	"taa/internal/codeaudit"
)

// maxDownloadBytes 限制单次资源下载的最大字节数，防止 OOM。
const maxDownloadBytes = 512 << 20 // 512 MB

// scriptTimeout 是脚本执行的统一超时时间。
const scriptTimeout = 10 * time.Minute

// ── 公共返回格式 ──────────────────────────────────────────

type apiResponse struct {
	Msg    string `json:"msg"`
	Result any    `json:"result"`
	Error  int    `json:"error"`
}

// ── TAA 全局状态 ──────────────────────────────────────────

// SecurityConfig holds immutable security settings configured at startup.
// Separated from TAAState so it doesn't need the phase mutex and can't be
// accidentally left at zero values.
type SecurityConfig struct {
	ScanEnabled bool                // 是否在 import type=1 时执行源码安全扫描
	ModelDir    string              // 模型代码存放目录（扫描目标，type=1）
	DataDir     string              // 数据目录（type=2 测试数据，type=3 训练数据，用于数据指纹比对）
	ResultCheck bool                // 是否在 export 时检查明文数据泄露
	ResultDir   string              // 训练结果目录（导出前检查）
	LLM         codeaudit.LLMConfig // 本地 LLM 语义验证配置
}

type TAAState struct {
	mu                   sync.RWMutex
	attestMu             sync.Mutex
	importIndexOnce      sync.Once
	CurrentPhase         int
	ModelImported        bool
	DataImported         bool
	TrainingDataImported bool
	TrainingDone         bool
	AttestationFile      string
	HelperPath           string
	HelperMode           string
	PlatformIP           string
	DockerID             string
	SM2PrivateKey        *teecrypto.SM2PrivateKey // TAA 启动时生成的 SM2 私钥，用于解密资源信封
	UserData             []byte                   // TAA 启动时生成的 64 字节 USERDATA，用于重新生成远程证明报告
	ExportPublicKey      string                   // phase1 import 时保存的公钥，phase3 export 时使用
	RuntimeConfig        string                   // importModel 保存的运行配置，训练时按该配置执行命令
	Security             SecurityConfig           // immutable after startup — no mutex needed
	Logs                 *LogStore                // 结构化日志存储
	LastAudit            *codeaudit.AuditReport   // 最近一次模型代码审计结果，用于训练报告输出
	CurrentDataRecord    ImportIndexRecord        // 当前绑定的数据导入记录
	ModelChecksum        map[string]any           // 模型压缩包校验和 (size, algorithm, value)
	CurrentOp            string                   // 当前操作: idle/downloading/decrypting/extracting/debugging/training/auditing/reporting
	importIndex          *ImportIndexStore
	importIndexErr       error
}

func (s *TAAState) setModelChecksum(checksum map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ModelChecksum = checksum
}

func (s *TAAState) getModelChecksum() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ModelChecksum == nil {
		return nil
	}
	out := make(map[string]any, len(s.ModelChecksum))
	for k, v := range s.ModelChecksum {
		out[k] = v
	}
	return out
}

func NewTAAState(attestationFile, platformIP, dockerID, helperPath, helperMode string, sm2Key *teecrypto.SM2PrivateKey, userData []byte, sec SecurityConfig) *TAAState {
	return &TAAState{
		CurrentPhase:    1,
		AttestationFile: attestationFile,
		HelperPath:      helperPath,
		HelperMode:      helperMode,
		PlatformIP:      platformIP,
		DockerID:        dockerID,
		SM2PrivateKey:   sm2Key,
		UserData:        userData,
		Security:        sec,
		Logs:            NewLogStore(1000),
		CurrentOp:       "idle",
	}
}

// ── 请求结构体 ────────────────────────────────────────────

type switchRequest struct {
	Phase int `json:"phase"`
}

type importRequest struct {
	ResourceURL   string  `json:"resourceUrl"`
	RequestID     string  `json:"requestId"`
	TaskID        string  `json:"taskId"`
	PublicKey     *string `json:"publicKey,omitempty"`
	RuntimeConfig string  `json:"runtimeConfig,omitempty"`
}

type runtimeConfig struct {
	Commands []string `json:"commands"`
	Env      string   `json:"env"`
}

type exportRequest struct {
	PublicKey *string `json:"publicKey"`
	RequestID string  `json:"requestId"`
	TaskID    string  `json:"taskId"`
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

// ── 路由注册 ─────────────────────────────────────────────

func RegisterRoutes(mux *http.ServeMux, state *TAAState) {
	taaRoutes := []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/v1/taa/health", state.healthHandler},
		// {"/v1/taa/reportRes", state.reportResHandler}, // /v1/taa/reportRes 为 TAA -> 平台上报接口，TAA 服务端不再接收该路径。
		{"/v1/taa/import", state.importHandler},
		{"/v1/taa/importModel", state.modelImportHandler},
		{"/v1/taa/getResourceInfo", state.resourceInfoHandler},
		{"/v1/taa/switch", state.switchHandler},
		{"/v1/taa/export", state.exportHandler},
		{"/v1/taa/getAttestation", state.getAttestationHandler},
		{"/v1/taa/logs", state.logsHandler},
		{"/v1/taa/status", state.statusHandler},
	}

	for _, route := range taaRoutes {
		mux.HandleFunc(route.path, postOnly(route.handler))
	}
}

func postOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Disposition, Content-Length, X-TAA-Task-Id, X-TAA-Encrypted")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, apiResponse{
				Msg:    "仅支持 POST 方法",
				Result: nil,
				Error:  http.StatusMethodNotAllowed,
			})
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, resp apiResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func writeEnvelope(w http.ResponseWriter, status int, msg string, result any, errorCode int) {
	writeJSON(w, status, apiResponse{Msg: msg, Result: result, Error: errorCode})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeEnvelope(w, status, msg, nil, status)
}

func phaseName(phase int) string {
	switch phase {
	case 1:
		return "调试"
	case 2:
		return "测试"
	case 3:
		return "正式训练"
	case 4:
		return "推理"
	default:
		return fmt.Sprintf("未知(%d)", phase)
	}
}

// ── Handler: /v1/taa/health ──────────────────────────────

func (s *TAAState) healthHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	phase := s.CurrentPhase
	modelImported := s.ModelImported
	dataImported := s.DataImported
	trainingDone := s.TrainingDone
	currentOp := s.CurrentOp
	s.mu.RUnlock()

	writeEnvelope(w, http.StatusOK, "ok", map[string]any{
		"phase":         phase,
		"phaseName":     phaseName(phase),
		"modelImported": modelImported,
		"dataImported":  dataImported,
		"trainingDone":  trainingDone,
		"currentOp":     currentOp,
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

// ── Handler: /v1/taa/status ──────────────────────────────

func (s *TAAState) statusHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	phase := s.CurrentPhase
	modelImported := s.ModelImported
	dataImported := s.DataImported
	trainingDataImported := s.TrainingDataImported
	trainingDone := s.TrainingDone
	currentOp := s.CurrentOp
	s.mu.RUnlock()

	writeEnvelope(w, http.StatusOK, "ok", map[string]any{
		"phase":                phase,
		"phaseName":            phaseName(phase),
		"modelImported":        modelImported,
		"dataImported":         dataImported,
		"trainingDataImported": trainingDataImported,
		"trainingDone":         trainingDone,
		"currentOp":            currentOp,
		"logCount":             s.Logs.Count(),
	}, 0)
}

// setCurrentOp is a helper to update the current operation.
func (s *TAAState) setCurrentOp(op string) {
	s.mu.Lock()
	s.CurrentOp = op
	s.mu.Unlock()
}

// ── Handler: /v1/taa/switch ──────────────────────────────

func (s *TAAState) switchHandler(w http.ResponseWriter, r *http.Request) {
	var req switchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("请求解析失败: %v", err))
		return
	}

	if req.Phase < 1 || req.Phase > 4 {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("无效的阶段值: %d，有效范围 1-4", req.Phase))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	current := s.CurrentPhase
	s.CurrentPhase = req.Phase
	s.Logs.Add(LogInfo, "phase", "阶段切换: %d(%s) -> %d(%s)", current, phaseName(current), req.Phase, phaseName(req.Phase))

	writeEnvelope(w, http.StatusOK, "阶段切换成功", nil, 0)
}

// ── Handler: /v1/taa/import ──────────────────────────────

func (s *TAAState) importHandler(w http.ResponseWriter, r *http.Request) {
	var req importRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("请求解析失败: %v", err))
		return
	}
	req.ResourceURL = strings.TrimSpace(req.ResourceURL)
	req.RequestID = strings.TrimSpace(req.RequestID)
	req.TaskID = strings.TrimSpace(req.TaskID)
	if req.ResourceURL == "" {
		writeError(w, http.StatusBadRequest, "resourceUrl 不能为空")
		return
	}
	if req.RequestID == "" && req.TaskID == "" {
		writeError(w, http.StatusBadRequest, "requestId 和 taskId 不能同时为空")
		return
	}

	store, err := s.importIndexStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("加载导入索引失败: %v", err))
		return
	}
	if err := store.Reserve(req.RequestID, req.TaskID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.mu.RLock()
	phase := s.CurrentPhase
	s.mu.RUnlock()

	s.Logs.Add(LogInfo, "import", "收到数据 import 请求: taskId=%s, requestId=%s, phase=%d",
		req.TaskID, req.RequestID, phase)

	if strings.TrimSpace(req.RuntimeConfig) != "" {
		s.mu.Lock()
		s.RuntimeConfig = req.RuntimeConfig
		s.mu.Unlock()
		s.Logs.Add(LogInfo, "import", "已保存 runtimeConfig (长度=%d)", len(req.RuntimeConfig))
	}

	msg := "资源已接收，下载处理中"
	s.setCurrentOp("downloading")
	s.Logs.Add(LogInfo, "import", "开始下载资源: %s", req.ResourceURL)
	ciphertextPath, size, err := downloadToTempFile(req.ResourceURL)
	if err != nil {
		store.Rollback(req.RequestID, req.TaskID)
		s.Logs.Add(LogError, "import", "下载资源失败: %v", err)
		s.setCurrentOp("idle")
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("下载资源失败: %v", err))
		return
	}
	s.Logs.Add(LogInfo, "import", "下载完成 (%d bytes) -> %s", size, ciphertextPath)

	msg = "数据已接收，训练结果将通过 reportRes 上报"
	writeEnvelope(w, http.StatusOK, msg, nil, 0)

	go s.processImportedResource(req, phase, false, ciphertextPath)
}

// ── Handler: /v1/taa/importModel ─────────────────────────

func (s *TAAState) modelImportHandler(w http.ResponseWriter, r *http.Request) {
	var req importRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("请求解析失败: %v", err))
		return
	}
	req.ResourceURL = strings.TrimSpace(req.ResourceURL)
	req.RequestID = strings.TrimSpace(req.RequestID)
	req.TaskID = strings.TrimSpace(req.TaskID)
	if req.ResourceURL == "" {
		writeError(w, http.StatusBadRequest, "resourceUrl 不能为空")
		return
	}
	if req.RequestID == "" && req.TaskID == "" {
		writeError(w, http.StatusBadRequest, "requestId 和 taskId 不能同时为空")
		return
	}

	s.mu.RLock()
	phase := s.CurrentPhase
	s.mu.RUnlock()

	var publicKey string
	if phase == 1 && req.PublicKey != nil && *req.PublicKey != "" {
		if _, err := teecrypto.ParseSM2PublicKeyPEM([]byte(*req.PublicKey)); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("publicKey 解析失败: %v", err))
			return
		}
		publicKey = *req.PublicKey
		s.mu.Lock()
		if s.ExportPublicKey == "" {
			s.ExportPublicKey = publicKey
			s.Logs.Add(LogInfo, "importModel", "阶段1: 已保存 ExportPublicKey 用于后续阶段3导出 (长度=%d)\n%s", len(publicKey), publicKey)
		} else {
			s.Logs.Add(LogInfo, "importModel", "阶段1: ExportPublicKey 已存在，跳过保存 (已有长度=%d, 新长度=%d)", len(s.ExportPublicKey), len(publicKey))
		}
		s.mu.Unlock()
	} else if phase == 1 {
		s.Logs.Add(LogWarn, "importModel", "阶段1: 未提供 publicKey，后续阶段3导出可能失败")
	}

	s.Logs.Add(LogInfo, "importModel", "收到模型 import 请求: taskId=%s, requestId=%s, phase=%d",
		req.TaskID, req.RequestID, phase)

	s.mu.Lock()
	s.RuntimeConfig = req.RuntimeConfig
	s.mu.Unlock()
	if strings.TrimSpace(req.RuntimeConfig) == "" {
		s.Logs.Add(LogWarn, "importModel", "runtimeConfig 为空，后续训练将失败")
	} else {
		s.Logs.Add(LogInfo, "importModel", "已保存 runtimeConfig (长度=%d)", len(req.RuntimeConfig))
	}

	s.setCurrentOp("downloading")
	s.Logs.Add(LogInfo, "importModel", "开始下载资源: %s", req.ResourceURL)
	ciphertextPath, size, err := downloadToTempFile(req.ResourceURL)
	if err != nil {
		s.Logs.Add(LogError, "importModel", "下载资源失败: %v", err)
		s.setCurrentOp("idle")
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("下载资源失败: %v", err))
		return
	}
	s.Logs.Add(LogInfo, "importModel", "下载完成 (%d bytes) -> %s", size, ciphertextPath)

	msg := "模型已接收，训练结果将通过 reportRes 上报"
	writeEnvelope(w, http.StatusOK, msg, nil, 0)

	go s.processImportedResource(req, phase, true, ciphertextPath)
}

// downloadToTempFile 将资源从 URL 流式写入临时文件，避免将整个文件加载到内存。
// 返回临时文件路径，调用方负责删除。
func downloadToTempFile(resourceURL string) (string, int64, error) {
	resp, err := http.Get(resourceURL)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > maxDownloadBytes {
		return "", 0, fmt.Errorf("资源过大: %d bytes, 上限 %d bytes", resp.ContentLength, maxDownloadBytes)
	}

	f, err := os.CreateTemp("", "taa-download-*")
	if err != nil {
		return "", 0, fmt.Errorf("创建临时文件失败: %w", err)
	}
	path := f.Name()

	var reader io.Reader = resp.Body
	if resp.ContentLength >= 0 {
		reader = io.LimitReader(resp.Body, resp.ContentLength+1)
	}
	n, err := io.Copy(f, reader)
	f.Close()
	if err != nil {
		os.Remove(path)
		return "", 0, fmt.Errorf("下载写入失败: %w", err)
	}
	if n > maxDownloadBytes {
		os.Remove(path)
		return "", 0, fmt.Errorf("资源超过大小上限: %d bytes > %d bytes", n, maxDownloadBytes)
	}
	return path, n, nil
}

// decryptResourceToTempFile 从磁盘密文文件中读取 SM2+SM4-GCM 封装密文，
// 用 TAA SM2 私钥解密，将明文写入临时文件。返回明文文件路径，调用方负责删除。
// 资源格式：WrappedKey(SM2WrappedKeySize 字节) || Ciphertext(剩余字节)
func (s *TAAState) decryptResourceToTempFile(ciphertextPath string) (string, error) {
	f, err := os.Open(ciphertextPath)
	if err != nil {
		return "", fmt.Errorf("打开密文文件: %w", err)
	}
	defer f.Close()

	// 读取完整密文到内存，交给一步式接口拆包并解密。
	sealed, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("读取密文: %w", err)
	}

	log.Printf("decrypt debug: sealed=%d bytes (first 16: %x)",
		len(sealed), sealed[:min(16, len(sealed))])

	if s.SM2PrivateKey != nil {
		if pubPEM, err := teecrypto.MarshalSM2PublicKeyPEM(&s.SM2PrivateKey.PublicKey); err != nil {
			log.Printf("decrypt debug: marshal TAA public key failed: %v", err)
			s.Logs.Add(LogError, "decrypt", "打印 TAA 公钥失败: %v", err)
		} else {
			log.Printf("decrypt debug: TAA public key:\n%s", pubPEM)
			s.Logs.Add(LogInfo, "decrypt", "TAA 公钥:\n%s", pubPEM)
		}
	}

	// 用 TAA SM2 私钥直接解密 SM2+SM4-GCM 密文。
	plaintext, err := teecrypto.OpenSM2SM4GCM(s.SM2PrivateKey, sealed)
	sealed = nil // 释放密文内存
	if err != nil {
		return "", err
	}

	// 明文写入临时文件后立即释放明文内存。
	out, err := os.CreateTemp("", "taa-plaintext-*")
	if err != nil {
		plaintext = nil
		return "", fmt.Errorf("创建明文临时文件: %w", err)
	}
	plainPath := out.Name()
	if _, err := out.Write(plaintext); err != nil {
		out.Close()
		os.Remove(plainPath)
		plaintext = nil
		return "", err
	}
	out.Close()
	plaintext = nil

	return plainPath, nil
}

func (s *TAAState) reportTrainingAsync(requestID, taskID string, code int, msg, report string) {
	s.mu.RLock()
	platformIP, dockerID := s.PlatformIP, s.DockerID
	s.mu.RUnlock()
	log.Printf("reportTrainingAsync: scheduling report upload, platformIP=%s, dockerID=%s, requestID=%s, taskID=%s, code=%d, reportLen=%d",
		platformIP, dockerID, requestID, taskID, code, len(report))
	go func() {
		log.Printf("reportTrainingAsync: calling ReportRes, requestID=%s, taskID=%s", requestID, taskID)
		if err := ReportRes(nil, platformIP, dockerID, requestID, taskID, code, msg, report); err != nil {
			log.Printf("reportTrainingAsync: report training result failed: requestID=%s, taskID=%s, err=%v", requestID, taskID, err)
		} else {
			log.Printf("reportTrainingAsync: report upload succeeded: requestID=%s, taskID=%s", requestID, taskID)
		}
	}()
}

// ── Handler: /v1/taa/export ──────────────────────────────

func (s *TAAState) exportHandler(w http.ResponseWriter, r *http.Request) {
	var req exportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("请求解析失败: %v", err))
		return
	}
	req.RequestID = strings.TrimSpace(req.RequestID)
	req.TaskID = strings.TrimSpace(req.TaskID)
	if req.RequestID == "" && req.TaskID == "" {
		writeError(w, http.StatusBadRequest, "requestId 和 taskId 不能同时为空")
		return
	}

	store, err := s.importIndexStore()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("加载导入索引失败: %v", err))
		return
	}

	record, err := store.Lookup(req.RequestID, req.TaskID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if _, err := os.Stat(filepath.Join(record.ResultDir, "training_report.json")); err != nil {
		if os.IsNotExist(err) {
			writeError(w, http.StatusNotFound, fmt.Sprintf("结果文件不存在: %s", filepath.Join(record.ResultDir, "training_report.json")))
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("检查结果文件失败: %v", err))
		return
	}

	s.Logs.Add(LogInfo, "export", "收到导出请求: requestId=%s, taskId=%s, hash=%s, resultDir=%s", req.RequestID, req.TaskID, record.Hash, record.ResultDir)

	resultData, err := compressDirToTarGz(record.ResultDir)
	if err != nil {
		s.Logs.Add(LogError, "export", "压缩结果目录失败: %v", err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("压缩结果目录失败: %v", err))
		return
	}

	filename := filepath.Base(record.ResultDir) + ".tar.gz"
	var pubKeyPEM string
	var encrypt bool
	if req.PublicKey != nil && strings.TrimSpace(*req.PublicKey) != "" {
		pubKeyPEM = strings.TrimSpace(*req.PublicKey)
		encrypt = true
		s.Logs.Add(LogInfo, "export", "使用请求中的 publicKey 加密 (长度=%d)", len(pubKeyPEM))
	} else {
		s.Logs.Add(LogInfo, "export", "未传入 publicKey，返回明文")
	}

	if encrypt {
		pub, err := teecrypto.ParseSM2PublicKeyPEM([]byte(pubKeyPEM))
		if err != nil {
			s.Logs.Add(LogError, "export", "publicKey 解析失败: %v", err)
			writeError(w, http.StatusBadRequest, fmt.Sprintf("publicKey 解析失败: %v", err))
			return
		}
		sealed, err := teecrypto.SealSM2SM4GCM(pub, resultData)
		if err != nil {
			s.Logs.Add(LogError, "export", "加密失败: %v", err)
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("加密失败: %v", err))
			return
		}
		filename += ".enc"
		s.Logs.Add(LogInfo, "export", "加密完成: 明文=%d bytes, 密文=%d bytes, taskId=%s, filename=%s", len(resultData), len(sealed), req.TaskID, filename)
		writeFileStream(w, req.TaskID, filename, true, int64(len(sealed)), bytes.NewReader(sealed), "导出加密结果失败")
		return
	}

	s.Logs.Add(LogInfo, "export", "明文导出: 大小=%d bytes, taskId=%s, filename=%s", len(resultData), req.TaskID, filename)
	writeFileStream(w, req.TaskID, filename, false, int64(len(resultData)), bytes.NewReader(resultData), "导出明文结果失败")
}

// compressDirToTarGz 将目录压缩为 tar.gz 格式的字节切片。
func compressDirToTarGz(srcDir string) ([]byte, error) {
	log.Printf("compressDirToTarGz: 开始压缩目录: %s", srcDir)
	info, err := os.Stat(srcDir)
	if err != nil {
		log.Printf("compressDirToTarGz: 目录不存在: %v", err)
		return nil, fmt.Errorf("目录不存在: %w", err)
	}
	if !info.IsDir() {
		log.Printf("compressDirToTarGz: 路径不是目录: %s", srcDir)
		return nil, fmt.Errorf("路径不是目录: %s", srcDir)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	baseDir := filepath.Dir(srcDir)
	fileCount := 0
	err = filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(baseDir, path)
		if err != nil {
			return err
		}
		// 统一使用 / 分隔符，兼容跨平台
		relPath = filepath.ToSlash(relPath)

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = relPath

		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			log.Printf("compressDirToTarGz:   [目录] %s", relPath)
			return nil
		}
		fileCount++
		log.Printf("compressDirToTarGz:   [文件] %s (%d bytes)", relPath, info.Size())
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		log.Printf("compressDirToTarGz: 遍历目录失败: %v", err)
		return nil, err
	}

	log.Printf("compressDirToTarGz: 共压缩 %d 个文件", fileCount)

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	result := buf.Bytes()
	log.Printf("compressDirToTarGz: 压缩完成，最终大小=%d bytes", len(result))
	return result, nil
}

func safeFilenamePart(value string) string {
	value = strings.TrimSpace(value)
	mapped := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '-'
	}, value)
	mapped = strings.Trim(mapped, ".-")
	if mapped == "" {
		return "request"
	}
	return mapped
}

// writeFileStream 直接返回二进制文件流：成功时写入 octet-stream 附件头并从 body 复制内容。
// encrypted 决定 X-TAA-Encrypted 头，errLabel 用于写入失败时的日志。
func writeFileStream(w http.ResponseWriter, taskID, filename string, encrypted bool, size int64, body io.Reader, errLabel string) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	w.Header().Set("X-TAA-Task-Id", taskID)
	w.Header().Set("X-TAA-Encrypted", fmt.Sprintf("%t", encrypted))
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, body); err != nil {
		log.Printf("%s: %v", errLabel, err)
	}
}

// ── Handler: /v1/taa/getAttestation ──────────────────────

func (s *TAAState) buildAttestationResult(ctx context.Context, attestationFile, helperPath, helperMode string, userData []byte) ([]byte, string, bool, string) {
	generateCtx, generateCancel := context.WithTimeout(ctx, 30*time.Second)
	defer generateCancel()

	if err := attestation.Generate(generateCtx, attestation.Config{
		OutputPath: attestationFile,
		HelperPath: helperPath,
		Mode:       helperMode,
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

	return reportData, formattedValues, true, "success"
}

func (s *TAAState) getAttestationHandler(w http.ResponseWriter, r *http.Request) {
	var req getAttestationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("请求解析失败: %v", err))
		return
	}

	if req.RequestID == "" {
		writeError(w, http.StatusBadRequest, "requestId 不能为空")
		return
	}

	s.mu.RLock()
	attestationFile := s.AttestationFile
	helperPath := s.HelperPath
	helperMode := s.HelperMode
	userData := s.UserData
	s.mu.RUnlock()

	// 同一时刻只允许一个 attestation 重新生成
	s.attestMu.Lock()
	defer s.attestMu.Unlock()

	reportData, reportValues, verifiedPass, msg := s.buildAttestationResult(r.Context(), attestationFile, helperPath, helperMode, userData)
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

func (s *TAAState) resourceInfoHandler(w http.ResponseWriter, r *http.Request) {
	var req resourceInfoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("请求解析失败: %v", err))
		return
	}
	if req.ResourceURL == "" {
		writeError(w, http.StatusBadRequest, "resourceUrl 不能为空")
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
	tmpDataDir, err := os.MkdirTemp("", "taa-resource-info-*")
	if err != nil {
		s.Logs.Add(LogError, "getResourceInfo", "创建临时目录失败: %v", err)
		s.setCurrentOp("idle")
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("创建临时目录失败: %v", err))
		return
	}
	defer os.RemoveAll(tmpDataDir)

	if err := extractArchiveFile(tmpDataDir, plaintextPath); err != nil {
		s.Logs.Add(LogError, "getResourceInfo", "解压资源失败: %v", err)
		s.setCurrentOp("idle")
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("解压资源失败: %v", err))
		return
	}
	s.Logs.Add(LogInfo, "getResourceInfo", "解压到临时目录: %s", tmpDataDir)

	output, err := buildResourceInfoJSON(tmpDataDir, plaintextPath)
	if err != nil {
		s.Logs.Add(LogError, "getResourceInfo", "生成资源树失败: %v", err)
		s.setCurrentOp("idle")
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("生成资源信息失败: %v", err))
		return
	}

	s.setCurrentOp("idle")
	s.Logs.Add(LogInfo, "getResourceInfo", "资源树分析完成，临时文件已清理")
	writeEnvelope(w, http.StatusOK, "ok", string(output), 0)
}

// ── Handler: /v1/taa/reportRes (平台 → TAA) ─────────────
//
// /v1/taa/reportRes 在接口文档中定义为 TAA -> 平台的训练结果上报接口，
// TAA 服务端不再注册或接收该路径。保留以下历史实现注释，便于必要时追溯。
//
// func (s *TAAState) reportResHandler(w http.ResponseWriter, r *http.Request) {
// 	var req reportResPlatformRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		writeError(w, http.StatusBadRequest, fmt.Sprintf("请求解析失败: %v", err))
// 		return
// 	}
//
// 	if req.RequestID == "" {
// 		writeError(w, http.StatusBadRequest, "requestId 不能为空")
// 		return
// 	}
//
// 	s.mu.Lock()
// 	if req.Code == 0 {
// 		s.TrainingDone = true
// 	}
// 	s.mu.Unlock()
//
// 	log.Printf("report result received: requestId=%s code=%d", req.RequestID, req.Code)
//
// 	writeEnvelope(w, http.StatusOK, "结果已接收", nil, 0)
// }

// ── Script helpers ──────────────────────────────────────


// runPythonScript executes a Python script via python3 with the given output path and optional extra args.
// Does not depend on bash or any shell shebang.
func runPythonScript(script, outputDir string, env map[string]string, args ...string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), scriptTimeout)
	defer cancel()

	cmdArgs := append([]string{script}, args...)
	cmdArgs = append(cmdArgs, "--output", outputDir)
	cmd := exec.CommandContext(ctx, "python3", cmdArgs...)
	cmd.Dir = filepath.Dir(script)
	if len(env) > 0 {
		cmd.Env = os.Environ()
		for key, value := range env {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("%s exited with error: %w", filepath.Base(script), err)
	}
	return string(output), nil
}

// runScript executes a Python script via python3 with --output argument.
func runScript(script, outputDir string) (string, error) {
	return runPythonScript(script, outputDir, nil)
}

func parseRuntimeConfig(raw string) (runtimeConfig, map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return runtimeConfig{}, nil, fmt.Errorf("runtimeConfig 不能为空")
	}

	var cfg runtimeConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return runtimeConfig{}, nil, fmt.Errorf("解析 runtimeConfig 失败: %w", err)
	}
	if len(cfg.Commands) == 0 {
		return runtimeConfig{}, nil, fmt.Errorf("runtimeConfig.commands 不能为空")
	}
	for i, command := range cfg.Commands {
		if strings.TrimSpace(command) == "" {
			return runtimeConfig{}, nil, fmt.Errorf("runtimeConfig.commands[%d] 不能为空", i)
		}
	}

	env := map[string]string{}
	if strings.TrimSpace(cfg.Env) != "" {
		if err := json.Unmarshal([]byte(cfg.Env), &env); err != nil {
			return runtimeConfig{}, nil, fmt.Errorf("解析 runtimeConfig.env 失败: %w", err)
		}
	}
	return cfg, env, nil
}

func newInOutReplacer(dataDir, outputDir string) *strings.Replacer {
	return strings.NewReplacer(
		"<in>", dataDir,
		"<out>", outputDir,
		"<IN>", dataDir,
		"<OUT>", outputDir,
	)
}

func resolveRuntimeCommands(commands []string, dataDir, outputDir string) []string {
	replacer := newInOutReplacer(dataDir, outputDir)
	resolved := make([]string, len(commands))
	for i, cmd := range commands {
		resolved[i] = replacer.Replace(cmd)
	}
	return resolved
}

func resolveRuntimeEnv(env map[string]string, dataDir, outputDir string) map[string]string {
	if len(env) == 0 {
		return env
	}
	replacer := newInOutReplacer(dataDir, outputDir)
	resolved := make(map[string]string, len(env))
	for k, v := range env {
		resolved[k] = replacer.Replace(v)
	}
	return resolved
}

func runRuntimeConfig(cfg runtimeConfig, env map[string]string, modelDir, dataDir, outputDir, taskID, startedAt string) (string, error) {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("create output dir: %w", err)
	}

	resolvedCommands := resolveRuntimeCommands(cfg.Commands, dataDir, outputDir)
	commandLine := strings.Join(resolvedCommands, " && ")
	ctx, cancel := context.WithTimeout(context.Background(), scriptTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", commandLine)
	cmd.Dir = modelDir
	cmd.Env = mergedRuntimeEnv(resolveRuntimeEnv(env, dataDir, outputDir), map[string]string{
		"TAA_TASK_ID":    taskID,
		"TAA_STARTED_AT": startedAt,
		"TAA_DATA_DIR":   dataDir,
		"TAA_OUTPUT_DIR": outputDir,
	})

	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return string(output), fmt.Errorf("runtimeConfig command timed out after %s", scriptTimeout)
		}
		return string(output), fmt.Errorf("runtimeConfig command exited with error: %w", err)
	}
	return string(output), nil
}

func mergedRuntimeEnv(userEnv, systemEnv map[string]string) []string {
	merged := map[string]string{}
	for _, item := range os.Environ() {
		key, value, ok := strings.Cut(item, "=")
		if ok {
			merged[key] = value
		}
	}
	for key, value := range userEnv {
		merged[key] = value
	}
	for key, value := range systemEnv {
		merged[key] = value
	}

	keys := envKeys(merged)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+merged[key])
	}
	return out
}

func envKeys(env map[string]string) []string {
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
