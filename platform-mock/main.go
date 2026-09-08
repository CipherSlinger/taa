package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"taa/crypto"
)

//go:embed index.html
var indexHTML string

type registerState struct {
	Received           bool   `json:"received"`
	Accepted           bool   `json:"accepted"`
	ReceivedAt         string `json:"receivedAt"`
	DockerID           string `json:"dockerId"`
	AuthInfo           string `json:"authInfo"`
	TaaPublicKey       string `json:"taaPublicKey"`
	AttestationValues  string `json:"attestationValues"`
	Timestamp          string `json:"timestamp"`
	VerifiedPass       bool   `json:"verifiedPass"`
	AttestationName    string `json:"attestationName"`
	AttestationSize    int64  `json:"attestationSize"`
	ContentType        string `json:"contentType"`
	StatusCode         int    `json:"statusCode"`
	Message            string `json:"message"`
	AttestationBase64  string `json:"attestationBase64"`
	AttestationContent string `json:"attestationContent"`
}

type registerRequest struct {
	DockerID          string          `json:"dockerId"`
	AuthInfo          json.RawMessage `json:"authInfo"`
	TaaPublicKey      string          `json:"taaPublicKey"`
	AttestationValues string          `json:"attestationValues"`
	Timestamp         string          `json:"timestamp"`
	VerifiedPass      bool            `json:"verifiedPass"`
	Attestation       string          `json:"attestation"`
}

type reportState struct {
	Received    bool   `json:"received"`
	Accepted    bool   `json:"accepted"`
	ReceivedAt  string `json:"receivedAt"`
	DockerID    string `json:"dockerId"`
	RequestID   string `json:"requestId"`
	TaskID      string `json:"taskId"`
	Code        int    `json:"code"`
	Msg         string `json:"msg"`
	Report      string `json:"report"`
	ContentType string `json:"contentType"`
	StatusCode  int    `json:"statusCode"`
	Message     string `json:"message"`
	RawBody     string `json:"rawBody"`
}

type apiResponse struct {
	Msg    string `json:"msg"`
	Result any    `json:"result"`
	Error  int    `json:"error"`
}

type uploadedFileRecord struct {
	Filename     string    `json:"filename"`
	OriginalName string    `json:"originalName"`
	Size         int64     `json:"size"`
	URL          string    `json:"url"`
	UploadedAt   time.Time `json:"uploadedAt"`
	Encrypted    bool      `json:"encrypted"`
}

type registerStateStore struct {
	mu    sync.RWMutex
	path  string
	state registerState
}

func newRegisterStateStore(stateDir string) *registerStateStore {
	store := &registerStateStore{path: defaultStateFile(stateDir, "register-state.json")}
	store.load()
	return store
}

func (s *registerStateStore) load() {
	state, err := loadJSONFile[registerState](s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("load register state failed: %v", err)
		}
		return
	}
	s.state = state
}

func (s *registerStateStore) get() registerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *registerStateStore) set(state registerState) {
	s.mu.Lock()
	s.state = state
	path := s.path
	s.mu.Unlock()
	if err := saveJSONFile(path, state); err != nil {
		log.Printf("save register state failed: %v", err)
	}
}

func (s *registerStateStore) reset() {
	s.mu.Lock()
	s.state = registerState{}
	path := s.path
	s.mu.Unlock()
	if err := saveJSONFile(path, registerState{}); err != nil {
		log.Printf("save register state failed: %v", err)
	}
}

type reportStateStore struct {
	mu    sync.RWMutex
	path  string
	state reportState
}

func newReportStateStore(stateDir string, filename ...string) *reportStateStore {
	name := "report-state.json"
	if len(filename) > 0 {
		name = filename[0]
	}
	store := &reportStateStore{path: defaultStateFile(stateDir, name)}
	store.load()
	return store
}

func (s *reportStateStore) load() {
	state, err := loadJSONFile[reportState](s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("load report state failed: %v", err)
		}
		return
	}
	s.state = state
}

func (s *reportStateStore) get() reportState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

func (s *reportStateStore) set(state reportState) {
	s.mu.Lock()
	s.state = state
	path := s.path
	s.mu.Unlock()
	if err := saveJSONFile(path, state); err != nil {
		log.Printf("save report state failed: %v", err)
	}
}

func (s *reportStateStore) reset() {
	s.mu.Lock()
	s.state = reportState{}
	path := s.path
	s.mu.Unlock()
	if err := saveJSONFile(path, reportState{}); err != nil {
		log.Printf("save report state failed: %v", err)
	}
}

type requestLogEntry struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Direction string `json:"direction,omitempty"`
	Level     string `json:"level,omitempty"`
	Component string `json:"component,omitempty"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status,omitempty"`
	Message   string `json:"message,omitempty"`
	Body      string `json:"body,omitempty"`
}

type requestLogStore struct {
	mu      sync.RWMutex
	path    string
	entries []requestLogEntry
	max     int
}

func newRequestLogStore(max int) *requestLogStore {
	if max <= 0 {
		max = 500
	}
	return &requestLogStore{max: max}
}

func (s *requestLogStore) add(entry requestLogEntry) {
	if entry.ID == "" {
		entry.ID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().Format(time.RFC3339Nano)
	}
	if entry.Level == "" {
		entry.Level = "info"
	}
	if entry.Direction == "" {
		entry.Direction = "out"
	}
	s.mu.Lock()
	s.entries = append(s.entries, entry)
	if len(s.entries) > s.max {
		s.entries = append([]requestLogEntry(nil), s.entries[len(s.entries)-s.max:]...)
	}
	s.mu.Unlock()
}

func (s *requestLogStore) list() []requestLogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]requestLogEntry(nil), s.entries...)
}

func (s *requestLogStore) drain() []requestLogEntry {
	s.mu.Lock()
	entries := append([]requestLogEntry(nil), s.entries...)
	s.entries = nil
	s.mu.Unlock()
	return entries
}

func (s *requestLogStore) reset() {
	s.mu.Lock()
	s.entries = nil
	s.mu.Unlock()
}

func summarizeRequestBody(body []byte, limit int) string {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return "{}"
	}
	if limit <= 0 || len(text) <= limit {
		return text
	}
	return text[:limit]
}

func logRequestWithID(store *requestLogStore, id, direction, component, method, path string, status int, message string, body []byte) {
	if store == nil {
		return
	}
	store.add(requestLogEntry{
		ID:        id,
		Timestamp: time.Now().Format(time.RFC3339Nano),
		Direction: direction,
		Level:     logLevelFromStatus(status),
		Component: component,
		Method:    method,
		Path:      path,
		Status:    status,
		Message:   message,
		Body:      summarizeRequestBody(body, 1<<20),
	})
}

func logRequest(store *requestLogStore, direction, component, method, path string, status int, message string, body []byte) {
	logRequestWithID(store, "", direction, component, method, path, status, message, body)
}

func logLevelFromStatus(status int) string {
	switch {
	case status >= 500:
		return "error"
	case status >= 400:
		return "warn"
	default:
		return "info"
	}
}

func requestComponentFromPath(path string) string {
	switch {
	case strings.HasPrefix(path, "/v1/taa/register"):
		return "register"
	case strings.HasPrefix(path, "/v1/taa/reportResourceRes"):
		return "reportResourceRes"
	case strings.HasPrefix(path, "/v1/taa/reportRes"):
		return "reportRes"
	case strings.HasPrefix(path, "/v1/taa/reportModelImport"):
		return "reportModelImport"
	case strings.HasPrefix(path, "/v1/taa/logs") || strings.HasPrefix(path, "/api/taa/logs"):
		return "taa-logs"
	case strings.HasPrefix(path, "/v1/taa/status") || strings.HasPrefix(path, "/api/taa/status"):
		return "taa-status"
	case strings.HasPrefix(path, "/v1/taa/getResourceInfo") || strings.HasPrefix(path, "/api/taa/getResourceInfo"):
		return "taa-resourceInfo"
	case strings.HasPrefix(path, "/api/upload") || strings.HasPrefix(path, "/api/uploads"):
		return "uploads"
	case strings.HasPrefix(path, "/taa/"):
		return "taa-proxy"
	case strings.HasPrefix(path, "/v1/taa/"):
		return "taa-callback"
	default:
		cleaned := strings.TrimSpace(strings.Trim(path, "/"))
		if cleaned == "" {
			return "root"
		}
		return cleaned
	}
}

const requestLogBodyLimit = 8 << 10

func shouldCaptureRequestBody(r *http.Request) bool {
	if r == nil || r.Body == nil {
		return false
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return false
	}
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(contentType, "multipart/form-data") {
		return false
	}
	if contentType == "" {
		return false
	}
	return strings.Contains(contentType, "json") || strings.Contains(contentType, "text/") || strings.Contains(contentType, "x-www-form-urlencoded")
}

func captureRequestBody(r *http.Request) []byte {
	if !shouldCaptureRequestBody(r) {
		return nil
	}
	if r.ContentLength < 0 || r.ContentLength > requestLogBodyLimit {
		return nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body
}

func loggingReverseProxyHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := captureRequestBody(r)
		reqID := r.Header.Get("X-Mock-Req-Id")
		if reqID == "" {
			reqID = fmt.Sprintf("req-%d", time.Now().UnixNano())
		}
		path := r.URL.Path
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if !strings.HasPrefix(path, "/v1/taa/logs") && !strings.HasPrefix(path, "/v1/taa/status") {
			bodyText := strings.TrimSpace(string(body))
			if bodyText == "" {
				bodyText = "{}"
			}
			logRequestWithID(requestLogs, reqID, "out", requestComponentFromPath(path), r.Method, path, http.StatusOK, "", []byte(bodyText))
		}
		next.ServeHTTP(w, r)
	})
}

var requestLogs = newRequestLogStore(1000)

type reportRequest struct {
	DockerID  string  `json:"dockerId"`
	RequestID string  `json:"requestId"`
	TaskID    string  `json:"taskId"`
	Code      int     `json:"code"`
	Msg       *string `json:"msg"`
	Report    string  `json:"report"`
}

const defaultTAAPort = "6001"

func discoverTAAAddr(kubectlPod, kubectlNS, port string) string {
	if kubectlPod == "" {
		return ""
	}
	args := []string{"get", "pod", kubectlPod, "-o", "jsonpath={.status.podIP}"}
	if kubectlNS != "" {
		args = append([]string{"-n", kubectlNS}, args[1:]...)
	}
	out, err := exec.Command("kubectl", args...).Output()
	if err != nil || len(out) == 0 {
		return ""
	}
	if port == "" {
		port = defaultTAAPort
	}
	return "http://" + strings.TrimSpace(string(out)) + ":" + port
}

func main() {
	addr := flag.String("addr", ":8080", "mock platform listen address")
	stateDir := flag.String("state-dir", envOrDefault("STATE_DIR", "/root/taa"), "directory for mock platform state files")
	taaTarget := flag.String("taa-target", "", "TAA service address for reverse proxy (e.g. http://10.244.0.5:6001). Auto-detected via -taa-pod if empty")
	taaPod := flag.String("taa-pod", envOrDefault("TAA_POD", "simple-busybox"), "Kubernetes pod name for auto-discovering TAA address")
	taaNS := flag.String("taa-ns", envOrDefault("TAA_NS", ""), "Kubernetes namespace for TAA pod (empty = default namespace)")
	taaPort := flag.String("taa-port", envOrDefault("TAA_PORT", defaultTAAPort), "TAA service port for auto-discovery fallback")
	allowEmptyAttestation := flag.Bool("allow-empty-attestation", false, "allow registration without attestation report (for local testing without TEE hardware)")
	flag.Parse()

	if err := os.MkdirAll(*stateDir, 0o755); err != nil {
		log.Printf("failed to create state directory %s: %v", *stateDir, err)
	}

	// Resolve TAA proxy target
	taaAddr := strings.TrimRight(strings.TrimSpace(*taaTarget), "/")
	if taaAddr == "" {
		taaAddr = discoverTAAAddr(*taaPod, *taaNS, strings.TrimSpace(*taaPort))
	}
	if taaAddr != "" {
		log.Printf("TAA reverse proxy target: %s (pod=%s)", taaAddr, *taaPod)
	} else {
		log.Printf("TAA reverse proxy disabled: set -taa-target or ensure kubectl can reach pod %q", *taaPod)
	}

	registerStore := newRegisterStateStore(*stateDir)
	reportStore := newReportStateStore(*stateDir)
	reportResStore := newReportStateStore(*stateDir, "reportRes-state.json")
	reportModelImportStore := newReportStateStore(*stateDir, "reportModelImport-state.json")
	uploadDir := "./uploads"
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		log.Printf("failed to create upload directory: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/v1/taa/register", registerHandler(registerStore, *allowEmptyAttestation))
	mux.HandleFunc("/v1/taa/reportResourceRes", reportResourceResHandler(reportStore))
	mux.HandleFunc("/v1/taa/reportRes", reportResHandler(reportResStore))
	mux.HandleFunc("/v1/taa/reportModelImport", reportModelImportHandler(reportModelImportStore))
	mux.HandleFunc("/api/register/status", registerStatusHandler(registerStore))
	mux.HandleFunc("/api/register/reset", registerResetHandler(registerStore))
	mux.HandleFunc("/api/reportResourceRes/status", reportStatusHandler(reportStore))
	mux.HandleFunc("/api/reportResourceRes/reset", reportResetHandler(reportStore))
	mux.HandleFunc("/api/reportRes/status", reportStatusHandler(reportResStore))
	mux.HandleFunc("/api/reportRes/reset", reportResetHandler(reportResStore))
	mux.HandleFunc("/api/reportModelImport/status", reportStatusHandler(reportModelImportStore))
	mux.HandleFunc("/api/reportModelImport/reset", reportResetHandler(reportModelImportStore))
	mux.HandleFunc("/api/taa-target", taaTargetHandler(taaAddr))
	mux.HandleFunc("/api/upload", uploadHandler(*addr, uploadDir, registerStore))
	mux.HandleFunc("/api/upload/delete", uploadDeleteHandler(uploadDir))
	mux.HandleFunc("/api/uploads", uploadListHandler(*addr, uploadDir))
	mux.HandleFunc("/api/uploads/delete", uploadDeleteHandler(uploadDir))
	mux.HandleFunc("/api/uploads/reset", uploadResetHandler(uploadDir))
	mux.HandleFunc("/api/crypto/generate-key", cryptoGenerateKeyHandler)
	mux.HandleFunc("/api/crypto/decrypt", cryptoDecryptHandler)
	mux.HandleFunc("/api/request-logs/status", requestLogsStatusHandler)
	mux.HandleFunc("/api/request-logs/reset", requestLogsResetHandler)
	mux.HandleFunc("/api/taa/logs", taaLogsHandler(taaAddr))
	mux.HandleFunc("/api/taa/status", taaStatusHandler(taaAddr))
	mux.HandleFunc("/api/taa/getResourceInfo", taaGetResourceInfoHandler(taaAddr))

	// Serve uploaded files
	mux.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir(uploadDir))))

	// TAA reverse proxy: /taa/* → TAA pod
	if taaAddr != "" {
		target, err := url.Parse(taaAddr)
		if err != nil {
			log.Printf("invalid TAA target %q: %v", taaAddr, err)
		} else {
			proxy := httputil.NewSingleHostReverseProxy(target)
			proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				log.Printf("TAA proxy error: %s %s → %v", r.Method, r.URL.Path, err)
				writeEnvelope(w, http.StatusBadGateway, "TAA proxy error: "+err.Error(), nil, http.StatusBadGateway)
			}
			mux.Handle("/taa/", http.StripPrefix("/taa", loggingReverseProxyHandler(proxy)))
		}
	}

	server := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	for _, url := range accessURLs(*addr) {
		log.Printf("mock platform URL: %s", url)
	}
	log.Printf("TAA should use PLATFORM_IP=%s", platformIP(*addr))
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func registerHandler(store *registerStateStore, allowEmptyAttestation bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		state := registerState{
			Received:   true,
			ReceivedAt: time.Now().Format(time.RFC3339),
		}

		state.ContentType = r.Header.Get("Content-Type")
		var req registerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			state.StatusCode = http.StatusBadRequest
			state.Message = "解析 application/json 失败: " + err.Error()
			store.set(state)
			writeEnvelope(w, http.StatusBadRequest, state.Message, nil, http.StatusBadRequest)
			return
		}

		state.DockerID = req.DockerID
		// authInfo is expected to be JSON null (or omitted); normalize both to "null".
		state.AuthInfo = strings.TrimSpace(string(req.AuthInfo))
		if state.AuthInfo == "" {
			state.AuthInfo = "null"
		}
		state.TaaPublicKey = req.TaaPublicKey
		state.AttestationValues = req.AttestationValues
		state.Timestamp = req.Timestamp
		state.VerifiedPass = req.VerifiedPass
		attestationBase64 := req.Attestation

		// 保存原始 base64 字符串
		state.AttestationBase64 = attestationBase64

		// Base64 解码 attestation
		if attestationBase64 != "" {
			attBytes, decodeErr := base64.StdEncoding.DecodeString(attestationBase64)
			if decodeErr != nil {
				state.StatusCode = http.StatusBadRequest
				state.Message = "attestation Base64 解码失败: " + decodeErr.Error()
				store.set(state)
				writeEnvelope(w, http.StatusBadRequest, state.Message, nil, http.StatusBadRequest)
				return
			}
			state.AttestationSize = int64(len(attBytes))
			state.AttestationContent = string(attBytes)
		}

		if state.DockerID == "" {
			state.StatusCode = http.StatusBadRequest
			state.Message = "缺少 dockerId"
		} else if !allowEmptyAttestation && attestationBase64 == "" {
			state.StatusCode = http.StatusBadRequest
			state.Message = "缺少 attestation"
		} else if state.AuthInfo != "null" {
			state.StatusCode = http.StatusBadRequest
			state.Message = fmt.Sprintf("authInfo 应为空或 null，实际为 %q", state.AuthInfo)
		} else if state.TaaPublicKey == "" {
			state.StatusCode = http.StatusBadRequest
			state.Message = "缺少 taaPublicKey"
		} else if !allowEmptyAttestation && state.AttestationValues == "" {
			state.StatusCode = http.StatusBadRequest
			state.Message = "缺少 attestationValues"
		} else if state.Timestamp == "" {
			state.StatusCode = http.StatusBadRequest
			state.Message = "缺少 timestamp"
		} else {
			state.Accepted = true
			state.StatusCode = http.StatusOK
			if allowEmptyAttestation && attestationBase64 == "" {
				state.Message = "平台已收到 TAA 注册请求，并返回 HTTP 200（本地模式：跳过 attestation 验证）"
			} else {
				state.Message = "平台已收到 TAA 注册请求，并返回 HTTP 200"
			}
		}

		store.set(state)
		if !state.Accepted {
			log.Printf("register rejected: status=%d dockerId=%q message=%s", state.StatusCode, state.DockerID, state.Message)
			writeEnvelope(w, state.StatusCode, state.Message, state, state.StatusCode)
			return
		}

		log.Printf("register accepted: dockerId=%s attestation size=%d timestamp=%s", state.DockerID, state.AttestationSize, state.Timestamp)
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"received":     true,
			"verifiedPass": true,
		}, 0)
	}
}

func reportResourceResHandler(store *reportStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		state := reportState{
			Received:   true,
			ReceivedAt: time.Now().Format(time.RFC3339),
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			state.StatusCode = http.StatusBadRequest
			state.Message = "读取请求体失败: " + err.Error()
			store.set(state)
			writeEnvelope(w, http.StatusBadRequest, state.Message, nil, http.StatusBadRequest)
			return
		}
		state.RawBody = string(bodyBytes)
		state.ContentType = r.Header.Get("Content-Type")
		if !strings.Contains(state.ContentType, "application/json") {
			state.StatusCode = http.StatusBadRequest
			state.Message = "Content-Type 应为 application/json"
			store.set(state)
			writeEnvelope(w, http.StatusBadRequest, state.Message, nil, http.StatusBadRequest)
			return
		}

		var req reportRequest
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			state.StatusCode = http.StatusBadRequest
			state.Message = "解析 JSON 失败: " + err.Error()
			store.set(state)
			writeEnvelope(w, http.StatusBadRequest, state.Message, nil, http.StatusBadRequest)
			return
		}

		state.DockerID = req.DockerID
		state.RequestID = req.RequestID
		state.TaskID = req.TaskID
		state.Code = req.Code
		state.Report = req.Report
		if req.Msg != nil {
			state.Msg = *req.Msg
		}

		if state.DockerID == "" {
			state.StatusCode = http.StatusBadRequest
			state.Message = "缺少 dockerId"
		} else if state.RequestID == "" {
			state.StatusCode = http.StatusBadRequest
			state.Message = "缺少 requestId"
		} else {
			state.Accepted = true
			state.StatusCode = http.StatusOK
			state.Message = "平台已收到资源下载结果上报，并返回 HTTP 200"
		}

		store.set(state)
		if !state.Accepted {
			log.Printf("report rejected: status=%d dockerId=%q requestId=%q message=%s", state.StatusCode, state.DockerID, state.RequestID, state.Message)
			writeEnvelope(w, state.StatusCode, state.Message, reportStateResult(state), state.StatusCode)
			return
		}

		log.Printf("report accepted: dockerId=%s requestId=%s code=%d", state.DockerID, state.RequestID, state.Code)
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"received": true,
		}, 0)
	}
}

// reportResHandler handles POST /v1/taa/reportRes — TAA 上报训练完成结果
func reportResHandler(store *reportStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		state := reportState{
			Received:   true,
			ReceivedAt: time.Now().Format(time.RFC3339),
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			state.StatusCode = http.StatusBadRequest
			state.Message = "读取请求体失败: " + err.Error()
			store.set(state)
			writeEnvelope(w, http.StatusBadRequest, state.Message, nil, http.StatusBadRequest)
			return
		}
		state.RawBody = string(bodyBytes)
		state.ContentType = r.Header.Get("Content-Type")

		var req reportRequest
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			state.StatusCode = http.StatusBadRequest
			state.Message = "解析 JSON 失败: " + err.Error()
			store.set(state)
			writeEnvelope(w, http.StatusBadRequest, state.Message, nil, http.StatusBadRequest)
			return
		}

		state.DockerID = req.DockerID
		state.RequestID = req.RequestID
		state.TaskID = req.TaskID
		state.Code = req.Code
		state.Report = req.Report
		if req.Msg != nil {
			state.Msg = *req.Msg
		}

		if state.RequestID == "" {
			state.StatusCode = http.StatusBadRequest
			state.Message = "缺少 requestId"
		} else {
			state.Accepted = true
			state.StatusCode = http.StatusOK
			state.Message = "平台已收到训练完成结果上报，并返回 HTTP 200"
		}

		store.set(state)
		if !state.Accepted {
			log.Printf("reportRes rejected: status=%d requestId=%q message=%s", state.StatusCode, state.RequestID, state.Message)
			writeEnvelope(w, state.StatusCode, state.Message, reportStateResult(state), state.StatusCode)
			return
		}

		log.Printf("reportRes accepted: requestId=%s code=%d", state.RequestID, state.Code)
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"received": true,
		}, 0)
	}
}

// reportModelImportHandler handles POST /v1/taa/reportModelImport — TAA 上报模型导入结果（含代码审计报告）
func reportModelImportHandler(store *reportStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		state := reportState{
			Received:   true,
			ReceivedAt: time.Now().Format(time.RFC3339),
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			state.StatusCode = http.StatusBadRequest
			state.Message = "读取请求体失败: " + err.Error()
			store.set(state)
			writeEnvelope(w, http.StatusBadRequest, state.Message, nil, http.StatusBadRequest)
			return
		}
		state.RawBody = string(bodyBytes)
		state.ContentType = r.Header.Get("Content-Type")

		var req reportRequest
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			state.StatusCode = http.StatusBadRequest
			state.Message = "解析 JSON 失败: " + err.Error()
			store.set(state)
			writeEnvelope(w, http.StatusBadRequest, state.Message, nil, http.StatusBadRequest)
			return
		}

		state.DockerID = req.DockerID
		state.RequestID = req.RequestID
		state.TaskID = req.TaskID
		state.Code = req.Code
		state.Report = req.Report
		if req.Msg != nil {
			state.Msg = *req.Msg
		}

		if state.DockerID == "" {
			state.StatusCode = http.StatusBadRequest
			state.Message = "缺少 dockerId"
		} else {
			state.Accepted = true
			state.StatusCode = http.StatusOK
			state.Message = "平台已收到模型导入结果上报，并返回 HTTP 200"
		}

		store.set(state)
		if !state.Accepted {
			log.Printf("reportModelImport rejected: status=%d dockerId=%q taskId=%q message=%s", state.StatusCode, state.DockerID, state.TaskID, state.Message)
			writeEnvelope(w, state.StatusCode, state.Message, reportStateResult(state), state.StatusCode)
			return
		}

		log.Printf("reportModelImport accepted: dockerId=%s taskId=%s code=%d", state.DockerID, state.TaskID, state.Code)
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"received": true,
		}, 0)
	}
}

func registerStatusHandler(store *registerStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		state := store.get()
		writeEnvelope(w, http.StatusOK, state.Message, state, state.StatusCode)
	}
}

func reportStateResult(state reportState) map[string]any {
	return map[string]any{
		"received":    state.Received,
		"accepted":    state.Accepted,
		"receivedAt":  state.ReceivedAt,
		"dockerId":    state.DockerID,
		"requestId":   state.RequestID,
		"taskId":      state.TaskID,
		"report":      state.Report,
		"contentType": state.ContentType,
		"statusCode":  state.StatusCode,
		"message":     state.Message,
		"rawBody":     state.RawBody,
	}
}

func reportStateEnvelope(state reportState) (string, int) {
	if !state.Accepted {
		return state.Message, state.StatusCode
	}
	if state.Msg != "" {
		return state.Msg, state.Code
	}
	return state.Message, state.Code
}

func registerResetHandler(store *registerStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}
		store.reset()
		writeEnvelope(w, http.StatusOK, "reset", nil, 0)
	}
}

func reportStatusHandler(store *reportStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		state := store.get()
		msg, errorCode := reportStateEnvelope(state)
		writeEnvelope(w, http.StatusOK, msg, reportStateResult(state), errorCode)
	}
}

func reportResetHandler(store *reportStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}
		store.reset()
		writeEnvelope(w, http.StatusOK, "reset", nil, 0)
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeEnvelope(w http.ResponseWriter, status int, msg string, result any, errorCode int) {
	writeJSON(w, status, apiResponse{Msg: msg, Result: result, Error: errorCode})
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func accessURLs(addr string) []string {
	port := listenPort(addr)
	urls := []string{"http://127.0.0.1:" + port + "/"}
	for _, ip := range localIPv4Addrs() {
		if ip == "127.0.0.1" {
			continue
		}
		urls = append(urls, "http://"+ip+":"+port+"/")
	}
	return dedupe(urls)
}

func platformIP(addr string) string {
	port := listenPort(addr)
	ips := localIPv4Addrs()
	if len(ips) > 0 {
		return ips[0] + ":" + port
	}
	return "127.0.0.1:" + port
}

func listenPort(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
		return port
	}
	if strings.HasPrefix(addr, ":") && len(addr) > 1 {
		return strings.TrimPrefix(addr, ":")
	}
	return "8080"
}

func localIPv4Addrs() []string {
	seen := map[string]struct{}{}
	var addrs []string
	ifs, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifs {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			ifaceAddrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range ifaceAddrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				ip = ip.To4()
				if ip == nil || ip.IsLoopback() {
					continue
				}
				text := ip.String()
				if _, ok := seen[text]; ok {
					continue
				}
				seen[text] = struct{}{}
				addrs = append(addrs, text)
			}
		}
	}
	if len(addrs) == 0 {
		return []string{"127.0.0.1"}
	}
	return addrs
}

func dedupe(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func taaTargetHandler(taaAddr string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"taaTarget": taaAddr,
		}, 0)
	}
}

func requestLogsStatusHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
		return
	}
	entries := requestLogs.list()
	writeEnvelope(w, http.StatusOK, "ok", map[string]any{
		"logs":  entries,
		"total": len(entries),
	}, 0)
}

func requestLogsResetHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
		return
	}
	requestLogs.reset()
	writeEnvelope(w, http.StatusOK, "reset", nil, 0)
}

func proxyJSONToTAA(ctx context.Context, taaAddr, endpoint string, body []byte) (int, []byte, error) {
	component := requestComponentFromPath(endpoint)
	targetURL := strings.TrimRight(taaAddr, "/") + endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		if !strings.Contains(endpoint, "/logs") && !strings.Contains(endpoint, "/status") {
			logRequest(requestLogs, "out", component, http.MethodPost, endpoint, http.StatusInternalServerError, "创建请求失败: "+err.Error(), body)
		}
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if !strings.Contains(endpoint, "/logs") && !strings.Contains(endpoint, "/status") {
			logRequest(requestLogs, "out", component, http.MethodPost, endpoint, http.StatusBadGateway, "TAA 请求失败: "+err.Error(), body)
		}
		return 0, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		if !strings.Contains(endpoint, "/logs") && !strings.Contains(endpoint, "/status") {
			logRequest(requestLogs, "out", component, http.MethodPost, endpoint, http.StatusBadGateway, "读取 TAA 响应失败: "+err.Error(), body)
		}
		return resp.StatusCode, nil, err
	}
	if !strings.Contains(endpoint, "/logs") && !strings.Contains(endpoint, "/status") {
		logRequest(requestLogs, "out", component, http.MethodPost, endpoint, resp.StatusCode, fmt.Sprintf("TAA HTTP %d (%s)", resp.StatusCode, time.Since(start).Round(time.Millisecond)), body)
	}
	return resp.StatusCode, respBody, nil
}

// taaLogsHandler proxies log requests to TAA's /v1/taa/logs endpoint.
func taaLogsHandler(taaAddr string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if taaAddr == "" {
			writeEnvelope(w, http.StatusServiceUnavailable, "TAA 地址未配置", nil, http.StatusServiceUnavailable)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "读取请求体失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}

		status, respBody, err := proxyJSONToTAA(r.Context(), taaAddr, "/v1/taa/logs", body)
		if err != nil {
			if status == 0 {
				status = http.StatusBadGateway
			}
			writeEnvelope(w, status, "TAA 请求失败: "+err.Error(), nil, status)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		w.Write(respBody)
	}
}

// taaStatusHandler proxies status requests to TAA's /v1/taa/status endpoint.
func taaStatusHandler(taaAddr string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if taaAddr == "" {
			writeEnvelope(w, http.StatusServiceUnavailable, "TAA 地址未配置", nil, http.StatusServiceUnavailable)
			return
		}

		status, respBody, err := proxyJSONToTAA(r.Context(), taaAddr, "/v1/taa/status", []byte("{}"))
		if err != nil {
			if status == 0 {
				status = http.StatusBadGateway
			}
			writeEnvelope(w, status, "TAA 请求失败: "+err.Error(), nil, status)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		w.Write(respBody)
	}
}

// taaGetResourceInfoHandler proxies resource info requests to TAA's /v1/taa/getResourceInfo endpoint.
func taaGetResourceInfoHandler(taaAddr string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if taaAddr == "" {
			writeEnvelope(w, http.StatusServiceUnavailable, "TAA 地址未配置", nil, http.StatusServiceUnavailable)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "读取请求体失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}

		status, respBody, err := proxyJSONToTAA(r.Context(), taaAddr, "/v1/taa/getResourceInfo", body)
		if err != nil {
			if status == 0 {
				status = http.StatusBadGateway
			}
			writeEnvelope(w, status, "TAA 请求失败: "+err.Error(), nil, status)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		w.Write(respBody)
	}
}

func listUploadedFiles(uploadDir, addr string) ([]uploadedFileRecord, error) {
	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []uploadedFileRecord{}, nil
		}
		return nil, err
	}

	files := make([]uploadedFileRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		filename := entry.Name()
		originalName := filename
		uploadedAt := info.ModTime().UTC()
		if prefix, rest, ok := strings.Cut(filename, "_"); ok {
			if nanos, err := strconv.ParseInt(prefix, 10, 64); err == nil {
				uploadedAt = time.Unix(0, nanos).UTC()
			}
			if rest != "" {
				originalName = rest
			}
		}
		files = append(files, uploadedFileRecord{
			Filename:     filename,
			OriginalName: originalName,
			Size:         info.Size(),
			URL:          fmt.Sprintf("http://%s/files/%s", platformIP(addr), filename),
			UploadedAt:   uploadedAt,
			Encrypted:    strings.HasSuffix(strings.ToLower(originalName), ".enc"),
		})
	}

	sort.Slice(files, func(i, j int) bool {
		if files[i].UploadedAt.Equal(files[j].UploadedAt) {
			return files[i].Filename > files[j].Filename
		}
		return files[i].UploadedAt.After(files[j].UploadedAt)
	})
	return files, nil
}

func clearUploadedFiles(uploadDir string) (int, error) {
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(uploadDir, entry.Name())); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func uploadListHandler(addr, uploadDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 GET 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		files, err := listUploadedFiles(uploadDir, addr)
		if err != nil {
			writeEnvelope(w, http.StatusInternalServerError, "读取上传文件列表失败: "+err.Error(), nil, http.StatusInternalServerError)
			return
		}
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"files": files,
		}, 0)
	}
}

func uploadResetHandler(uploadDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		deleted, err := clearUploadedFiles(uploadDir)
		if err != nil {
			writeEnvelope(w, http.StatusInternalServerError, "清空上传文件失败: "+err.Error(), nil, http.StatusInternalServerError)
			return
		}
		writeEnvelope(w, http.StatusOK, "reset", map[string]any{
			"deleted": deleted,
		}, 0)
	}
}

func uploadDeleteHandler(uploadDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost && r.Method != http.MethodDelete {
			w.Header().Set("Allow", "POST, DELETE")
			writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 或 DELETE 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		filename := r.URL.Query().Get("filename")
		if filename == "" {
			if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
				var req struct {
					Filename string `json:"filename"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
					filename = req.Filename
				}
			} else {
				filename = r.FormValue("filename")
			}
		}

		filename = strings.TrimSpace(filename)
		if filename == "" {
			writeEnvelope(w, http.StatusBadRequest, "缺少 filename 参数", nil, http.StatusBadRequest)
			return
		}

		baseName := filepath.Base(filename)
		if baseName == "." || baseName == "/" || baseName == "\\" || baseName == "" {
			writeEnvelope(w, http.StatusBadRequest, "非法文件名", nil, http.StatusBadRequest)
			return
		}

		targetPath := filepath.Join(uploadDir, baseName)
		if err := os.Remove(targetPath); err != nil {
			if os.IsNotExist(err) {
				writeEnvelope(w, http.StatusNotFound, "文件不存在: "+baseName, nil, http.StatusNotFound)
				return
			}
			writeEnvelope(w, http.StatusInternalServerError, "删除文件失败: "+err.Error(), nil, http.StatusInternalServerError)
			return
		}

		log.Printf("file deleted: %s", baseName)
		writeEnvelope(w, http.StatusOK, "文件删除成功", map[string]any{
			"filename": baseName,
		}, 0)
	}
}

func sanitizeUploadFilename(name string) string {
	cleaned := strings.ReplaceAll(name, "\\", "/")
	cleaned = filepath.Base(cleaned)
	cleaned = strings.TrimSpace(cleaned)
	if cleaned == "" || cleaned == "." || cleaned == string(filepath.Separator) {
		return "upload"
	}
	return cleaned
}

func uploadHandler(addr, uploadDir string, registerStores ...*registerStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
			return
		}

		// Parse multipart form (max 128MB)
		if err := r.ParseMultipartForm(128 << 20); err != nil {
			writeEnvelope(w, http.StatusBadRequest, "解析 multipart/form-data 失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}

		// Get uploaded file
		file, header, err := r.FormFile("file")
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "获取上传文件失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Create upload directory if not exists
		if err := os.MkdirAll(uploadDir, 0o755); err != nil {
			writeEnvelope(w, http.StatusInternalServerError, "创建上传目录失败: "+err.Error(), nil, http.StatusInternalServerError)
			return
		}

		originalName := sanitizeUploadFilename(header.Filename)

		encryptVal := strings.TrimSpace(r.FormValue("encrypt"))
		shouldEncrypt := strings.EqualFold(encryptVal, "true") || encryptVal == "1" || strings.EqualFold(encryptVal, "on")

		var (
			fileSize int64
			filename string
			filePath string
		)

		if shouldEncrypt {
			pubKeyPEM := strings.TrimSpace(r.FormValue("publicKey"))
			if pubKeyPEM == "" && len(registerStores) > 0 && registerStores[0] != nil {
				pubKeyPEM = strings.TrimSpace(registerStores[0].get().TaaPublicKey)
			}
			if pubKeyPEM == "" {
				writeEnvelope(w, http.StatusBadRequest, "开启加密但尚未获取到 TAA 注册公钥，请等待 TAA 完成注册", nil, http.StatusBadRequest)
				return
			}

			pubKey, err := crypto.ParseSM2PublicKeyPEM([]byte(pubKeyPEM))
			if err != nil {
				writeEnvelope(w, http.StatusBadRequest, "解析 SM2 公钥失败: "+err.Error(), nil, http.StatusBadRequest)
				return
			}

			fileBytes, err := io.ReadAll(file)
			if err != nil {
				writeEnvelope(w, http.StatusInternalServerError, "读取上传文件内容失败: "+err.Error(), nil, http.StatusInternalServerError)
				return
			}

			cipherBytes, err := crypto.SealSM2SM4GCM(pubKey, fileBytes)
			if err != nil {
				writeEnvelope(w, http.StatusInternalServerError, "SM2+SM4-GCM 加密失败: "+err.Error(), nil, http.StatusInternalServerError)
				return
			}

			if !strings.HasSuffix(strings.ToLower(originalName), ".enc") {
				originalName += ".enc"
			}

			filename = fmt.Sprintf("%d_%s", time.Now().UnixNano(), originalName)
			filePath = filepath.Join(uploadDir, filename)

			if err := os.WriteFile(filePath, cipherBytes, 0o644); err != nil {
				writeEnvelope(w, http.StatusInternalServerError, "保存加密文件失败: "+err.Error(), nil, http.StatusInternalServerError)
				return
			}
			fileSize = int64(len(cipherBytes))
		} else {
			filename = fmt.Sprintf("%d_%s", time.Now().UnixNano(), originalName)
			filePath = filepath.Join(uploadDir, filename)

			// Create destination file
			dst, err := os.Create(filePath)
			if err != nil {
				writeEnvelope(w, http.StatusInternalServerError, "创建文件失败: "+err.Error(), nil, http.StatusInternalServerError)
				return
			}
			defer dst.Close()

			// Copy uploaded file to destination
			if _, err := io.Copy(dst, file); err != nil {
				writeEnvelope(w, http.StatusInternalServerError, "保存文件失败: "+err.Error(), nil, http.StatusInternalServerError)
				return
			}
			fileSize = header.Size
		}

		// Generate URL for the uploaded file
		// Use the server's actual IP address instead of 0.0.0.0
		host := platformIP(addr)
		fileURL := fmt.Sprintf("http://%s/files/%s", host, filename)

		log.Printf("file uploaded: %s → %s (encrypted=%v)", originalName, fileURL, shouldEncrypt)

		writeEnvelope(w, http.StatusOK, "文件上传成功", map[string]any{
			"filename":     filename,
			"originalName": originalName,
			"size":         fileSize,
			"url":          fileURL,
			"encrypted":    shouldEncrypt,
			"uploadedAt":   time.Now().UTC(),
		}, 0)
	}
}

func defaultStateFile(stateDir, name string) string {
	if strings.TrimSpace(stateDir) == "" {
		stateDir = "/root/taa"
	}
	return filepath.Join(stateDir, name)
}

func loadJSONFile[T any](path string) (T, error) {
	var zero T
	data, err := os.ReadFile(path)
	if err != nil {
		return zero, err
	}
	if len(data) == 0 {
		return zero, nil
	}
	if err := json.Unmarshal(data, &zero); err != nil {
		return zero, err
	}
	return zero, nil
}

func saveJSONFile(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func cryptoGenerateKeyHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 GET 或 POST 方法", nil, http.StatusMethodNotAllowed)
		return
	}

	priv, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		writeEnvelope(w, http.StatusInternalServerError, "生成 SM2 密钥对失败: "+err.Error(), nil, http.StatusInternalServerError)
		return
	}
	pubPEM, err := crypto.MarshalSM2PublicKeyPEM(&priv.PublicKey)
	if err != nil {
		writeEnvelope(w, http.StatusInternalServerError, "编码 SM2 公钥失败: "+err.Error(), nil, http.StatusInternalServerError)
		return
	}
	privPEM, err := crypto.MarshalSM2PrivateKeyPEM(priv)
	if err != nil {
		writeEnvelope(w, http.StatusInternalServerError, "编码 SM2 私钥失败: "+err.Error(), nil, http.StatusInternalServerError)
		return
	}

	writeEnvelope(w, http.StatusOK, "success", map[string]string{
		"publicKey":  string(pubPEM),
		"privateKey": string(privPEM),
	}, 0)
}

func cryptoDecryptHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
		return
	}

	var (
		privKeyPEM string
		cipherData []byte
	)

	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(128 << 20); err != nil {
			writeEnvelope(w, http.StatusBadRequest, "解析 multipart/form-data 失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		privKeyPEM = strings.TrimSpace(r.FormValue("privateKey"))
		file, _, err := r.FormFile("file")
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "获取待解密文件失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		defer file.Close()
		data, err := io.ReadAll(file)
		if err != nil {
			writeEnvelope(w, http.StatusInternalServerError, "读取待解密文件失败: "+err.Error(), nil, http.StatusInternalServerError)
			return
		}
		cipherData = data
	} else if strings.Contains(contentType, "application/json") {
		var req struct {
			PrivateKey string `json:"privateKey"`
			Ciphertext string `json:"ciphertext"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeEnvelope(w, http.StatusBadRequest, "解析 JSON 失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		privKeyPEM = strings.TrimSpace(req.PrivateKey)
		data, err := base64.StdEncoding.DecodeString(req.Ciphertext)
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "Base64 解码密文失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		cipherData = data
	} else {
		privKeyPEM = strings.TrimSpace(r.Header.Get("X-Private-Key"))
		if privKeyPEM != "" {
			if decoded, err := base64.StdEncoding.DecodeString(privKeyPEM); err == nil && strings.Contains(string(decoded), "PRIVATE KEY") {
				privKeyPEM = string(decoded)
			}
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "读取请求体失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		cipherData = data
	}

	if privKeyPEM == "" {
		writeEnvelope(w, http.StatusBadRequest, "缺少 privateKey 参数", nil, http.StatusBadRequest)
		return
	}
	if len(cipherData) == 0 {
		writeEnvelope(w, http.StatusBadRequest, "待解密数据为空", nil, http.StatusBadRequest)
		return
	}

	privKey, err := crypto.ParseSM2PrivateKeyPEM([]byte(privKeyPEM))
	if err != nil {
		writeEnvelope(w, http.StatusBadRequest, "解析 SM2 私钥失败: "+err.Error(), nil, http.StatusBadRequest)
		return
	}

	plainData, err := crypto.OpenSM2SM4GCM(privKey, cipherData)
	if err != nil {
		writeEnvelope(w, http.StatusBadRequest, "SM2+SM4-GCM 解密失败: "+err.Error(), nil, http.StatusBadRequest)
		return
	}

	if strings.Contains(contentType, "application/json") {
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"plaintext": base64.StdEncoding.EncodeToString(plainData),
			"size":      len(plainData),
		}, 0)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(plainData)))
	w.WriteHeader(http.StatusOK)
	w.Write(plainData)
}
