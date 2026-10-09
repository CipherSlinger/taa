package mock

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

var requestLogs = newRequestLogStore(1000)

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
	case strings.HasPrefix(path, "/v1/taa/reportAudit"):
		return "reportAudit"
	case strings.HasPrefix(path, "/v1/taa/reportProgress") || strings.HasPrefix(path, "/api/reportProgress"):
		return "reportProgress"
	case strings.HasPrefix(path, "/v1/taa/modelLog") || strings.HasPrefix(path, "/api/modelLog"):
		return "modelLog"
	case strings.HasPrefix(path, "/v1/taa/taaLog") || strings.HasPrefix(path, "/api/taaLog"):
		return "taaLog"
	case strings.HasPrefix(path, "/v1/taa/status") || strings.HasPrefix(path, "/api/taa/status"):
		return "taa-status"
	case strings.HasPrefix(path, "/v1/taa/getResourceInfo") || strings.HasPrefix(path, "/api/taa/getResourceInfo"):
		return "taa-resourceInfo"
	case strings.HasPrefix(path, "/v1/taa/stopTraining") || strings.HasPrefix(path, "/api/taa/stopTraining"):
		return "taa-stopTraining"
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
		if !strings.HasPrefix(path, "/v1/taa/status") {
			bodyText := strings.TrimSpace(string(body))
			if bodyText == "" {
				bodyText = "{}"
			}
			logRequestWithID(requestLogs, reqID, "out", requestComponentFromPath(path), r.Method, path, http.StatusOK, "", []byte(bodyText))
		}
		next.ServeHTTP(w, r)
	})
}

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
	ip := strings.TrimSpace(string(out))
	if ip == "" {
		return ""
	}
	return fmt.Sprintf("http://%s:%s", ip, port)
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
		if !strings.Contains(endpoint, "/status") {
			logRequest(requestLogs, "out", component, http.MethodPost, endpoint, http.StatusBadGateway, "读取 TAA 响应失败: "+err.Error(), body)
		}
		return resp.StatusCode, nil, err
	}
	if !strings.Contains(endpoint, "/status") {
		logRequest(requestLogs, "out", component, http.MethodPost, endpoint, resp.StatusCode, fmt.Sprintf("TAA HTTP %d (%s)", resp.StatusCode, time.Since(start).Round(time.Millisecond)), body)
	}
	return resp.StatusCode, respBody, nil
}
