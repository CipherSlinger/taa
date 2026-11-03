package mock

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"taa/internal/platform/envelope"
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

// deriveTAATarget builds the TAA base URL from the address the registration
// came from. The port is the configured TAA port, not the source port: the
// source port is ephemeral. A RemoteAddr that yields no usable host returns ""
// and leaves the instance without a derived target; registration still
// succeeds, and outbound calls report the missing address explicitly.
func deriveTAATarget(remoteAddr, port string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if net.ParseIP(host) == nil {
		log.Printf("cannot derive the TAA target from RemoteAddr %q: %v", remoteAddr, err)
		return ""
	}
	if strings.TrimSpace(port) == "" {
		port = defaultTAAPort
	}
	return "http://" + net.JoinHostPort(host, port)
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

// proxyJSONToTAA sends a platform request to TAA. body is the business JSON:
// it is sealed here, once, so every caller keeps writing plain bodies and none
// can accidentally send plaintext to a TAA that now refuses it.
//
// The response is unsealed when it is an envelope, because TAA seals every JSON
// response. Anything that does not parse as an envelope is returned unchanged:
// that covers a non-envelope TAA build, a plain error page and the endpoints
// whose response is binary.
func proxyJSONToTAA(ctx context.Context, taaAddr, endpoint string, body []byte) (int, []byte, error) {
	component := requestComponentFromPath(endpoint)
	targetURL := strings.TrimRight(taaAddr, "/") + endpoint

	sealed, err := currentPlatformKeys().sealForTAA(body)
	if err != nil {
		logRequest(requestLogs, "out", component, http.MethodPost, endpoint, http.StatusInternalServerError, "封装请求失败: "+err.Error(), body)
		return 0, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(sealed))
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
	return resp.StatusCode, openTAAResponse(respBody), nil
}

// openTAAResponse returns the plaintext of a sealed TAA response, or the body
// unchanged when it is not an envelope (binary export captured by mistake, a
// plain error, or a TAA that did not seal). A sealed body whose signature does
// not verify is left sealed rather than decoded: the caller then shows the
// envelope, which is honest, instead of business data taken on trust.
func openTAAResponse(body []byte) []byte {
	env, err := envelope.Parse(body)
	if err != nil {
		return body
	}
	plaintext, err := currentPlatformKeys().openFromTAAResponse(env)
	if err != nil {
		log.Printf("could not open a TAA response envelope: %v", err)
		return body
	}
	return plaintext
}

// sealProxyRequestBody seals what the embedded console forwards to TAA.
//
// The console talks to the mock's own /taa/* reverse proxy, so its calls are
// plaintext on the browser side but must be envelopes on the TAA side. Sealing
// here keeps the browser code unchanged and leaves one place responsible for
// the wire format. GET/HEAD requests carry no body and are passed through.
func sealProxyRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "读取请求体失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		sealed, err := currentPlatformKeys().sealForTAA(body)
		if err != nil {
			log.Printf("TAA proxy: cannot seal %s: %v", r.URL.Path, err)
			writeEnvelope(w, http.StatusBadGateway, "TAA 请求封装失败: "+err.Error(), nil, http.StatusBadGateway)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(sealed))
		r.ContentLength = int64(len(sealed))
		next.ServeHTTP(w, r)
	})
}

// openProxyResponse replaces a sealed JSON response with its plaintext so the
// console can decode it. Non-JSON responses (the binary export) are left alone.
func openProxyResponse(resp *http.Response) error {
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "json") {
		return nil
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	plaintext := openTAAResponse(data)
	resp.Body = io.NopCloser(bytes.NewReader(plaintext))
	resp.ContentLength = int64(len(plaintext))
	resp.Header.Set("Content-Length", strconv.Itoa(len(plaintext)))
	return nil
}
