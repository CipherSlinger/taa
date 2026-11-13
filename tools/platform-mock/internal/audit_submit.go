package mock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

const (
	// auditSubmitTimeout bounds the synchronous half of a submission. TAA runs
	// the scan and the LLM adjudication asynchronously and answers importModel
	// once the package is downloaded and decrypted, so the wait covers the
	// download only; a minute would hide an unreachable instance behind a
	// stalled browser tab.
	auditSubmitTimeout = 30 * time.Second
	// auditSubmitMemoryLimit is the multipart in-memory threshold: parts larger
	// than this are spooled to a temp file instead of being held in RAM. It is
	// not a size cap — a submission is accepted at any size.
	auditSubmitMemoryLimit = 32 << 20
	// auditSubmitDefaultRuntimeConfig is the "trigger the audit, run nothing"
	// convention already used by the console: TAA stages the package, audits
	// it, and a training run of `true` exits immediately if one is ever
	// started. The submit endpoint never runs a real workload.
	auditSubmitDefaultRuntimeConfig = `{"commands":["true"],"env":""}`
)

// auditSubmitEncryptModes are the accepted encryptMode values, in the order
// they are documented. "urlkey" is the default because it is the protocol the
// current platform frontend produces.
var auditSubmitEncryptModes = map[string]bool{
	"urlkey":   true,
	"envelope": true,
	"none":     true,
}

// auditImportModelRequest is the importModel body this endpoint builds. It
// carries the same fields the console's own import form sends, so TAA cannot
// tell a workbench submission from a manually triggered one.
type auditImportModelRequest struct {
	ResourceURL   string `json:"resourceUrl"`
	RequestID     string `json:"requestId"`
	TaskID        string `json:"taskId"`
	PublicKey     string `json:"publicKey"`
	RuntimeConfig string `json:"runtimeConfig"`
}

// buildAuditImportBody assembles the importModel JSON. It is a function of its
// own so the exact wire body can be asserted without a live TAA.
func buildAuditImportBody(resourceURL, requestID, taskID, publicKey, runtimeConfig string) ([]byte, error) {
	return json.Marshal(auditImportModelRequest{
		ResourceURL:   resourceURL,
		RequestID:     requestID,
		TaskID:        taskID,
		PublicKey:     publicKey,
		RuntimeConfig: runtimeConfig,
	})
}

// validateRuntimeConfig accepts what TAA's runtime.ParseRuntimeConfig reads: a
// JSON object with a non-empty commands array. The env field is left alone
// because TAA accepts both the string and the object form.
func validateRuntimeConfig(raw string) error {
	var cfg struct {
		Commands []string `json:"commands"`
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return fmt.Errorf("runtimeConfig 不是合法 JSON: %v", err)
	}
	if len(cfg.Commands) == 0 {
		return fmt.Errorf("runtimeConfig 必须包含非空的 commands 数组")
	}
	return nil
}

// auditPayloadIsArchive reports whether the payload's leading bytes are a
// ZIP, GZIP or TAR archive. It mirrors the magic test TAA applies before it
// decides a resource is plaintext, so a plaintext submission that would fail
// remotely is refused here with an error the operator can act on.
//
// It only reads; the caller rewinds the file afterwards.
func auditPayloadIsArchive(file multipart.File) (bool, error) {
	header := make([]byte, 512)
	n, err := io.ReadFull(file, header)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return false, err
	}
	header = header[:n]
	if len(header) >= 2 {
		if header[0] == 0x50 && header[1] == 0x4B {
			return true, nil
		}
		if header[0] == 0x1F && header[1] == 0x8B {
			return true, nil
		}
	}
	if len(header) >= 262 && bytes.Equal(header[257:262], []byte("ustar")) {
		return true, nil
	}
	return false, nil
}

// auditSubmitHandler owns the whole "upload → encrypt → dispatch" chain the
// frontend used to perform itself. Keeping it server-side means the key comes
// from the instance's registration state (never from a page snapshot) and every
// failure is reported in one body shape.
//
// A job is registered as pending before the request leaves, so the workbench
// shows the submission while TAA is still auditing. record() replaces that row
// when reportAudit arrives; if the dispatch fails the row is abandoned and the
// upload is removed, leaving no ghost entry or orphan file.
func auditSubmitHandler(mgr *instanceManager, jobs *auditJobStore, uploadDir, addr string) http.HandlerFunc {
	if jobs == nil {
		// reportAuditHandler writes to globalAuditJobs and takes no store, so a
		// nil store must mean "the one the callback uses" or submissions would
		// never meet their verdicts.
		jobs = globalAuditJobs
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "仅支持 POST 方法"})
			return
		}

		// The target is resolved first: an unknown dockerId or an instance with
		// no address is a submission that cannot be sent, and it should not
		// leave an upload behind.
		dockerID, target, err := mgr.targetFor(requestedDockerID(r))
		if err != nil {
			status := http.StatusServiceUnavailable
			if !writeInstanceErrorJSON(w, err) {
				writeJSON(w, status, map[string]any{"ok": false, "error": "下发失败: " + err.Error()})
			}
			return
		}

		if err := r.ParseMultipartForm(auditSubmitMemoryLimit); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "解析 multipart/form-data 失败: " + err.Error()})
			return
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "缺少待审计文件: " + err.Error()})
			return
		}
		defer file.Close()

		encryptMode := strings.ToLower(strings.TrimSpace(r.FormValue("encryptMode")))
		if encryptMode == "" {
			encryptMode = "urlkey"
		}
		if !auditSubmitEncryptModes[encryptMode] {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "encryptMode 必须为 urlkey、envelope 或 none"})
			return
		}

		// A plaintext payload is sniffed before it is stored. TAA decides a
		// resource is plaintext by the same magic test, so a non-archive would
		// be treated as ciphertext there and fail after the round trip; the
		// upload is refused here instead. An encrypted payload cannot be
		// sniffed at all, which is why this only runs for none.
		if encryptMode == "none" {
			isArchive, err := auditPayloadIsArchive(file)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "读取上传文件失败: " + err.Error()})
				return
			}
			if !isArchive {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "待审计文件必须是 zip、gzip 或 tar 归档"})
				return
			}
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "读取上传文件失败: " + err.Error()})
				return
			}
		}

		// The public key is the instance's registered one; the form field is an
		// explicit override, which a caller that pins a key across a
		// re-registration may need. Whichever wins is used for both the
		// envelope and the request body, so TAA unwraps with the key it is told
		// to use.
		registered := ""
		if b := mgr.lookup(dockerID); b != nil {
			registered = strings.TrimSpace(b.register.get().TaaPublicKey)
		}
		publicKey := strings.TrimSpace(r.FormValue("publicKey"))
		if publicKey == "" {
			publicKey = registered
		}
		if publicKey == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "实例尚未注册 TAA 公钥，请等待 TAA 完成注册后再提交"})
			return
		}

		runtimeConfig := strings.TrimSpace(r.FormValue("runtimeConfig"))
		if runtimeConfig == "" {
			runtimeConfig = auditSubmitDefaultRuntimeConfig
		}
		if err := validateRuntimeConfig(runtimeConfig); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}

		requestID := strings.TrimSpace(r.FormValue("requestId"))
		if requestID == "" {
			requestID = fmt.Sprintf("audit-%d", time.Now().UnixNano())
		}
		taskID := strings.TrimSpace(r.FormValue("taskId"))
		if taskID == "" {
			taskID = requestID
		}

		uploaded, err := storeUploadedPayload(uploadDir, addr, file, header, encryptMode, publicKey, "")
		if err != nil {
			status, message := uploadFailureStatus(err)
			writeJSON(w, status, map[string]any{"ok": false, "error": message})
			return
		}

		// Register before dispatching: the row must already exist when TAA is
		// asked to start, or a verdict that arrives quickly would land first
		// and the operator would never see the submission as in flight.
		jobs.begin(dockerID, requestID, taskID)

		body, err := buildAuditImportBody(uploaded.URL, requestID, taskID, publicKey, runtimeConfig)
		if err != nil {
			jobs.abandon(dockerID, requestID, "组装下发请求失败: "+err.Error())
			removeStoredUpload(uploadDir, uploaded)
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "组装下发请求失败: " + err.Error()})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), auditSubmitTimeout)
		defer cancel()
		status, respBody, err := proxyJSONToTAA(ctx, dockerID, target, "/v1/taa/importModel", body)
		if err == nil {
			err = auditImportRejection(status, respBody)
		}
		if err != nil {
			reason := "下发失败: " + err.Error()
			log.Printf("audit submit rejected: dockerId=%s requestId=%s: %v", dockerID, requestID, err)
			jobs.abandon(dockerID, requestID, reason)
			removeStoredUpload(uploadDir, uploaded)
			writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": reason})
			return
		}

		log.Printf("audit submitted: dockerId=%s requestId=%s taskId=%s mode=%s file=%s", dockerID, requestID, taskID, encryptMode, uploaded.Filename)

		summary, _ := jobs.summaryForRequest(dockerID, requestID)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"jobId":         summary.ID,
			"requestId":     requestID,
			"taskId":        taskID,
			"filename":      uploaded.Filename,
			"originalName":  uploaded.OriginalName,
			"size":          uploaded.Size,
			"encrypted":     uploaded.Encrypted,
			"dataKeyCipher": uploaded.DataKeyCipher,
			"url":           uploaded.URL,
			"at":            summary.At,
			"submitted":     true,
			"message":       "已下发，审计结果将自动回流",
		})
	}
}

// auditImportRejection turns an HTTP-level answer that is not a successful
// import into an error. TAA answers a refused import with a business error code
// in an envelope, so a 200 alone is not success.
func auditImportRejection(status int, body []byte) error {
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return fmt.Errorf("TAA 返回 HTTP %d: %s", status, strings.TrimSpace(string(body)))
	}
	var resp struct {
		Error *int   `json:"error"`
		Msg   string `json:"msg"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		// Not the mock's response shape: TAA did answer 2xx, so treat the
		// import as accepted rather than inventing a failure.
		return nil
	}
	if resp.Error != nil && *resp.Error != 0 {
		msg := strings.TrimSpace(resp.Msg)
		if msg == "" {
			msg = fmt.Sprintf("TAA 错误码 %d", *resp.Error)
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// writeInstanceErrorJSON is writeInstanceError in the submit endpoint's body
// shape. It reports whether it answered, so the caller can fall back.
func writeInstanceErrorJSON(w http.ResponseWriter, err error) bool {
	status, message := 0, ""
	switch {
	case errors.Is(err, errInstanceNotFound):
		status, message = http.StatusNotFound, "指定的 dockerId 不存在"
	case errors.Is(err, errNoInstance):
		status, message = http.StatusServiceUnavailable, "尚无 TAA 实例注册"
	default:
		return false
	}
	writeJSON(w, status, map[string]any{"ok": false, "error": message})
	return true
}
