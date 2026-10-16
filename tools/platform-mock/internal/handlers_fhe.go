package mock

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	teecrypto "taa/pkg/crypto"
)

// fheSubmitRequest is the body of POST /api/fhe/submit. Both files are named by
// the name the upload endpoint returned, never by a path: the mock references
// objects in its upload directory the way a real platform references objects in
// its object store.
type fheSubmitRequest struct {
	EvalKeyFile string `json:"evalKeyFile"`
	InputZip    string `json:"inputZip"`
	RequestID   string `json:"requestId"`
	TaskID      string `json:"taskId"`
}

// fheSubmitHandler drives the whole FHE chain from the mock: it hashes the eval
// key with SM3, then calls TAA's import with the two new fields, exactly as a
// real platform would.
//
// The key and the input are uploaded first through the existing /api/upload
// endpoint and referenced here by name, which is what makes this a full-chain
// exercise: the mock never touches the shared directory itself.
func fheSubmitHandler(cfg Config, taaAddr string) http.HandlerFunc {
	uploadDir := cfg.UploadDir
	if abs, err := filepath.Abs(uploadDir); err == nil {
		uploadDir = abs
	}

	// The URLs handed to TAA must be absolute: the download happens from TAA,
	// not from the browser that uploaded the file. cfg.Addr is a bare listen
	// address (":8080"), so it carries neither a scheme nor a host - build the
	// base the same way the upload endpoint does, off platformIP.
	baseURL := fmt.Sprintf("http://%s/files/", platformIP(cfg.Addr))

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
		if strings.TrimSpace(taaAddr) == "" {
			writeEnvelope(w, http.StatusServiceUnavailable, "TAA 地址未配置", nil, http.StatusServiceUnavailable)
			return
		}

		var req fheSubmitRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			writeEnvelope(w, http.StatusBadRequest, "解析请求体失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		req.RequestID = strings.TrimSpace(req.RequestID)
		req.TaskID = strings.TrimSpace(req.TaskID)
		if req.RequestID == "" || req.TaskID == "" {
			writeEnvelope(w, http.StatusBadRequest, "缺少 requestId 或 taskId", nil, http.StatusBadRequest)
			return
		}

		keyPath, err := resolveUploadFilePath(uploadDir, req.EvalKeyFile)
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "eval key 文件不可用: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		inputPath, err := resolveUploadFilePath(uploadDir, req.InputZip)
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "输入包不可用: "+err.Error(), nil, http.StatusBadRequest)
			return
		}

		_, keyHash, err := teecrypto.HashFileSM3(keyPath)
		if err != nil {
			writeEnvelope(w, http.StatusInternalServerError, "计算 eval key SM3 摘要失败: "+err.Error(), nil, http.StatusInternalServerError)
			return
		}

		body, err := json.Marshal(map[string]any{
			"resourceUrl":     baseURL + filepath.Base(inputPath),
			"requestId":       req.RequestID,
			"taskId":          req.TaskID,
			"evalKeyUrl":      baseURL + filepath.Base(keyPath),
			"evalKeyFileHash": keyHash,
		})
		if err != nil {
			writeEnvelope(w, http.StatusInternalServerError, "组装导入请求失败: "+err.Error(), nil, http.StatusInternalServerError)
			return
		}

		log.Printf("fhe submit: taskId=%s requestId=%s evalKeyHash=%s", req.TaskID, req.RequestID, keyHash)

		status, respBody, err := proxyJSONToTAA(r.Context(), taaAddr, "/v1/taa/import", body)
		if err != nil {
			if status == 0 {
				status = http.StatusBadGateway
			}
			writeEnvelope(w, status, "TAA 请求失败: "+err.Error(), nil, status)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write(respBody)
	}
}

// resolveUploadFilePath turns an uploaded file name into the absolute path of
// that file inside the upload directory.
//
// The name arrives in an HTTP body and ends up as a filesystem read, so anything
// that could leave uploadDir - an absolute path, a "../" walk, an embedded
// separator, a bare "." - is refused before the path is built. The prefix check
// stays even though the name checks already cover those shapes: it is the
// boundary itself, not an inference from the shape of the input.
func resolveUploadFilePath(uploadDir, name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", fmt.Errorf("文件名为空")
	}
	cleaned := filepath.Clean(trimmed)
	if filepath.IsAbs(cleaned) || cleaned != filepath.Base(cleaned) || cleaned == "." || cleaned == ".." {
		return "", fmt.Errorf("文件名不合法: %s", name)
	}

	full := filepath.Join(uploadDir, cleaned)
	if !strings.HasPrefix(full, uploadDir+string(filepath.Separator)) {
		return "", fmt.Errorf("文件名越出上传目录: %s", name)
	}

	st, err := os.Stat(full)
	if err != nil {
		return "", fmt.Errorf("文件不存在: %s", cleaned)
	}
	if st.IsDir() {
		return "", fmt.Errorf("不是文件: %s", cleaned)
	}
	return full, nil
}
