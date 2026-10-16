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

// platformIPForRequest is platformIP, indirected so a test can observe when the
// submit handler resolves the host its file URLs are built on. The handler must
// resolve it per request, not once at construction: platformIP answers
// 127.0.0.1 while the mock has no non-loopback address yet, so a value captured
// before the interface comes up would be served for the whole process lifetime.
var platformIPForRequest = platformIP

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

		// The URLs handed to TAA must be absolute: the download happens from TAA,
		// not from the browser that uploaded the file. cfg.Addr is a bare listen
		// address (":8080"), so it carries neither a scheme nor a host - build the
		// base the same way the upload endpoint does, off platformIP.
		//
		// It is resolved here, per request, and must stay here: platformIP falls
		// back to 127.0.0.1 while no non-loopback interface is up, so a base built
		// once at construction would bake an unreachable host into every URL for
		// the rest of the process's life - and those URLs are the ones TAA has to
		// download the eval key and the input package from.
		baseURL := fmt.Sprintf("http://%s/files/", platformIPForRequest(cfg.Addr))

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
		// An encrypted upload is refused rather than hashed. /api/upload writes its
		// ciphertext into the same directory this handler reads, so an eval key sent
		// with encryptMode=envelope|urlkey would otherwise be SM3-hashed as
		// ciphertext and advertised through an evalKeyUrl that carries no
		// ?dataKeyCipher= - a key TAA could neither unwrap nor verify. The default
		// upload path is unencrypted and TAA rejects the result loudly, but a 400
		// here says what actually went wrong.
		if uploadNameIsEncrypted(req.EvalKeyFile) {
			writeEnvelope(w, http.StatusBadRequest,
				"eval key 必须是未加密的上传文件: "+filepath.Base(keyPath)+
					" 是密文，SM3 摘要和 evalKeyUrl 都无法让 TAA 使用它；请以 encryptMode=none 重新上传",
				nil, http.StatusBadRequest)
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

// uploadNameIsEncrypted reports whether an upload holds ciphertext rather than
// the plaintext this package can hash or hand to TAA.
//
// The suffix is the one /api/upload appends: ".enc" for encryptMode=envelope
// and ".sm4" for encryptMode=urlkey. Nothing records the mode a file was
// uploaded with, so its name is the only signal a later request has.
//
// listUploadedFiles' "encrypted" flag is narrower than this: it tests for
// ".enc" alone, so an ".sm4" upload is listed as plaintext. That flag is
// advisory - no submit path reads it - so the two disagree about a label
// rather than about what TAA is handed.
func uploadNameIsEncrypted(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	return strings.HasSuffix(lower, ".enc") || strings.HasSuffix(lower, ".sm4")
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
