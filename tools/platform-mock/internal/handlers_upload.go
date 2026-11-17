package mock

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"taa/pkg/crypto"
)

func registerUploadDeleteRoutes(mux *http.ServeMux, uploadDir string) {
	deleteH := uploadDeleteHandler(uploadDir)
	mux.HandleFunc("/api/upload/delete", deleteH)
	mux.HandleFunc("/api/uploads/delete", deleteH)
}

// uploadMetaDir holds one sidecar per uploaded file. The data key envelope exists
// only at upload time -- it is sealed to TAA's key, so it cannot be recovered from
// the ciphertext afterwards -- and the download URL is the only place that carries
// it. Rebuilding a URL from the directory listing (which is what the console and
// the drag-to-fill widget do) therefore lost it: the console handed out a bare
// /files/<name>.sm4, TAA found no dataKeyCipher parameter, and fell back to
// interpreting the raw ciphertext as a whole-file envelope.
//
// A dot-directory is used because listUploadedFiles already skips directories, so
// the sidecars never show up as uploads themselves.
const uploadMetaDir = ".uploadmeta"

// dataKeyCipherQueryParam is the parameter TAA reads the SM2 data key envelope
// from (resource.SplitDataKeyCipher). Spelled here rather than imported because
// the mock is a separate module from the daemon's internals.
const dataKeyCipherQueryParam = "dataKeyCipher"

type uploadMeta struct {
	DataKeyCipher string `json:"dataKeyCipher,omitempty"`
	Encrypted     bool   `json:"encrypted,omitempty"`
}

func uploadMetaPath(uploadDir, filename string) string {
	return filepath.Join(uploadDir, uploadMetaDir, filename+".json")
}

func writeUploadMeta(uploadDir, filename string, meta uploadMeta) error {
	dir := filepath.Join(uploadDir, uploadMetaDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return os.WriteFile(uploadMetaPath(uploadDir, filename), data, 0o644)
}

// readUploadMeta reports (meta, true) only when a sidecar exists and parses. A
// missing or unreadable sidecar is not an error: files uploaded before the
// sidecar existed, or dropped into the directory by hand, simply have no extra
// metadata.
func readUploadMeta(uploadDir, filename string) (uploadMeta, bool) {
	data, err := os.ReadFile(uploadMetaPath(uploadDir, filename))
	if err != nil {
		return uploadMeta{}, false
	}
	var meta uploadMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return uploadMeta{}, false
	}
	return meta, true
}

func removeUploadMeta(uploadDir, filename string) {
	// Best effort: the file itself is already gone, and a leftover sidecar only
	// costs an entry nobody can reach.
	_ = os.Remove(uploadMetaPath(uploadDir, filename))
}

func listUploadedFiles(uploadDir, addr string) ([]uploadedFileRecord, error) {
	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []uploadedFileRecord{}, nil
		}
		return nil, err
	}

	baseURL := fmt.Sprintf("http://%s/files/", platformIP(addr))
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
		rec := uploadedFileRecord{
			Filename:     filename,
			OriginalName: originalName,
			Size:         info.Size(),
			URL:          baseURL + filename,
			UploadedAt:   uploadedAt,
			Encrypted:    strings.HasSuffix(strings.ToLower(originalName), ".enc"),
		}
		// The envelope has to be rejoined here: this list is how the console
		// re-offers the file, and without it a URL-key upload looks like a plain
		// link to bare ciphertext.
		if meta, ok := readUploadMeta(uploadDir, filename); ok {
			rec.Encrypted = rec.Encrypted || meta.Encrypted
			if meta.DataKeyCipher != "" {
				rec.URL += "?" + dataKeyCipherQueryParam + "=" + meta.DataKeyCipher
			}
		}
		files = append(files, rec)
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
			writeEnvelope(w, http.StatusInternalServerError, "获取文件列表失败: "+err.Error(), nil, http.StatusInternalServerError)
			return
		}

		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"total": len(files),
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

		deletedCount, err := clearUploadedFiles(uploadDir)
		if err != nil {
			writeEnvelope(w, http.StatusInternalServerError, "清空文件失败: "+err.Error(), nil, http.StatusInternalServerError)
			return
		}

		writeEnvelope(w, http.StatusOK, "文件清空成功", map[string]any{
			"deleted": deletedCount,
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
		removeUploadMeta(uploadDir, baseName)
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

// storedUpload is the result of storing one multipart upload: the list-record
// shape every upload response shares, plus the data key envelope that only the
// immediate response needs (the sidecar holds the durable copy).
type storedUpload struct {
	uploadedFileRecord
	DataKeyCipher string
}

// uploadFailure carries the HTTP status and the exact operator-facing message
// for a storage failure. The upload endpoint and the audit submit endpoint both
// reuse the storage step but answer in their own body shape, so the step reports
// the cause instead of writing a response.
type uploadFailure struct {
	status  int
	message string
}

func (e *uploadFailure) Error() string { return e.message }

func uploadFail(status int, message string) error {
	return &uploadFailure{status: status, message: message}
}

// uploadFailureStatus splits a storeUploadedPayload error into the status and
// the message a caller writes. Any other error maps to 500 with its own text,
// so a failure the storage step did not classify still says what happened.
func uploadFailureStatus(err error) (int, string) {
	var failure *uploadFailure
	if errors.As(err, &failure) {
		return failure.status, failure.message
	}
	return http.StatusInternalServerError, err.Error()
}

// storeUploadedPayload is the shared "multipart file in, addressable upload
// out" step: it encrypts when asked (SM2+SM4-GCM in either envelope layout),
// writes the payload and its sidecar under uploadDir, and builds the absolute
// URL TAA will download from.
//
// encryptMode is already resolved by the caller (none / envelope / urlkey);
// registeredPublicKey is the selected instance's registered TAA key, and
// fallbackPublicKey is the caller's own fallback for an instance that has not
// registered yet. Both endpoints therefore encrypt to exactly the key the
// instance is known by.
func storeUploadedPayload(uploadDir, addr string, file multipart.File, header *multipart.FileHeader, encryptMode, registeredPublicKey, fallbackPublicKey string) (storedUpload, error) {
	// Create upload directory if not exists
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		return storedUpload{}, uploadFail(http.StatusInternalServerError, "创建上传目录失败: "+err.Error())
	}

	originalName := sanitizeUploadFilename(header.Filename)
	shouldEncrypt := encryptMode != "none"

	var (
		fileSize      int64
		filename      string
		filePath      string
		dataKeyCipher string
	)

	if shouldEncrypt {
		// The selected instance's registered key wins: the form's publicKey
		// comes from the page's last registration snapshot, which can be
		// stale when the console is pointed at another instance. The fallback
		// is only for an instance that has not registered its key yet.
		pubKeyPEM := strings.TrimSpace(registeredPublicKey)
		if pubKeyPEM == "" {
			pubKeyPEM = strings.TrimSpace(fallbackPublicKey)
		}
		if pubKeyPEM == "" {
			return storedUpload{}, uploadFail(http.StatusBadRequest, "开启加密但尚未获取到 TAA 注册公钥，请等待 TAA 完成注册")
		}

		pubKey, err := crypto.ParseSM2PublicKeyPEM([]byte(pubKeyPEM))
		if err != nil {
			return storedUpload{}, uploadFail(http.StatusBadRequest, "解析 SM2 公钥失败: "+err.Error())
		}

		fileBytes, err := io.ReadAll(file)
		if err != nil {
			return storedUpload{}, uploadFail(http.StatusInternalServerError, "读取上传文件内容失败: "+err.Error())
		}

		if encryptMode == "urlkey" {
			// New protocol: the file holds nothing but ciphertext, and the SM2 key
			// envelope is hex-encoded onto the download URL.
			env, err := crypto.SealSM2(pubKey, fileBytes)
			if err != nil {
				return storedUpload{}, uploadFail(http.StatusInternalServerError, "SM2+SM4-GCM 加密失败: "+err.Error())
			}

			// The platform's frontend prefixes the body with a one-byte format
			// version -- [version][nonce][ciphertext][tag] -- so the mock mirrors
			// it instead of writing the bare layout: local runs then deliver
			// exactly what the platform delivers. (TAA reads both; the GCM tag
			// decides which one a body is.)
			body := make([]byte, 0, len(env.Ciphertext)+1)
			body = append(body, crypto.SM4FileVersion)
			body = append(body, env.Ciphertext...)

			if !strings.HasSuffix(strings.ToLower(originalName), ".sm4") {
				originalName += ".sm4"
			}

			filename = fmt.Sprintf("%d_%s", time.Now().UnixNano(), originalName)
			filePath = filepath.Join(uploadDir, filename)

			if err := os.WriteFile(filePath, body, 0o644); err != nil {
				return storedUpload{}, uploadFail(http.StatusInternalServerError, "保存加密文件失败: "+err.Error())
			}
			// Deliver the 112-byte C1C3C2 form (no uncompressed point prefix);
			// TAA accepts either layout.
			dataKeyCipher = hex.EncodeToString(env.WrappedKey[1:])
			fileSize = int64(len(body))
		} else {
			cipherBytes, err := crypto.SealSM2SM4GCM(pubKey, fileBytes)
			if err != nil {
				return storedUpload{}, uploadFail(http.StatusInternalServerError, "SM2+SM4-GCM 加密失败: "+err.Error())
			}

			if !strings.HasSuffix(strings.ToLower(originalName), ".enc") {
				originalName += ".enc"
			}

			filename = fmt.Sprintf("%d_%s", time.Now().UnixNano(), originalName)
			filePath = filepath.Join(uploadDir, filename)

			if err := os.WriteFile(filePath, cipherBytes, 0o644); err != nil {
				return storedUpload{}, uploadFail(http.StatusInternalServerError, "保存加密文件失败: "+err.Error())
			}
			fileSize = int64(len(cipherBytes))
		}
	} else {
		filename = fmt.Sprintf("%d_%s", time.Now().UnixNano(), originalName)
		filePath = filepath.Join(uploadDir, filename)

		// Create destination file
		dst, err := os.Create(filePath)
		if err != nil {
			return storedUpload{}, uploadFail(http.StatusInternalServerError, "创建文件失败: "+err.Error())
		}
		defer dst.Close()

		// Copy uploaded file to destination
		if _, err := io.Copy(dst, file); err != nil {
			return storedUpload{}, uploadFail(http.StatusInternalServerError, "保存文件失败: "+err.Error())
		}
		fileSize = header.Size
	}

	// Generate URL for the uploaded file
	// Use the server's actual IP address instead of 0.0.0.0
	fileURL := fmt.Sprintf("http://%s/files/%s", platformIP(addr), filename)
	if dataKeyCipher != "" {
		fileURL += "?" + dataKeyCipherQueryParam + "=" + dataKeyCipher
	}

	// Persist what the URL carried. The listing is the console's source for
	// every later import, so an envelope that lives only in this one response
	// is an envelope the operator can never use again.
	if shouldEncrypt {
		if err := writeUploadMeta(uploadDir, filename, uploadMeta{DataKeyCipher: dataKeyCipher, Encrypted: true}); err != nil {
			// A file whose envelope cannot be re-offered is worse than no
			// file: the operator would import it and get an opaque decrypt
			// failure. Drop the payload and report the real cause.
			_ = os.Remove(filePath)
			return storedUpload{}, uploadFail(http.StatusInternalServerError, "保存上传元数据失败: "+err.Error())
		}
	}

	return storedUpload{
		uploadedFileRecord: uploadedFileRecord{
			Filename:     filename,
			OriginalName: originalName,
			Size:         fileSize,
			URL:          fileURL,
			UploadedAt:   time.Now().UTC(),
			Encrypted:    shouldEncrypt,
		},
		DataKeyCipher: dataKeyCipher,
	}, nil
}

// removeStoredUpload deletes a payload and its sidecar after a later step of
// the same request failed, so a rejected submission leaves no orphan behind.
func removeStoredUpload(uploadDir string, upload storedUpload) {
	if upload.Filename == "" {
		return
	}
	_ = os.Remove(filepath.Join(uploadDir, upload.Filename))
	removeUploadMeta(uploadDir, upload.Filename)
}

func uploadHandler(addr, uploadDir string, mgr *instanceManager) http.HandlerFunc {
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

		b, resolveErr := mgr.resolveLenient(r)
		if writeInstanceError(w, resolveErr) {
			return
		}

		// Logged before the body is read, with the declared length: an upload that
		// stalls in the browser leaves no trace after this point, so the presence
		// or absence of this line is what separates "the request never arrived"
		// from "it arrived and the bytes stalled".
		log.Printf("upload start: from=%s dockerId=%q contentLength=%d contentType=%q",
			r.RemoteAddr, b.dockerID, r.ContentLength, r.Header.Get("Content-Type"))
		uploadStarted := time.Now()

		// Parse multipart form (max 128MB)
		if err := r.ParseMultipartForm(128 << 20); err != nil {
			log.Printf("upload parse failed after %s: %v", time.Since(uploadStarted).Round(time.Millisecond), err)
			writeEnvelope(w, http.StatusBadRequest, "解析 multipart/form-data 失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		log.Printf("upload body received in %s: contentLength=%d",
			time.Since(uploadStarted).Round(time.Millisecond), r.ContentLength)

		// Get uploaded file
		file, header, err := r.FormFile("file")
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "获取上传文件失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		defer file.Close()

		// encryptMode is none / envelope (whole-file envelope, the legacy format) /
		// urlkey (envelope in the URL, the new protocol). The legacy encrypt=true
		// field maps to envelope for backward compatibility.
		encryptMode := strings.ToLower(strings.TrimSpace(r.FormValue("encryptMode")))
		if encryptMode != "none" && encryptMode != "envelope" && encryptMode != "urlkey" {
			encryptVal := strings.TrimSpace(r.FormValue("encrypt"))
			if strings.EqualFold(encryptVal, "true") || encryptVal == "1" || strings.EqualFold(encryptVal, "on") {
				encryptMode = "envelope"
			} else {
				encryptMode = "none"
			}
		}

		// The storage step is shared with the audit submit endpoint. The
		// selected instance's registered key wins; the form's publicKey is only
		// a fallback for an instance that has not registered yet.
		uploaded, err := storeUploadedPayload(uploadDir, addr, file, header, encryptMode,
			b.register.get().TaaPublicKey, r.FormValue("publicKey"))
		if err != nil {
			status, message := uploadFailureStatus(err)
			writeEnvelope(w, status, message, nil, status)
			return
		}

		log.Printf("file uploaded: %s → %s (mode=%s, total %s)",
			uploaded.OriginalName, uploaded.URL, encryptMode, time.Since(uploadStarted).Round(time.Millisecond))

		writeEnvelope(w, http.StatusOK, "文件上传成功", map[string]any{
			"filename":      uploaded.Filename,
			"originalName":  uploaded.OriginalName,
			"size":          uploaded.Size,
			"url":           uploaded.URL,
			"encrypted":     uploaded.Encrypted,
			"dataKeyCipher": uploaded.DataKeyCipher,
			"uploadedAt":    uploaded.UploadedAt,
		}, 0)
	}
}
