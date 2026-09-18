package mock

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
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
		files = append(files, uploadedFileRecord{
			Filename:     filename,
			OriginalName: originalName,
			Size:         info.Size(),
			URL:          baseURL + filename,
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
