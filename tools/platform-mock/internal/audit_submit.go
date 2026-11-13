package mock

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"taa/internal/resource"
)

const (
	// auditSubmitMemoryLimit is the multipart in-memory threshold: parts larger
	// than this are spooled to a temp file instead of being held in RAM. It is
	// not a size cap — a submission is accepted at any size.
	auditSubmitMemoryLimit = 32 << 20
)

// auditSubmitHandler accepts a plaintext code archive and hands it to the
// in-process audit runner. There is no TAA dispatch, no envelope and no
// registered public key: the workbench is a test tool for the audit pipeline
// itself, so the same archive that TAA would decrypt out of an envelope is
// simply extracted here.
//
// The pending job row exists before the audit starts, so the console can show
// the run from its first step. The runner replaces it in place when the verdict
// is ready, and marks the failing step when it is not.
func auditSubmitHandler(runner *localAuditRunner, uploadDir string) http.HandlerFunc {
	if runner == nil {
		panic("audit submit requires a local audit runner")
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

		// Taken before the body is parsed: while an audit runs, accepting and
		// spooling another upload would only waste disk before the same refusal.
		if !runner.acquire() {
			writeJSON(w, http.StatusConflict, map[string]any{
				"ok":    false,
				"error": "已有审计任务正在执行，请等待其完成后再提交",
			})
			return
		}
		started := false
		defer func() {
			if !started {
				runner.release()
			}
		}()

		if err := r.ParseMultipartForm(auditSubmitMemoryLimit); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "解析 multipart/form-data 失败: " + err.Error()})
			return
		}
		defer func() {
			if r.MultipartForm != nil {
				_ = r.MultipartForm.RemoveAll()
			}
		}()

		// A submission either carries the bytes (`file`) or names an entry in the
		// file area (`fileId`). The latter is what a drag from the file list sends,
		// so repeating a run does not upload the archive again.
		fileID := strings.TrimSpace(r.FormValue("fileId"))
		file, header, fileErr := r.FormFile("file")
		if fileErr == nil {
			defer file.Close()
		}
		if fileErr != nil && fileID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "缺少待审计文件，请上传归档或从文件区域选择"})
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

		workDir, err := os.MkdirTemp(uploadDir, "local-audit-*")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "创建审计目录失败: " + err.Error()})
			return
		}
		// The runner owns the directory from here on and removes it when the
		// audit settles. Every path that fails before start cleans it explicitly.
		archivePath := filepath.Join(workDir, "package")
		originalName := ""
		size := int64(0)
		savedID := fileID

		if fileErr == nil {
			originalName = header.Filename
			size, err = copyToFile(archivePath, file)
			if err != nil {
				_ = os.RemoveAll(workDir)
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "保存上传文件失败: " + err.Error()})
				return
			}
			isArchive, err := resource.IsArchiveFile(archivePath)
			if err != nil {
				_ = os.RemoveAll(workDir)
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "读取上传文件失败: " + err.Error()})
				return
			}
			if !isArchive {
				_ = os.RemoveAll(workDir)
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "待审计文件必须是 zip、gzip 或 tar 归档"})
				return
			}
			// The accepted upload is kept in the file area so it can be dragged
			// back into the launcher later. The staged copy above is what the
			// audit uses and what the temp-directory cleanup removes.
			if runner.files == nil {
				_ = os.RemoveAll(workDir)
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "文件区域不可用"})
				return
			}
			entry, saveErr := runner.files.saveFromFile(archivePath, originalName)
			if saveErr != nil {
				_ = os.RemoveAll(workDir)
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "保存文件到文件区域失败: " + saveErr.Error()})
				return
			}
			savedID = entry.ID
		} else {
			if runner.files == nil {
				_ = os.RemoveAll(workDir)
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "文件区域不可用"})
				return
			}
			entry, srcPath, ok := runner.files.path(fileID)
			if !ok {
				_ = os.RemoveAll(workDir)
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": errAuditFileNotFound.Error()})
				return
			}
			originalName = entry.Name
			size, err = copyAuditFileTo(archivePath, srcPath)
			if err != nil {
				_ = os.RemoveAll(workDir)
				if errors.Is(err, errAuditFileNotFound) {
					writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": errAuditFileNotFound.Error()})
					return
				}
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "读取文件区域失败: " + err.Error()})
				return
			}
			isArchive, err := resource.IsArchiveFile(archivePath)
			if err != nil {
				_ = os.RemoveAll(workDir)
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "读取待审计文件失败: " + err.Error()})
				return
			}
			if !isArchive {
				_ = os.RemoveAll(workDir)
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "待审计文件必须是 zip、gzip 或 tar 归档"})
				return
			}
		}

		runner.jobs.begin(localAuditInstanceKey, requestID, taskID)
		summary, _ := runner.jobs.summaryForRequest(localAuditInstanceKey, requestID)

		log.Printf("local audit accepted: requestId=%s taskId=%s file=%s size=%d fileId=%s",
			requestID, taskID, originalName, size, savedID)

		started = true
		runner.start(workDir, archivePath, requestID, taskID)

		writeJSON(w, http.StatusOK, map[string]any{
			"ok":           true,
			"jobId":        summary.ID,
			"requestId":    requestID,
			"taskId":       taskID,
			"at":           summary.At,
			"filename":     filepath.Base(archivePath),
			"originalName": originalName,
			"fileId":       savedID,
			"size":         size,
			"stage":        summary.Stage,
			"stages":       summary.Stages,
			"message":      "已接收，正在控制台进程内执行审计",
		})
	}
}

// copyToFile writes the uploaded part to path and returns its size.
func copyToFile(path string, src io.Reader) (int64, error) {
	dst, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	size, copyErr := io.Copy(dst, src)
	closeErr := dst.Close()
	if copyErr != nil {
		return size, copyErr
	}
	return size, closeErr
}
