package controller

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	pkgerrors "taa/pkg/errors"
)

// apiResponse 定义控制器层统一响应结构体
type apiResponse struct {
	Msg    string `json:"msg"`
	Result any    `json:"result"`
	Error  int    `json:"error"`
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

// writeErr 根据 error 对象的类型写入统一 API 错误响应。
// 若 err 为 pkg/errors.Error，自动使用其内置 Code 作为 HTTP 状态码与业务错误码，
// 否则使用 defaultStatus。
func writeErr(w http.ResponseWriter, defaultStatus int, err error) {
	if err == nil {
		return
	}
	code := pkgerrors.CodeOf(err, defaultStatus)
	var appErr *pkgerrors.Error
	msg := err.Error()
	if pkgerrors.As(err, &appErr) {
		msg = appErr.Message()
	}
	writeEnvelope(w, code, msg, nil, code)
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
