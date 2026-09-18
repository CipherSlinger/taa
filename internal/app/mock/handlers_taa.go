package mock

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type reportRequest struct {
	DockerID  string         `json:"dockerId"`
	RequestID string         `json:"requestId"`
	TaskID    string         `json:"taskId"`
	Code      int            `json:"code"`
	Msg       *string        `json:"msg"`
	Report    string         `json:"report"`
	Checksum  map[string]any `json:"checksum,omitempty"`
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

		if strings.TrimSpace(state.DockerID) == "" || strings.TrimSpace(state.RequestID) == "" || strings.TrimSpace(state.TaskID) == "" {
			state.StatusCode = http.StatusBadRequest
			state.Message = "requestId、dockerId 和 taskId 不能为空"
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

func isValidModelChecksum(cs map[string]any) bool {
	if cs == nil || len(cs) == 0 {
		return false
	}
	alg, ok := cs["algorithm"].(string)
	if !ok || strings.TrimSpace(alg) == "" {
		return false
	}
	val, ok := cs["value"].(string)
	if !ok || strings.TrimSpace(val) == "" {
		return false
	}
	switch v := cs["size"].(type) {
	case float64:
		if v <= 0 {
			return false
		}
	case int:
		if v <= 0 {
			return false
		}
	case int64:
		if v <= 0 {
			return false
		}
	case json.Number:
		n, err := v.Int64()
		if err != nil || n <= 0 {
			return false
		}
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil || n <= 0 {
			return false
		}
	default:
		return false
	}
	return true
}

// reportModelImportHandler handles POST /v1/taa/reportModelImport — TAA 上报模型导入与完整性校验结果
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
		state.Checksum = req.Checksum
		if req.Msg != nil {
			state.Msg = *req.Msg
		}

		if strings.TrimSpace(state.DockerID) == "" {
			state.StatusCode = http.StatusBadRequest
			state.Message = "缺少 dockerId"
		} else if strings.TrimSpace(state.RequestID) == "" {
			state.StatusCode = http.StatusBadRequest
			state.Message = "缺少 requestId"
		} else if state.Code == 0 && !isValidModelChecksum(state.Checksum) {
			state.StatusCode = http.StatusBadRequest
			state.Message = "导入成功时 checksum 不能为空且必须包含 size、algorithm 与 value"
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

// reportAuditHandler handles POST /v1/taa/reportAudit — TAA 上报模型代码安全审计结果
func reportAuditHandler(store *reportStateStore) http.HandlerFunc {
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
		state.Checksum = req.Checksum
		if req.Msg != nil {
			state.Msg = *req.Msg
		}

		if strings.TrimSpace(state.DockerID) == "" {
			state.StatusCode = http.StatusBadRequest
			state.Message = "缺少 dockerId"
		} else if strings.TrimSpace(state.RequestID) == "" {
			state.StatusCode = http.StatusBadRequest
			state.Message = "缺少 requestId"
		} else if state.Code != 0 && state.Code != 1 && state.Code != 2 {
			state.StatusCode = http.StatusBadRequest
			state.Message = "code 必须为 0(通过)、1(未通过) 或 2(LLM不可用)"
		} else {
			state.Accepted = true
			state.StatusCode = http.StatusOK
			state.Message = "平台已收到代码审计结果上报，并返回 HTTP 200"
		}

		store.set(state)
		if !state.Accepted {
			log.Printf("reportAudit rejected: status=%d dockerId=%q taskId=%q message=%s", state.StatusCode, state.DockerID, state.TaskID, state.Message)
			writeEnvelope(w, state.StatusCode, state.Message, reportStateResult(state), state.StatusCode)
			return
		}

		log.Printf("reportAudit accepted: dockerId=%s taskId=%s code=%d", state.DockerID, state.TaskID, state.Code)
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"received": true,
		}, 0)
	}
}

func parseProgressTimestamp(ts string) (time.Time, error) {
	ts = strings.TrimSpace(ts)
	if ts == "" {
		return time.Time{}, fmt.Errorf("timestamp 为空")
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, ts)
}

func reportProgressHandler(store *progressStateStore) http.HandlerFunc {
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

		if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			writeEnvelope(w, http.StatusBadRequest, "Content-Type 应为 application/json", nil, http.StatusBadRequest)
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "读取请求体失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}

		var req reportProgressRequest
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeEnvelope(w, http.StatusBadRequest, "解析 JSON 失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}

		if strings.TrimSpace(req.DockerID) == "" {
			writeEnvelope(w, http.StatusBadRequest, "缺少 dockerId", nil, http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.RequestID) == "" {
			writeEnvelope(w, http.StatusBadRequest, "缺少 requestId", nil, http.StatusBadRequest)
			return
		}
		if req.Percent < 0 || req.Percent > 100 {
			writeEnvelope(w, http.StatusBadRequest, "percent 必须在 0 到 100 之间", nil, http.StatusBadRequest)
			return
		}

		newTime, err := parseProgressTimestamp(req.Timestamp)
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "非法时间戳格式: "+err.Error(), nil, http.StatusBadRequest)
			return
		}

		// 防逆序检查：如果此前已有状态且之前的时间戳解析成功，且当前新时间戳早于之前时间戳，则不更新状态，直接返回 200
		currState := store.get()
		if currState.Received && currState.Accepted && currState.Timestamp != "" {
			if prevTime, err := parseProgressTimestamp(currState.Timestamp); err == nil {
				if newTime.Before(prevTime) {
					log.Printf("reportProgress ignored out-of-order timestamp: curr=%s incoming=%s", currState.Timestamp, req.Timestamp)
					writeEnvelope(w, http.StatusOK, "success", map[string]any{
						"received": true,
					}, 0)
					return
				}
			}
		}

		state := progressState{
			Received:   true,
			Accepted:   true,
			ReceivedAt: time.Now().Format(time.RFC3339),
			DockerID:   req.DockerID,
			RequestID:  req.RequestID,
			TaskID:     req.TaskID,
			Percent:    req.Percent,
			Timestamp:  req.Timestamp,
			StatusCode: http.StatusOK,
			Message:    "平台已收到训练进度上报，并返回 HTTP 200",
			RawBody:    string(bodyBytes),
		}

		store.set(state)
		log.Printf("reportProgress accepted: dockerId=%s requestId=%s percent=%.2f timestamp=%s", state.DockerID, state.RequestID, state.Percent, state.Timestamp)
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"received": true,
		}, 0)
	}
}

func modelLogHandler(store *modelLogStore) http.HandlerFunc {
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

		if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			writeEnvelope(w, http.StatusBadRequest, "Content-Type 应为 application/json", nil, http.StatusBadRequest)
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "读取请求体失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}

		var req modelLogRequest
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeEnvelope(w, http.StatusBadRequest, "解析 JSON 失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}

		if strings.TrimSpace(req.DockerID) == "" {
			writeEnvelope(w, http.StatusBadRequest, "缺少 dockerId", nil, http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.RequestID) == "" {
			writeEnvelope(w, http.StatusBadRequest, "缺少 requestId", nil, http.StatusBadRequest)
			return
		}
		if len(req.Entries) == 0 {
			writeEnvelope(w, http.StatusBadRequest, "entries 不能为空", nil, http.StatusBadRequest)
			return
		}
		for _, e := range req.Entries {
			if strings.TrimSpace(e.Message) == "" {
				writeEnvelope(w, http.StatusBadRequest, "entry.message 不能为空", nil, http.StatusBadRequest)
				return
			}
		}

		added := store.addEntries(req.DockerID, req.RequestID, req.TaskID, req.Entries)
		log.Printf("modelLog accepted: dockerId=%s requestId=%s added=%d total=%d", req.DockerID, req.RequestID, added, store.get().TotalCount)
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"received": true,
		}, 0)
	}
}

func taaLogHandler(store *taaLogStore) http.HandlerFunc {
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

		if !strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			writeEnvelope(w, http.StatusBadRequest, "Content-Type 应为 application/json", nil, http.StatusBadRequest)
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "读取请求体失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}

		var req taaLogRequest
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			writeEnvelope(w, http.StatusBadRequest, "解析 JSON 失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}

		if strings.TrimSpace(req.DockerID) == "" {
			writeEnvelope(w, http.StatusBadRequest, "缺少 dockerId", nil, http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.RequestID) == "" {
			writeEnvelope(w, http.StatusBadRequest, "缺少 requestId", nil, http.StatusBadRequest)
			return
		}
		if len(req.Entries) == 0 {
			writeEnvelope(w, http.StatusBadRequest, "entries 不能为空", nil, http.StatusBadRequest)
			return
		}
		for _, e := range req.Entries {
			if strings.TrimSpace(e.Message) == "" {
				writeEnvelope(w, http.StatusBadRequest, "entry.message 不能为空", nil, http.StatusBadRequest)
				return
			}
		}

		added := store.addEntries(req.DockerID, req.RequestID, req.TaskID, req.Entries)
		log.Printf("taaLog accepted: dockerId=%s requestId=%s added=%d total=%d", req.DockerID, req.RequestID, added, store.get().TotalCount)
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"received": true,
		}, 0)
	}
}
