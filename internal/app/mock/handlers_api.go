package mock

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

func dashboardStatusHandler(registerStore *registerStateStore, modelImportStore, auditStore *reportStateStore, progressStore *progressStateStore, taaAddr string) http.HandlerFunc {
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
		res := map[string]any{
			"register":    registerStore.get(),
			"modelImport": reportStateResult(modelImportStore.get()),
			"audit":       reportStateResult(auditStore.get()),
			"progress":    progressStore.get(),
			"taaTarget":   taaAddr,
		}
		writeEnvelope(w, http.StatusOK, "ok", res, 0)
	}
}

func registerStatusHandler(store *registerStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		state := store.get()
		writeEnvelope(w, http.StatusOK, state.Message, state, state.StatusCode)
	}
}

func resetHandler(resetFn func()) http.HandlerFunc {
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
		resetFn()
		writeEnvelope(w, http.StatusOK, "reset", nil, 0)
	}
}

func registerResetHandler(store *registerStateStore) http.HandlerFunc {
	return resetHandler(store.reset)
}

func reportStateResult(state reportState) map[string]any {
	res := map[string]any{
		"received":    state.Received,
		"accepted":    state.Accepted,
		"receivedAt":  state.ReceivedAt,
		"dockerId":    state.DockerID,
		"requestId":   state.RequestID,
		"taskId":      state.TaskID,
		"code":        state.Code,
		"msg":         state.Msg,
		"checksum":    state.Checksum,
		"report":      state.Report,
		"contentType": state.ContentType,
		"statusCode":  state.StatusCode,
		"message":     state.Message,
		"rawBody":     state.RawBody,
	}
	if state.Report != "" {
		var reportObj struct {
			Conclusion struct {
				RiskLevel  string         `json:"risk_level"`
				Statistics map[string]any `json:"statistics"`
			} `json:"conclusion"`
		}
		if err := json.Unmarshal([]byte(state.Report), &reportObj); err == nil {
			if reportObj.Conclusion.RiskLevel != "" {
				res["riskLevel"] = reportObj.Conclusion.RiskLevel
			}
			if reportObj.Conclusion.Statistics != nil {
				res["statistics"] = reportObj.Conclusion.Statistics
			}
		}
	}
	return res
}

func reportStateEnvelope(state reportState) (string, int) {
	if !state.Accepted {
		return state.Message, state.StatusCode
	}
	if state.Msg != "" {
		return state.Msg, state.Code
	}
	return state.Message, state.Code
}

func reportStatusHandler(store *reportStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		state := store.get()
		msg, errorCode := reportStateEnvelope(state)
		res := reportStateResult(state)
		res["history"] = store.getHistory()
		writeEnvelope(w, http.StatusOK, msg, res, errorCode)
	}
}

func reportResetHandler(store *reportStateStore) http.HandlerFunc {
	return resetHandler(store.reset)
}

func progressStatusHandler(store *progressStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		state := store.get()
		msg := state.Message
		if msg == "" {
			msg = "success"
		}
		var errCode int
		if !state.Accepted && state.Received {
			errCode = state.StatusCode
		}
		writeEnvelope(w, http.StatusOK, msg, state, errCode)
	}
}

func progressResetHandler(store *progressStateStore) http.HandlerFunc {
	return resetHandler(store.reset)
}

func modelLogStatusHandler(store *modelLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		state := store.get()
		if state.Entries == nil {
			state.Entries = []modelLogEntry{}
		}
		writeEnvelope(w, http.StatusOK, "success", state, 0)
	}
}

func modelLogResetHandler(store *modelLogStore) http.HandlerFunc {
	return resetHandler(store.reset)
}

func taaLogStatusHandler(store *taaLogStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		state := store.get()
		if state.Entries == nil {
			state.Entries = []taaLogEntry{}
		}
		writeEnvelope(w, http.StatusOK, "success", state, 0)
	}
}

func taaLogResetHandler(store *taaLogStore) http.HandlerFunc {
	return resetHandler(store.reset)
}

func taaTargetHandler(taaAddr string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"taaTarget": taaAddr,
		}, 0)
	}
}

func requestLogsStatusHandler(w http.ResponseWriter, r *http.Request) {
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
	entries := requestLogs.list()
	writeEnvelope(w, http.StatusOK, "ok", map[string]any{
		"logs":  entries,
		"total": len(entries),
	}, 0)
}

func requestLogsResetHandler(w http.ResponseWriter, r *http.Request) {
	resetHandler(requestLogs.reset)(w, r)
}

func taaStatusHandler(taaAddr string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if taaAddr == "" {
			writeEnvelope(w, http.StatusServiceUnavailable, "TAA 地址未配置", nil, http.StatusServiceUnavailable)
			return
		}

		status, respBody, err := proxyJSONToTAA(r.Context(), taaAddr, "/v1/taa/status", []byte("{}"))
		if err != nil {
			if status == 0 {
				status = http.StatusBadGateway
			}
			writeEnvelope(w, status, "TAA 请求失败: "+err.Error(), nil, status)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		w.Write(respBody)
	}
}

// taaGetResourceInfoHandler proxies resource info requests to TAA's /v1/taa/getResourceInfo endpoint.
func taaGetResourceInfoHandler(taaAddr string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if taaAddr == "" {
			writeEnvelope(w, http.StatusServiceUnavailable, "TAA 地址未配置", nil, http.StatusServiceUnavailable)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "读取请求体失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}

		status, respBody, err := proxyJSONToTAA(r.Context(), taaAddr, "/v1/taa/getResourceInfo", body)
		if err != nil {
			if status == 0 {
				status = http.StatusBadGateway
			}
			writeEnvelope(w, status, "TAA 请求失败: "+err.Error(), nil, status)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		w.Write(respBody)
	}
}

// taaStopTrainingHandler proxies stop training requests to TAA's /v1/taa/stopTraining endpoint.
func taaStopTrainingHandler(taaAddr string) http.HandlerFunc {
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
			writeEnvelope(w, http.StatusBadGateway, "未配置 TAA 目标地址（-taa-target 或 TAA_POD）", nil, http.StatusBadGateway)
			return
		}

		status, respBody, err := proxyJSONToTAA(r.Context(), taaAddr, "/v1/taa/stopTraining", []byte("{}"))
		if err != nil {
			if status == 0 {
				status = http.StatusBadGateway
			}
			writeEnvelope(w, status, "TAA 请求失败: "+err.Error(), nil, status)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		w.Write(respBody)
	}
}
