package mock

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// writeInstanceError maps the manager's sentinel errors onto their HTTP status.
// It reports whether it wrote a response. The sentinel texts are deliberately
// not surfaced: they are internal, and each handler localizes its own answer.
func writeInstanceError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, errInstanceNotFound):
		writeEnvelope(w, http.StatusNotFound, "指定的 dockerId 不存在", nil, http.StatusNotFound)
		return true
	case errors.Is(err, errNoInstance):
		writeEnvelope(w, http.StatusServiceUnavailable, "尚无 TAA 实例注册", nil, http.StatusServiceUnavailable)
		return true
	}
	return false
}

// instanceSummary is the console's one-line view of a registered instance.
type instanceSummary struct {
	DockerID      string `json:"dockerId"`
	Accepted      bool   `json:"accepted"`
	Received      bool   `json:"received"`
	ReceivedAt    string `json:"receivedAt"`
	TaaTarget     string `json:"taaTarget"`
	LastReportAt  string `json:"lastReportAt"`
	ModelLogCount int    `json:"modelLogCount"`
	TaaLogCount   int    `json:"taaLogCount"`
	Default       bool   `json:"default"`
}

func lastReportAt(b *instanceStores) string {
	latest := ""
	for _, store := range []*reportStateStore{b.reportResourceRes, b.reportRes, b.reportModelImport, b.reportAudit} {
		if at := store.get().ReceivedAt; at > latest {
			latest = at
		}
	}
	return latest
}

func summarizeInstance(b *instanceStores) instanceSummary {
	reg := b.register.get()
	return instanceSummary{
		DockerID:      b.dockerID,
		Accepted:      reg.Accepted,
		Received:      reg.Received,
		ReceivedAt:    reg.ReceivedAt,
		TaaTarget:     b.target(),
		LastReportAt:  lastReportAt(b),
		ModelLogCount: b.modelLog.get().TotalCount,
		TaaLogCount:   b.taaLog.get().TotalCount,
	}
}

func instanceListPayload(mgr *instanceManager) ([]instanceSummary, string) {
	defaultBundle := mgr.defaultBundle()
	defaultID := ""
	if defaultBundle != nil {
		defaultID = defaultBundle.dockerID
	}
	items := make([]instanceSummary, 0)
	for _, b := range mgr.list() {
		item := summarizeInstance(b)
		item.Default = defaultBundle != nil && b.dockerID == defaultBundle.dockerID
		items = append(items, item)
	}
	return items, defaultID
}

func instancesHandler(mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		items, defaultID := instanceListPayload(mgr)
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"instances":       items,
			"defaultDockerId": defaultID,
		}, 0)
	}
}

func targetForDisplay(mgr *instanceManager, dockerID string) string {
	_, target, err := mgr.targetFor(dockerID)
	if err != nil {
		return ""
	}
	return target
}

func dashboardStatusHandler(mgr *instanceManager) http.HandlerFunc {
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
		b, err := mgr.resolveLenient(r)
		if writeInstanceError(w, err) {
			return
		}
		items, defaultID := instanceListPayload(mgr)
		res := map[string]any{
			"register":        b.register.get(),
			"modelImport":     reportStateResult(b.reportModelImport.get()),
			"audit":           reportStateResult(b.reportAudit.get()),
			"progress":        b.progress.get(),
			"taaTarget":       targetForDisplay(mgr, b.dockerID),
			"dockerId":        b.dockerID,
			"instances":       items,
			"defaultDockerId": defaultID,
		}
		writeEnvelope(w, http.StatusOK, "ok", res, 0)
	}
}

// registerStatusHandler always answers HTTP 200 when no instance exists: the
// deploy scripts poll it as a readiness probe. The envelope error field still
// carries the last registration's status code once one has happened.
func registerStatusHandler(mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		b, err := mgr.resolve(r)
		if errors.Is(err, errNoInstance) {
			writeEnvelope(w, http.StatusOK, "", registerState{}, 0)
			return
		}
		if writeInstanceError(w, err) {
			return
		}
		state := b.register.get()
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

func registerResetHandler(mgr *instanceManager) http.HandlerFunc {
	return instanceResetHandler(mgr, func(b *instanceStores) { b.register.reset() })
}

func instanceResetHandler(mgr *instanceManager, apply func(*instanceStores)) http.HandlerFunc {
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
		if id := requestedDockerID(r); id != "" {
			b := mgr.lookup(id)
			if b == nil {
				writeEnvelope(w, http.StatusNotFound, "指定的 dockerId 不存在", nil, http.StatusNotFound)
				return
			}
			apply(b)
		} else {
			for _, b := range mgr.list() {
				apply(b)
			}
		}
		writeEnvelope(w, http.StatusOK, "reset", nil, 0)
	}
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

func reportStatusHandler(mgr *instanceManager, pick func(*instanceStores) *reportStateStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		b, err := mgr.resolve(r)
		if writeInstanceError(w, err) {
			return
		}
		store := pick(b)
		state := store.get()
		msg, errorCode := reportStateEnvelope(state)
		res := reportStateResult(state)
		res["history"] = store.getHistory()
		writeEnvelope(w, http.StatusOK, msg, res, errorCode)
	}
}

func reportResetHandler(mgr *instanceManager, pick func(*instanceStores) *reportStateStore) http.HandlerFunc {
	return instanceResetHandler(mgr, func(b *instanceStores) { pick(b).reset() })
}

func progressStatusHandler(mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		b, err := mgr.resolve(r)
		if writeInstanceError(w, err) {
			return
		}
		state := b.progress.get()
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

func progressResetHandler(mgr *instanceManager) http.HandlerFunc {
	return instanceResetHandler(mgr, func(b *instanceStores) { b.progress.reset() })
}

func modelLogStatusHandler(mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		b, err := mgr.resolve(r)
		if writeInstanceError(w, err) {
			return
		}
		state := b.modelLog.get()
		if state.Entries == nil {
			state.Entries = []modelLogEntry{}
		}
		writeEnvelope(w, http.StatusOK, "success", state, 0)
	}
}

func modelLogResetHandler(mgr *instanceManager) http.HandlerFunc {
	return instanceResetHandler(mgr, func(b *instanceStores) { b.modelLog.reset() })
}

func taaLogStatusHandler(mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		b, err := mgr.resolve(r)
		if writeInstanceError(w, err) {
			return
		}
		state := b.taaLog.get()
		if state.Entries == nil {
			state.Entries = []taaLogEntry{}
		}
		writeEnvelope(w, http.StatusOK, "success", state, 0)
	}
}

func taaLogResetHandler(mgr *instanceManager) http.HandlerFunc {
	return instanceResetHandler(mgr, func(b *instanceStores) { b.taaLog.reset() })
}

func taaTargetHandler(mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		b, err := mgr.resolveLenient(r)
		if writeInstanceError(w, err) {
			return
		}
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"taaTarget": targetForDisplay(mgr, b.dockerID),
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

func taaStatusHandler(mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		id, target, err := mgr.targetFor(requestedDockerID(r))
		if err != nil {
			if !writeInstanceError(w, err) {
				writeEnvelope(w, http.StatusServiceUnavailable, err.Error(), nil, http.StatusServiceUnavailable)
			}
			return
		}

		status, respBody, err := proxyJSONToTAA(r.Context(), id, target, "/v1/taa/status", []byte("{}"))
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
func taaGetResourceInfoHandler(mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		id, target, err := mgr.targetFor(requestedDockerID(r))
		if err != nil {
			if !writeInstanceError(w, err) {
				writeEnvelope(w, http.StatusServiceUnavailable, err.Error(), nil, http.StatusServiceUnavailable)
			}
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "读取请求体失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}

		status, respBody, err := proxyJSONToTAA(r.Context(), id, target, "/v1/taa/getResourceInfo", body)
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
func taaStopTrainingHandler(mgr *instanceManager) http.HandlerFunc {
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
		id, target, err := mgr.targetFor(requestedDockerID(r))
		if err != nil {
			if !writeInstanceError(w, err) {
				writeEnvelope(w, http.StatusBadGateway, "未配置 TAA 目标地址（-taa-target 或 TAA_POD）: "+err.Error(), nil, http.StatusBadGateway)
			}
			return
		}

		status, respBody, err := proxyJSONToTAA(r.Context(), id, target, "/v1/taa/stopTraining", []byte("{}"))
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
