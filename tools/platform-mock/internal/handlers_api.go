package mock

import (
	"encoding/json"
	"errors"
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
	case errors.Is(err, errExpectedNotRegistered):
		// 404 like an unknown dockerId: from the caller's side there is nothing
		// to call. The message is the difference — it says the instance is
		// configured and simply has not registered, instead of implying the
		// name is wrong.
		writeEnvelope(w, http.StatusNotFound, "该实例在清单中，但尚未向平台注册，没有可用的 TAA 地址", nil, http.StatusNotFound)
		return true
	case errors.Is(err, errNoInstance):
		writeEnvelope(w, http.StatusServiceUnavailable, "尚无 TAA 实例注册", nil, http.StatusServiceUnavailable)
		return true
	}
	return false
}

// requireMethod applies the console's method guard: it answers a CORS preflight
// itself and rejects any method other than the one the route serves. It reports
// whether the request may continue.
func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return false
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 "+method+" 方法", nil, http.StatusMethodNotAllowed)
		return false
	}
	return true
}

// Instance kinds the console can show. The registration has no explicit server
// type field, so the kind is inferred from the report it carries.
const (
	instanceKindTEE          = "tee"
	instanceKindFHE          = "fhe"
	instanceKindDataAnalysis = "data-anaylsis"
	// instanceKindUnknown is the group a registration that matches no inventory
	// entry and has no report to infer from is listed under.
	instanceKindUnknown = ""
)

// validInstanceKind reports whether kind names a console instance type. The
// spelling of data-anaylsis is TAA's own (ServerTypeDataAnalysis), typo
// included; accepting a corrected spelling here would split the vocabulary.
func validInstanceKind(kind string) bool {
	switch kind {
	case instanceKindTEE, instanceKindFHE, instanceKindDataAnalysis:
		return true
	}
	return false
}

// registrationKind derives the instance kind from its registration.
//
// An FHE instance is not a TEE: it writes an empty attestation file and keeps
// verifiedPass false, which is the only difference the platform can see. A TEE
// instance submits a CPU/CSV report and verifies it, so any report content is
// enough to call it a TEE even when verification failed.
//
// The inference is not exact: a TEE instance running without /dev/csv-guest
// registers the same way as FHE (empty report, verifiedPass false) and is shown
// as FHE. That matches what the platform was told - it has no attestation to
// distinguish the two.
func registrationKind(reg registerState) string {
	if !reg.Received {
		return ""
	}
	if reg.AttestationSize > 0 || reg.AttestationBase64 != "" || reg.VerifiedPass {
		return instanceKindTEE
	}
	return instanceKindFHE
}

// instanceSummary is the console's one-line view of a registered instance.
type instanceSummary struct {
	DockerID string `json:"dockerId"`
	Kind     string `json:"kind"`
	// Expected marks a row that comes from the configured inventory rather than
	// from something that registered. It is separate from Received so the
	// console can tell "never registered" (未连接) from "registered but
	// rejected" (注册失败) without a second list.
	Expected      bool   `json:"expected"`
	Accepted      bool   `json:"accepted"`
	Received      bool   `json:"received"`
	ReceivedAt    string `json:"receivedAt"`
	TaaTarget     string `json:"taaTarget"`
	LastReportAt  string `json:"lastReportAt"`
	ModelLogCount int    `json:"modelLogCount"`
	TaaLogCount   int    `json:"taaLogCount"`
	Default       bool   `json:"default"`
	// SourceAddr and UserAgent are the registration's origin as the platform
	// observed it. dockerId is an identity the instance was configured with, not
	// a Pod name, so these are what the console shows when the two disagree.
	SourceAddr string `json:"sourceAddr,omitempty"`
	UserAgent  string `json:"userAgent,omitempty"`
}

func lastReportAt(b *instanceStores) string {
	latest := ""
	for _, store := range []*reportStateStore{b.reportResourceRes, b.reportRes, b.reportModelImport, b.reportAudit} {
		if at := store.get().ReceivedAt; compareTimestamps(at, latest) > 0 {
			latest = at
		}
	}
	return latest
}

func summarizeInstance(mgr *instanceManager, b *instanceStores) instanceSummary {
	reg := b.register.get()
	return instanceSummary{
		DockerID:      b.dockerID,
		Kind:          registrationKind(reg),
		Accepted:      reg.Accepted,
		Received:      reg.Received,
		ReceivedAt:    reg.ReceivedAt,
		TaaTarget:     targetForDisplay(mgr, b.dockerID),
		LastReportAt:  lastReportAt(b),
		ModelLogCount: b.modelLog.get().TotalCount,
		TaaLogCount:   b.taaLog.get().TotalCount,
		SourceAddr:    reg.SourceAddr,
		UserAgent:     reg.UserAgent,
	}
}

// instanceListPayload builds the console's list: everything that registered,
// merged with the configured inventory so an instance that has not registered
// is still listed (as 未连接) rather than absent.
//
// The default is the first accepted registration, as it always was. An
// inventory entry that never registered is not a candidate: the console's own
// requests would be addressed to an address nothing answers, and every panel
// would read as broken instead of empty.
func instanceListPayload(mgr *instanceManager) ([]instanceSummary, string) {
	registered := make([]instanceSummary, 0)
	for _, b := range mgr.list() {
		// The empty-id legacy bundle is a write fallback, not an instance: the
		// console cannot address it, so listing it would offer a phantom entry
		// whose selection snaps back on the next poll.
		if b.dockerID == "" {
			continue
		}
		registered = append(registered, summarizeInstance(mgr, b))
	}
	items := mergeExpectedInstances(mgr, mgr.expectedConfig(), registered)
	if len(items) == 0 {
		return items, ""
	}
	// list() is already in default order, so the first accepted registration is
	// also the first one here: inventory entries precede a registration only
	// when they registered, and those carry their accepted flag.
	defaultID := ""
	for i := range items {
		if !items[i].Received {
			continue
		}
		items[i].Default = true
		defaultID = items[i].DockerID
		break
	}
	return items, defaultID
}

func instancesHandler(mgr *instanceManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
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
		if !requireMethod(w, r, http.MethodGet) {
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
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
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
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		if id := requestedDockerID(r); id != "" {
			b := mgr.lookup(id)
			if b == nil {
				writeInstanceError(w, errInstanceNotFound)
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
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		b, err := mgr.resolveLenient(r)
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
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		b, err := mgr.resolveLenient(r)
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
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		b, err := mgr.resolveLenient(r)
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
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		b, err := mgr.resolveLenient(r)
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
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
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
