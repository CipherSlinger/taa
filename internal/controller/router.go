package controller

import (
	"net/http"
)

// RegisterRoutes 注册 TAA 服务端全部 API 路由与安全中间件
func RegisterRoutes(mux *http.ServeMux, state *TAAState) {
	taaRoutes := []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/v1/taa/health", state.healthHandler},
		{"/v1/taa/stopTraining", state.stopTrainingHandler},
		{"/v1/taa/import", state.importHandler},
		{"/v1/taa/importModel", state.modelImportHandler},
		{"/v1/taa/getResourceInfo", state.resourceInfoHandler},
		{"/v1/taa/switch", state.switchHandler},
		{"/v1/taa/export", state.exportHandler},
		{"/v1/taa/getAttestation", state.getAttestationHandler},
		{"/v1/taa/logs", state.logsHandler},
		{"/v1/taa/status", state.statusHandler},
	}

	for _, route := range taaRoutes {
		mux.HandleFunc(route.path, postOnly(route.handler))
	}
}

// postOnly 强制仅允许 POST 请求并注入 CORS 安全头
func postOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Disposition, Content-Length, X-TAA-Task-Id, X-TAA-Encrypted")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, apiResponse{
				Msg:    "仅支持 POST 方法",
				Result: nil,
				Error:  http.StatusMethodNotAllowed,
			})
			return
		}
		next(w, r)
	}
}
