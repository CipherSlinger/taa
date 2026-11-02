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
		{"/v1/taa/fheCallback", state.fheCallbackHandler},
		{"/v1/taa/stopTraining", state.stopTrainingHandler},
		{"/v1/taa/import", state.importHandler},
		{"/v1/taa/importModel", state.modelImportHandler},
		{"/v1/taa/getResourceInfo", state.resourceInfoHandler},
		{"/v1/taa/switch", state.switchHandler},
		{"/v1/taa/export", state.exportHandler},
		{"/v1/taa/getAttestation", state.getAttestationHandler},
		{"/v1/taa/status", state.statusHandler},
	}

	for _, route := range taaRoutes {
		handler := route.handler
		// fheCallback is the only unsealed route. Its caller is the FHE service,
		// not the platform, and it has no platform private key to seal with; the
		// endpoint keeps its loopback-source check instead. Every other route is
		// called by the platform and requires an envelope in both directions.
		if route.path != fheCallbackPath {
			// Inside postOnly: a method rejection has no request body to open and
			// no handler to protect, so it must not be reported as a malformed
			// envelope.
			handler = state.envelopeMiddleware(handler)
		}
		mux.HandleFunc(route.path, postOnly(handler))
	}
}

// fheCallbackPath is referenced by name so the exemption above cannot silently
// stop matching when a route is renamed.
const fheCallbackPath = "/v1/taa/fheCallback"

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
