// Package mock implements the platform mock service used to exercise the
// TAA daemon during local development and integration testing. It embeds a
// small web console (index.html), exposes the register/report/upload HTTP
// endpoints that a real platform backend would expose, and reverse-proxies
// console requests to the TAA instance the console names.
package mock

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed all:static
var staticFS embed.FS

var (
	indexHTML      string
	frontendBundle string
)

func init() {
	b, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		panic("failed to read embedded static/index.html: " + err.Error())
	}
	indexHTML = string(b)

	var sb strings.Builder
	sb.WriteString(indexHTML)
	sb.WriteString("\n")

	jsFiles := []string{
		"static/js/toast.js",
		"static/js/drawer.js",
		"static/js/api.js",
		"static/js/crypto.js",
		"static/js/tree.js",
		"static/js/logs.js",
		"static/js/app.js",
	}
	for _, f := range jsFiles {
		content, readErr := staticFS.ReadFile(f)
		if readErr == nil {
			sb.WriteString("\n/* " + f + " */\n")
			sb.Write(content)
		}
	}
	frontendBundle = sb.String()
}

// Server is the platform mock HTTP server.
type Server struct {
	cfg        Config
	httpServer *http.Server
}

// NewServer builds a Server from cfg: it prepares the state/upload directories,
// builds the per-instance manager, and registers all HTTP routes. The console
// endpoints and the /taa/* proxy resolve the selected instance's target per
// request. It does not start listening; call Start (or Run) for that.
func NewServer(cfg Config) *Server {
	cfg = cfg.withDefaults()

	if err := os.MkdirAll(cfg.StateDir, 0o755); err != nil {
		log.Printf("failed to create state directory %s: %v", cfg.StateDir, err)
	}

	// The keystore is installed before anything is routed: the envelope is
	// mandatory on every TAA route, so a server without one could not serve a
	// single callback. A failure here is logged and leaves the routes answering
	// with an envelope error rather than silently exchanging plaintext.
	keys, err := newKeystore(cfg.StateDir, cfg.PlatformKeyFile, []byte(cfg.SM2ID))
	if err != nil {
		log.Printf("[envelope] platform keystore unavailable, TAA callbacks will be refused: %v", err)
	} else {
		setPlatformKeys(keys)
	}

	mgr := newInstanceManager(cfg.StateDir, cfg)
	if mgr.staticTarget != "" {
		log.Printf("TAA reverse proxy: static target %s", mgr.staticTarget)
	} else {
		log.Printf("TAA reverse proxy: per-instance targets from registration (discovered fallback %q)", mgr.discoveredTarget)
	}

	uploadDir := cfg.UploadDir
	if abs, err := filepath.Abs(uploadDir); err == nil {
		uploadDir = abs
	}
	if err := os.MkdirAll(uploadDir, 0o755); err != nil {
		log.Printf("failed to create upload directory %s: %v", uploadDir, err)
	} else {
		log.Printf("upload directory: %s", uploadDir)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/index.html", indexHandler)

	// Serve embedded static assets (/static/*)
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Printf("failed to create static sub FS: %v", err)
	} else {
		mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))
	}
	mux.HandleFunc("/v1/taa/register", registerHandler(mgr, cfg.AllowEmptyAttestation))
	mux.HandleFunc("/v1/taa/reportResourceRes", reportResourceResHandler(mgr))
	mux.HandleFunc("/v1/taa/reportRes", reportResHandler(mgr))
	mux.HandleFunc("/v1/taa/reportModelImport", reportModelImportHandler(mgr))
	mux.HandleFunc("/v1/taa/reportAudit", reportAuditHandler(mgr))
	mux.HandleFunc("/v1/taa/reportProgress", reportProgressHandler(mgr))
	mux.HandleFunc("/v1/taa/modelLog", modelLogHandler(mgr))
	mux.HandleFunc("/v1/taa/taaLog", taaLogHandler(mgr))
	// The LLM reports in plaintext on its own prefix and is not attached to any
	// TAA instance, so these routes keep their own state and log store.
	llmState := newLLMStateStore(cfg.StateDir)
	llmLogStore := newTaaLogStoreAt(defaultStateFile(cfg.StateDir, "llm-log-state.json"), 2000)
	mux.HandleFunc("/v1/llm/register", llmRegisterHandler(llmState))
	mux.HandleFunc("/v1/llm/heartbeat", llmHeartbeatHandler(llmState))
	mux.HandleFunc("/v1/llm/log", llmLogHandler(llmLogStore))
	mux.HandleFunc("/api/llm/status", llmStatusHandler(llmState, llmLogStore))
	mux.HandleFunc("/api/llm/reset", llmResetHandler(llmState))
	mux.HandleFunc("/api/instances", instancesHandler(mgr))
	mux.HandleFunc("/api/dashboard/status", dashboardStatusHandler(mgr))
	mux.HandleFunc("/api/register/status", registerStatusHandler(mgr))
	mux.HandleFunc("/api/register/reset", registerResetHandler(mgr))
	mux.HandleFunc("/api/reportResourceRes/status", reportStatusHandler(mgr, func(b *instanceStores) *reportStateStore { return b.reportResourceRes }))
	mux.HandleFunc("/api/reportResourceRes/reset", reportResetHandler(mgr, func(b *instanceStores) *reportStateStore { return b.reportResourceRes }))
	mux.HandleFunc("/api/reportRes/status", reportStatusHandler(mgr, func(b *instanceStores) *reportStateStore { return b.reportRes }))
	mux.HandleFunc("/api/reportRes/reset", reportResetHandler(mgr, func(b *instanceStores) *reportStateStore { return b.reportRes }))
	mux.HandleFunc("/api/reportModelImport/status", reportStatusHandler(mgr, func(b *instanceStores) *reportStateStore { return b.reportModelImport }))
	mux.HandleFunc("/api/reportModelImport/reset", reportResetHandler(mgr, func(b *instanceStores) *reportStateStore { return b.reportModelImport }))
	mux.HandleFunc("/api/reportAudit/status", reportStatusHandler(mgr, func(b *instanceStores) *reportStateStore { return b.reportAudit }))
	mux.HandleFunc("/api/reportAudit/reset", reportResetHandler(mgr, func(b *instanceStores) *reportStateStore { return b.reportAudit }))
	mux.HandleFunc("/api/reportProgress/status", progressStatusHandler(mgr))
	mux.HandleFunc("/api/reportProgress/reset", progressResetHandler(mgr))
	mux.HandleFunc("/api/modelLog/status", modelLogStatusHandler(mgr))
	mux.HandleFunc("/api/modelLog/reset", modelLogResetHandler(mgr))
	mux.HandleFunc("/api/taaLog/status", taaLogStatusHandler(mgr))
	mux.HandleFunc("/api/taaLog/reset", taaLogResetHandler(mgr))
	mux.HandleFunc("/api/taa-target", taaTargetHandler(mgr))
	mux.HandleFunc("/api/upload", uploadHandler(cfg.Addr, uploadDir, mgr))
	registerUploadDeleteRoutes(mux, uploadDir)
	mux.HandleFunc("/api/uploads", uploadListHandler(cfg.Addr, uploadDir))
	mux.HandleFunc("/api/uploads/reset", uploadResetHandler(uploadDir))
	mux.HandleFunc("/api/fhe/submit", fheSubmitHandler(cfg, mgr))
	mux.HandleFunc("/api/crypto/generate-key", cryptoGenerateKeyHandler)
	mux.HandleFunc("/api/crypto/decrypt", cryptoDecryptHandler)
	mux.HandleFunc("/api/request-logs/status", requestLogsStatusHandler)
	mux.HandleFunc("/api/request-logs/reset", requestLogsResetHandler)
	mux.HandleFunc("/api/taa/status", taaStatusHandler(mgr))
	mux.HandleFunc("/api/taa/getResourceInfo", taaGetResourceInfoHandler(mgr))
	mux.HandleFunc("/api/taa/stopTraining", taaStopTrainingHandler(mgr))

	// Serve uploaded files
	mux.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir(uploadDir))))

	// TAA reverse proxy: /taa/* → the selected instance's TAA target. The target
	// is resolved per request, so this mount stays unconditional: a console call
	// made before any instance registered gets an explained 502 instead of a
	// route that does not exist.
	mux.Handle("/taa/", loggingReverseProxyHandler(http.StripPrefix("/taa", dynamicTAAProxyHandler(mgr, newProxyPool()))))

	return &Server{
		cfg: cfg,
		httpServer: &http.Server{
			Addr:              cfg.Addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
}

// Start runs the mock server until ctx is cancelled, then gracefully shuts
// it down. It returns any error encountered while serving or shutting down.
func (s *Server) Start(ctx context.Context) error {
	for _, u := range accessURLs(s.cfg.Addr) {
		log.Printf("mock platform URL: %s", u)
	}
	log.Printf("TAA should use PLATFORM_IP=%s", platformIP(s.cfg.Addr))

	serveErr := make(chan error, 1)
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return <-serveErr
	case err := <-serveErr:
		return err
	}
}

// Run builds a Server from cfg and starts it, blocking until ctx is
// cancelled or the server fails.
func Run(ctx context.Context, cfg Config) error {
	srv := NewServer(cfg)
	return srv.Start(ctx)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	_, _ = w.Write([]byte(indexHTML))
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeEnvelope(w http.ResponseWriter, status int, msg string, result any, errorCode int) {
	writeJSON(w, status, apiResponse{Msg: msg, Result: result, Error: errorCode})
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func accessURLs(addr string) []string {
	port := listenPort(addr)
	urls := []string{"http://127.0.0.1:" + port + "/"}
	for _, ip := range localIPv4Addrs() {
		if ip == "127.0.0.1" {
			continue
		}
		urls = append(urls, "http://"+ip+":"+port+"/")
	}
	return dedupe(urls)
}

func platformIP(addr string) string {
	port := listenPort(addr)
	ips := localIPv4Addrs()
	if len(ips) > 0 {
		return ips[0] + ":" + port
	}
	return "127.0.0.1:" + port
}

func listenPort(addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil && port != "" {
		return port
	}
	if strings.HasPrefix(addr, ":") && len(addr) > 1 {
		return strings.TrimPrefix(addr, ":")
	}
	return "8080"
}

func localIPv4Addrs() []string {
	seen := map[string]struct{}{}
	var addrs []string
	ifs, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifs {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			ifaceAddrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range ifaceAddrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				ip = ip.To4()
				if ip == nil || ip.IsLoopback() {
					continue
				}
				text := ip.String()
				if _, ok := seen[text]; ok {
					continue
				}
				seen[text] = struct{}{}
				addrs = append(addrs, text)
			}
		}
	}
	if len(addrs) == 0 {
		return []string{"127.0.0.1"}
	}
	return addrs
}

func dedupe(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
