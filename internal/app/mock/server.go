// Package mock implements the platform mock service used to exercise the
// TAA daemon during local development and integration testing. It embeds a
// small web console (index.html), exposes the register/report/upload HTTP
// endpoints that a real platform backend would expose, and optionally
// reverse-proxies requests to a real TAA instance for end-to-end testing.
package mock

import (
	"context"
	_ "embed"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed index.html
var indexHTML string

// Server is the platform mock HTTP server.
type Server struct {
	cfg        Config
	uploadDir  string
	taaAddr    string
	httpServer *http.Server
}

// NewServer builds a Server from cfg: it resolves the TAA reverse-proxy
// target, prepares the state/upload directories, and registers all HTTP
// routes. It does not start listening; call Start (or Run) for that.
func NewServer(cfg Config) *Server {
	cfg = cfg.withDefaults()

	if err := os.MkdirAll(cfg.StateDir, 0o755); err != nil {
		log.Printf("failed to create state directory %s: %v", cfg.StateDir, err)
	}

	// Resolve TAA proxy target
	taaAddr := strings.TrimRight(strings.TrimSpace(cfg.TAATarget), "/")
	if taaAddr == "" {
		taaAddr = discoverTAAAddr(cfg.TAAPod, cfg.TAANS, strings.TrimSpace(cfg.TAAPort))
	}
	if taaAddr != "" {
		log.Printf("TAA reverse proxy target: %s (pod=%s)", taaAddr, cfg.TAAPod)
	} else {
		log.Printf("TAA reverse proxy disabled: set -taa-target or ensure kubectl can reach pod %q", cfg.TAAPod)
	}

	registerStore := newRegisterStateStore(cfg.StateDir)
	reportStore := newReportStateStore(cfg.StateDir)
	reportResStore := newReportStateStore(cfg.StateDir, "reportRes-state.json")
	reportModelImportStore := newReportStateStore(cfg.StateDir, "reportModelImport-state.json")
	reportAuditStore := newReportStateStore(cfg.StateDir, "reportAudit-state.json")
	progressStore := newProgressStateStore(cfg.StateDir)
	modelLogStore := newModelLogStore(cfg.StateDir, 2000)
	taaLogStore := newTaaLogStore(cfg.StateDir, 2000)

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
	mux.HandleFunc("/v1/taa/register", registerHandler(registerStore, cfg.AllowEmptyAttestation))
	mux.HandleFunc("/v1/taa/reportResourceRes", reportResourceResHandler(reportStore))
	mux.HandleFunc("/v1/taa/reportRes", reportResHandler(reportResStore))
	mux.HandleFunc("/v1/taa/reportModelImport", reportModelImportHandler(reportModelImportStore))
	mux.HandleFunc("/v1/taa/reportAudit", reportAuditHandler(reportAuditStore))
	mux.HandleFunc("/v1/taa/reportProgress", reportProgressHandler(progressStore))
	mux.HandleFunc("/v1/taa/modelLog", modelLogHandler(modelLogStore))
	mux.HandleFunc("/v1/taa/taaLog", taaLogHandler(taaLogStore))
	mux.HandleFunc("/api/dashboard/status", dashboardStatusHandler(registerStore, reportModelImportStore, reportAuditStore, progressStore, taaAddr))
	mux.HandleFunc("/api/register/status", registerStatusHandler(registerStore))
	mux.HandleFunc("/api/register/reset", registerResetHandler(registerStore))
	mux.HandleFunc("/api/reportResourceRes/status", reportStatusHandler(reportStore))
	mux.HandleFunc("/api/reportResourceRes/reset", reportResetHandler(reportStore))
	mux.HandleFunc("/api/reportRes/status", reportStatusHandler(reportResStore))
	mux.HandleFunc("/api/reportRes/reset", reportResetHandler(reportResStore))
	mux.HandleFunc("/api/reportModelImport/status", reportStatusHandler(reportModelImportStore))
	mux.HandleFunc("/api/reportModelImport/reset", reportResetHandler(reportModelImportStore))
	mux.HandleFunc("/api/reportAudit/status", reportStatusHandler(reportAuditStore))
	mux.HandleFunc("/api/reportAudit/reset", reportResetHandler(reportAuditStore))
	mux.HandleFunc("/api/reportProgress/status", progressStatusHandler(progressStore))
	mux.HandleFunc("/api/reportProgress/reset", progressResetHandler(progressStore))
	mux.HandleFunc("/api/modelLog/status", modelLogStatusHandler(modelLogStore))
	mux.HandleFunc("/api/modelLog/reset", modelLogResetHandler(modelLogStore))
	mux.HandleFunc("/api/taaLog/status", taaLogStatusHandler(taaLogStore))
	mux.HandleFunc("/api/taaLog/reset", taaLogResetHandler(taaLogStore))
	mux.HandleFunc("/api/taa-target", taaTargetHandler(taaAddr))
	mux.HandleFunc("/api/upload", uploadHandler(cfg.Addr, uploadDir, registerStore))
	registerUploadDeleteRoutes(mux, uploadDir)
	mux.HandleFunc("/api/uploads", uploadListHandler(cfg.Addr, uploadDir))
	mux.HandleFunc("/api/uploads/reset", uploadResetHandler(uploadDir))
	mux.HandleFunc("/api/crypto/generate-key", cryptoGenerateKeyHandler)
	mux.HandleFunc("/api/crypto/decrypt", cryptoDecryptHandler)
	mux.HandleFunc("/api/request-logs/status", requestLogsStatusHandler)
	mux.HandleFunc("/api/request-logs/reset", requestLogsResetHandler)
	mux.HandleFunc("/api/taa/status", taaStatusHandler(taaAddr))
	mux.HandleFunc("/api/taa/getResourceInfo", taaGetResourceInfoHandler(taaAddr))
	mux.HandleFunc("/api/taa/stopTraining", taaStopTrainingHandler(taaAddr))

	// Serve uploaded files
	mux.Handle("/files/", http.StripPrefix("/files/", http.FileServer(http.Dir(uploadDir))))

	// TAA reverse proxy: /taa/* → TAA pod
	if taaAddr != "" {
		target, err := url.Parse(taaAddr)
		if err != nil {
			log.Printf("invalid TAA target %q: %v", taaAddr, err)
		} else {
			proxy := httputil.NewSingleHostReverseProxy(target)
			proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
				log.Printf("TAA proxy error: %s %s → %v", r.Method, r.URL.Path, err)
				writeEnvelope(w, http.StatusBadGateway, "TAA proxy error: "+err.Error(), nil, http.StatusBadGateway)
			}
			mux.Handle("/taa/", http.StripPrefix("/taa", loggingReverseProxyHandler(proxy)))
		}
	}

	return &Server{
		cfg:       cfg,
		uploadDir: uploadDir,
		taaAddr:   taaAddr,
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

