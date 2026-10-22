package taa

import (
	"bytes"
	"context"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CipherSlinger/teetls"
	"taa/internal/attestation"
	"taa/internal/codeaudit"
	"taa/internal/config"
	teecrypto "taa/pkg/crypto"
)

// TestDeriveUserDataAndKeyPair 校验国密 SM2 密钥生成与 UserData 派生逻辑：
// 生成的密钥对应可用于派生出恰好 64 字节的 UserData（前 32 字节 X，后 32 字节 Y）。
func TestDeriveUserDataAndKeyPair(t *testing.T) {
	keyPair, err := generateTAAKeyPair()
	if err != nil {
		t.Fatalf("generate key pair failed: %v", err)
	}
	if keyPair.PrivateKey == nil {
		t.Fatalf("expected non-nil private key")
	}
	if keyPair.PublicKeyPEM == "" {
		t.Fatalf("expected non-empty public key PEM")
	}

	userData, err := deriveUserData(&keyPair.PrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("derive user data failed: %v", err)
	}
	if len(userData) != 64 {
		t.Fatalf("expected 64 bytes userdata, got %d", len(userData))
	}
}

// TestDeriveUserDataNilPublicKey 校验缺失公钥坐标时返回错误而非 panic
func TestDeriveUserDataNilPublicKey(t *testing.T) {
	if _, err := deriveUserData(nil); err == nil {
		t.Fatalf("expected error for nil public key")
	}
}

// TestDeriveUserDataExcessiveCoordinateLength 校验公钥坐标长度超过 32 字节时返回错误而非 panic
func TestDeriveUserDataExcessiveCoordinateLength(t *testing.T) {
	hugeVal := new(big.Int).Lsh(big.NewInt(1), 260) // > 32 字节
	pub := &teecrypto.SM2PublicKey{
		X: hugeVal,
		Y: big.NewInt(1),
	}
	if _, err := deriveUserData(pub); err == nil {
		t.Fatalf("expected error when coordinate length exceeds 32 bytes")
	}
}

// TestCheckKeyFileExists_DirectoryTargetFails 校验路径为目录时 checkKeyFileExists 严格返回错误而非假定存在
func TestCheckKeyFileExists_DirectoryTargetFails(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "sub-dir")
	if err := os.Mkdir(subDir, 0o700); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	exists, err := checkKeyFileExists(subDir)
	if err == nil {
		t.Fatalf("expected error when key file target is a directory, got exists=%v", exists)
	}
	if !strings.Contains(err.Error(), "found directory") {
		t.Fatalf("expected 'found directory' error message, got: %v", err)
	}
}

// TestBuildSecurityConfig verifies mapping from StartupConfig to controller.SecurityConfig
func TestBuildSecurityConfig(t *testing.T) {
	// CodeScan.Engine is set explicitly because an unset engine name is rejected
	// rather than treated as the baseline: a caller that bypassed the config
	// loader must not get a scan with an engine nobody chose. The loader's own
	// default is "semgrep" and is asserted in the config package.
	cfg := config.StartupConfig{
		EnableCodeAudit:   true,
		ServerType:        config.ServerTypeDataAnalysis,
		CodeScan:          config.CodeScanConfig{Engine: "regex"},
		ModelDir:          "/opt/taa/models",
		EnableResultCheck: true,
		DataDir:           "/opt/taa/data",
		ResultDir:         "/opt/taa/results",
		ModelInputDir:     "/opt/taa/models/input",
		ModelOutputDir:    "/opt/taa/models/output",
		ModelLogDir:       "/opt/taa/models/log",
		ModelProgressDir:  "/opt/taa/models/progress",
		LLM: config.LLMConfig{
			Enabled:                 true,
			AttestationEnabled:      true,
			Endpoint:                "https://127.0.0.1:8443",
			AttestationMeasurement:  "measure-1",
			HRKCertPath:             "/path/hrk.cert",
			HSKCekCertPath:          "/path/hsk.cert",
			RequireMutualAttest:     true,
			InsecureSkipVerify:      true,
			AuthToken:               "test-secret-token",
			TimeoutMs:               60000,
			AllowedHosts:            []string{"127.0.0.1", "localhost"},
			CircuitBreakerThreshold: 5,
			CooldownSec:             45,
			Model:                   "qwen2.5-coder:0.5b",
			FailClosed:              true,
		},
		BinaryAuditEnabled:              true,
		BinaryAuditMaxArchiveMembers:    17,
		BinaryAuditHighEntropyThreshold: 7.25,
		BinaryAuditMaxFindings:          23,
		BinaryAuditMaxFullScanBytes:     134217728,
		BinaryAuditMaxStreamBytes:       268435456,
	}

	sec, err := buildSecurityConfig(cfg)
	if err != nil {
		t.Fatalf("buildSecurityConfig() error = %v", err)
	}

	if sec.ScanEnabled != cfg.EnableCodeAudit {
		t.Errorf("ScanEnabled = %v, want %v", sec.ScanEnabled, cfg.EnableCodeAudit)
	}
	if sec.ModelDir != cfg.ModelDir {
		t.Errorf("ModelDir = %q, want %q", sec.ModelDir, cfg.ModelDir)
	}
	if sec.ResultCheck != cfg.EnableResultCheck {
		t.Errorf("ResultCheck = %v, want %v", sec.ResultCheck, cfg.EnableResultCheck)
	}
	if sec.DataDir != cfg.DataDir {
		t.Errorf("DataDir = %q, want %q", sec.DataDir, cfg.DataDir)
	}
	if sec.ServerType != cfg.ServerType {
		t.Errorf("ServerType = %q, want %q", sec.ServerType, cfg.ServerType)
	}
	if sec.ResultDir != cfg.ResultDir {
		t.Errorf("ResultDir = %q, want %q", sec.ResultDir, cfg.ResultDir)
	}
	if sec.ModelInputDir != cfg.ModelInputDir {
		t.Errorf("ModelInputDir = %q, want %q", sec.ModelInputDir, cfg.ModelInputDir)
	}
	if sec.ModelOutputDir != cfg.ModelOutputDir {
		t.Errorf("ModelOutputDir = %q, want %q", sec.ModelOutputDir, cfg.ModelOutputDir)
	}
	if sec.ModelLogDir != cfg.ModelLogDir {
		t.Errorf("ModelLogDir = %q, want %q", sec.ModelLogDir, cfg.ModelLogDir)
	}
	if sec.ModelProgressDir != cfg.ModelProgressDir {
		t.Errorf("ModelProgressDir = %q, want %q", sec.ModelProgressDir, cfg.ModelProgressDir)
	}

	wantLLM := codeaudit.LLMConfig{
		Enabled:                 cfg.LLM.Enabled,
		AttestationEnabled:      cfg.LLM.AttestationEnabled,
		Endpoint:                cfg.LLM.Endpoint,
		AttestationMeasurement:  cfg.LLM.AttestationMeasurement,
		HRKCertPath:             cfg.LLM.HRKCertPath,
		HSKCekCertPath:          cfg.LLM.HSKCekCertPath,
		RequireMutualAttest:     cfg.LLM.RequireMutualAttest,
		InsecureSkipVerify:      cfg.LLM.InsecureSkipVerify,
		AuthToken:               cfg.LLM.AuthToken,
		Model:                   cfg.LLM.Model,
		Timeout:                 60 * time.Second,
		MaxFindings:             0,
		FailClosed:              cfg.LLM.FailClosed,
		AllowedHosts:            cfg.LLM.AllowedHosts,
		CircuitBreakerThreshold: cfg.LLM.CircuitBreakerThreshold,
		CooldownSec:             cfg.LLM.CooldownSec,
	}
	if sec.LLM.Enabled != wantLLM.Enabled {
		t.Errorf("LLM.Enabled = %v, want %v", sec.LLM.Enabled, wantLLM.Enabled)
	}
	if sec.LLM.AttestationEnabled != wantLLM.AttestationEnabled {
		t.Errorf("LLM.AttestationEnabled = %v, want %v", sec.LLM.AttestationEnabled, wantLLM.AttestationEnabled)
	}
	if sec.LLM.Endpoint != wantLLM.Endpoint {
		t.Errorf("LLM.Endpoint = %q, want %q", sec.LLM.Endpoint, wantLLM.Endpoint)
	}
	if sec.LLM.AttestationMeasurement != wantLLM.AttestationMeasurement {
		t.Errorf("LLM.AttestationMeasurement = %q, want %q", sec.LLM.AttestationMeasurement, wantLLM.AttestationMeasurement)
	}
	if sec.LLM.HRKCertPath != wantLLM.HRKCertPath {
		t.Errorf("LLM.HRKCertPath = %q, want %q", sec.LLM.HRKCertPath, wantLLM.HRKCertPath)
	}
	if sec.LLM.HSKCekCertPath != wantLLM.HSKCekCertPath {
		t.Errorf("LLM.HSKCekCertPath = %q, want %q", sec.LLM.HSKCekCertPath, wantLLM.HSKCekCertPath)
	}
	if sec.LLM.RequireMutualAttest != wantLLM.RequireMutualAttest {
		t.Errorf("LLM.RequireMutualAttest = %v, want %v", sec.LLM.RequireMutualAttest, wantLLM.RequireMutualAttest)
	}
	if sec.LLM.InsecureSkipVerify != wantLLM.InsecureSkipVerify {
		t.Errorf("LLM.InsecureSkipVerify = %v, want %v", sec.LLM.InsecureSkipVerify, wantLLM.InsecureSkipVerify)
	}
	if sec.LLM.AuthToken != wantLLM.AuthToken {
		t.Errorf("LLM.AuthToken = %q, want %q", sec.LLM.AuthToken, wantLLM.AuthToken)
	}
	if sec.LLM.Model != wantLLM.Model {
		t.Errorf("LLM.Model = %q, want %q", sec.LLM.Model, wantLLM.Model)
	}
	if sec.LLM.Timeout != wantLLM.Timeout {
		t.Errorf("LLM.Timeout = %v, want %v", sec.LLM.Timeout, wantLLM.Timeout)
	}
	if sec.LLM.MaxFindings != wantLLM.MaxFindings {
		t.Errorf("LLM.MaxFindings = %d, want %d", sec.LLM.MaxFindings, wantLLM.MaxFindings)
	}
	if sec.LLM.FailClosed != wantLLM.FailClosed {
		t.Errorf("LLM.FailClosed = %v, want %v", sec.LLM.FailClosed, wantLLM.FailClosed)
	}
	if len(sec.LLM.AllowedHosts) != len(wantLLM.AllowedHosts) {
		t.Errorf("LLM.AllowedHosts len = %d, want %d", len(sec.LLM.AllowedHosts), len(wantLLM.AllowedHosts))
	} else {
		for i := range wantLLM.AllowedHosts {
			if sec.LLM.AllowedHosts[i] != wantLLM.AllowedHosts[i] {
				t.Errorf("LLM.AllowedHosts[%d] = %q, want %q", i, sec.LLM.AllowedHosts[i], wantLLM.AllowedHosts[i])
			}
		}
	}
	if sec.LLM.CircuitBreakerThreshold != wantLLM.CircuitBreakerThreshold {
		t.Errorf("LLM.CircuitBreakerThreshold = %d, want %d", sec.LLM.CircuitBreakerThreshold, wantLLM.CircuitBreakerThreshold)
	}
	if sec.LLM.CooldownSec != wantLLM.CooldownSec {
		t.Errorf("LLM.CooldownSec = %d, want %d", sec.LLM.CooldownSec, wantLLM.CooldownSec)
	}

	// The binary channel's configuration is carried through rather than dropped:
	// a value that reaches the config struct and not the controller is a setting
	// an operator can write and cannot observe.
	//
	// The comparison is against the raw config value, not the resolved one. "0
	// means use the codeaudit default" resolves in exactly one place - the
	// codeaudit normalizer every extraction path already calls - and a second
	// resolver here would be a second place for the two to disagree about what
	// the default is. The resolution itself is proven at the codeaudit level.
	//
	// All six are compared, and each carries a different value, because the
	// failure this guards against is a pair swapped in the literal or a field
	// left at zero - both of which a check on one or two of them survives.
	if sec.Binary.Enabled != cfg.BinaryAuditEnabled {
		t.Errorf("SecurityConfig.Binary.Enabled = %t, want the value carried from BinaryAuditEnabled",
			sec.Binary.Enabled)
	}
	if sec.Binary.MaxArchiveMembers != cfg.BinaryAuditMaxArchiveMembers {
		t.Errorf("SecurityConfig.Binary.MaxArchiveMembers = %d, want the raw config value %d",
			sec.Binary.MaxArchiveMembers, cfg.BinaryAuditMaxArchiveMembers)
	}
	if sec.Binary.HighEntropyThreshold != cfg.BinaryAuditHighEntropyThreshold {
		t.Errorf("SecurityConfig.Binary.HighEntropyThreshold = %v, want the raw config value %v",
			sec.Binary.HighEntropyThreshold, cfg.BinaryAuditHighEntropyThreshold)
	}
	if sec.Binary.MaxFindings != cfg.BinaryAuditMaxFindings {
		t.Errorf("SecurityConfig.Binary.MaxFindings = %d, want the raw config value %d",
			sec.Binary.MaxFindings, cfg.BinaryAuditMaxFindings)
	}
	if sec.Binary.MaxFullScanBytes != int64(cfg.BinaryAuditMaxFullScanBytes) {
		t.Errorf("SecurityConfig.Binary.MaxFullScanBytes = %d, want the raw config value %d",
			sec.Binary.MaxFullScanBytes, cfg.BinaryAuditMaxFullScanBytes)
	}
	if sec.Binary.MaxStreamBytes != int64(cfg.BinaryAuditMaxStreamBytes) {
		t.Errorf("SecurityConfig.Binary.MaxStreamBytes = %d, want the raw config value %d",
			sec.Binary.MaxStreamBytes, cfg.BinaryAuditMaxStreamBytes)
	}

	// The enabled flag is checked in both directions. A single case with the
	// fixture set to true is satisfied by an Enabled hard-coded to true, which is
	// the one way this wiring can break while looking right: the channel would
	// then run on a deployment that turned it off.
	cfg.BinaryAuditEnabled = false
	sec, err = buildSecurityConfig(cfg)
	if err != nil {
		t.Fatalf("buildSecurityConfig() with the channel off error = %v", err)
	}
	if sec.Binary.Enabled {
		t.Error("SecurityConfig.Binary.Enabled = true for BinaryAuditEnabled false; the rollback would not take effect")
	}
}

// TestBuildSecurityConfigPassesThroughTemperature pins the translation of the
// sampling temperature from the startup configuration into the audit config.
//
// The unset case is the one that matters for the default deployment: nil has to
// stay nil all the way to the verify request, because nil is what leaves the
// inference service on its own deterministic default. Turning it into an
// explicit zero here would produce the same verdicts today but would silently
// stop tracking that default.
func TestBuildSecurityConfigPassesThroughTemperature(t *testing.T) {
	temp := func(v float32) *float32 { return &v }

	for _, tc := range []struct {
		name  string
		given *float32
	}{
		{"unset stays unset", nil},
		{"explicit zero survives", temp(0)},
		{"non-zero passes through", temp(0.3)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.StartupConfig{
				CodeScan: config.CodeScanConfig{Engine: "regex"},
				ModelDir: "/opt/taa/models",
				LLM: config.LLMConfig{
					Temperature: tc.given,
				},
			}

			sec, err := buildSecurityConfig(cfg)
			if err != nil {
				t.Fatalf("buildSecurityConfig() error = %v", err)
			}

			switch {
			case tc.given == nil && sec.LLM.Temperature != nil:
				t.Errorf("LLM.Temperature = %v, want nil", *sec.LLM.Temperature)
			case tc.given != nil && sec.LLM.Temperature == nil:
				t.Errorf("LLM.Temperature = nil, want %v", *tc.given)
			case tc.given != nil && *sec.LLM.Temperature != *tc.given:
				t.Errorf("LLM.Temperature = %v, want %v", *sec.LLM.Temperature, *tc.given)
			}
		})
	}
}

// TestBuildSecurityConfigResolvesTheConfiguredEngine pins that the engine named
// in the startup configuration is the one the controller will scan with. The
// whole point of resolving here rather than on the import path is that the
// selection is visible in the running configuration; if this mapping broke, the
// deployment would run whatever the selector's default is and nothing else would
// notice.
func TestBuildSecurityConfigResolvesTheConfiguredEngine(t *testing.T) {
	semgrepRules := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(semgrepRules, []byte("rules: []\n"), 0o644); err != nil {
		t.Fatalf("write rules fixture: %v", err)
	}

	for _, tc := range []struct {
		name     string
		engine   string
		rules    string
		wantName string
	}{
		{"regex", "regex", "", "regex"},
		{"semgrep", "semgrep", semgrepRules, "semgrep"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sec, err := buildSecurityConfig(config.StartupConfig{
				CodeScan: config.CodeScanConfig{Engine: tc.engine, RulesPath: tc.rules},
			})
			if err != nil {
				t.Fatalf("buildSecurityConfig() error = %v", err)
			}
			if sec.Engine == nil {
				t.Fatal("SecurityConfig.Engine = nil; the controller would have no engine to scan with")
			}
			if got := sec.Engine.Name(); got != tc.wantName {
				t.Errorf("SecurityConfig.Engine.Name() = %q, want %q", got, tc.wantName)
			}
		})
	}
}

// TestBuildSecurityConfigFailsFastOnAnUnusableEngine pins that a Tier 1 engine
// that cannot be honoured stops the process instead of starting and failing
// every import.
//
// Both cases below are configuration mistakes with consequences that look like
// the scanner working: an unknown name would silently scan with another engine,
// and a missing rules file fails every scan, which the import path reports as a
// failed audit. Neither is diagnosable from the
// audit result, so both have to be refused here.
func TestBuildSecurityConfigFailsFastOnAnUnusableEngine(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent-rules.yaml")

	for _, tc := range []struct {
		name   string
		engine string
		rules  string
	}{
		{"unknown engine name", "enforce", ""},
		{"unset engine name", "", ""},
		{"semgrep without rules", "semgrep", missing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sec, err := buildSecurityConfig(config.StartupConfig{
				CodeScan: config.CodeScanConfig{Engine: tc.engine, RulesPath: tc.rules},
			})
			if err == nil {
				t.Fatalf("buildSecurityConfig() accepted %q and returned engine %v; "+
					"the process must not start with an engine it cannot honour",
					tc.engine, sec.Engine)
			}
		})
	}
}

// TestRunConfigNotFound 校验配置文件不存在时 Run 返回错误
func TestRunConfigNotFound(t *testing.T) {
	ctx := context.Background()
	err := Run(ctx, filepath.Join(t.TempDir(), "nonexistent-config.json"), "")
	if err == nil {
		t.Fatal("expected error when config file does not exist")
	}
	if !strings.Contains(err.Error(), "load startup config") {
		t.Fatalf("expected 'load startup config' error, got: %v", err)
	}
}

func newTestTEETLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	mockProv := teetls.NewMockEvidenceProvider()
	listener, err := teetls.Listen("tcp", "127.0.0.1:0", &teetls.Config{
		Mode:             teetls.ModeStrict,
		EvidenceProvider: mockProv,
	})
	if err != nil {
		t.Fatalf("failed to create teetls listener: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	server.URL = "https://" + server.Listener.Addr().String()
	return server
}

// TestProbeInferenceService_ContextCancelled verifies probeInferenceService immediately returns error on cancelled context.
func TestProbeInferenceService_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := config.StartupConfig{
		LLM: config.LLMConfig{
			AttestationEnabled: true,
			Endpoint:           "https://127.0.0.1:65534",
			InsecureSkipVerify: true,
			TimeoutMs:          3000,
		},
	}

	err := probeInferenceService(ctx, cfg)
	if err == nil {
		t.Fatal("expected error on cancelled context, got nil")
	}
}

// TestProbeInferenceService_HealthyEndpoint verifies probeInferenceService succeeds when endpoint health check passes.
func TestProbeInferenceService_HealthyEndpoint(t *testing.T) {
	server := newTestTEETLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := config.StartupConfig{
		LLM: config.LLMConfig{
			AttestationEnabled: true,
			Endpoint:           server.URL,
			InsecureSkipVerify: true,
			TimeoutMs:          3000,
		},
	}

	err := probeInferenceService(context.Background(), cfg)
	if err != nil {
		t.Fatalf("expected healthy probe to succeed, got error: %v", err)
	}
}

// TestProbeInferenceService_UnhealthyEndpoint verifies probeInferenceService errors when endpoint returns failure.
func TestProbeInferenceService_UnhealthyEndpoint(t *testing.T) {
	server := newTestTEETLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unhealthy"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := config.StartupConfig{
		LLM: config.LLMConfig{
			AttestationEnabled: true,
			Endpoint:           server.URL,
			InsecureSkipVerify: true,
			TimeoutMs:          3000,
		},
	}

	err := probeInferenceService(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected probe error on unhealthy endpoint, got nil")
	}
}

// TestRunWithConfig_LLMProbeFailureDoesNotAbortStartup pins the contract that an
// unreachable inference service at startup is advisory, not fatal -- even with
// LLMFailClosed set. The initrd deployment starts TAA before kata-agent exists, so the
// guest has no network yet and a fatal probe would keep the VM from ever being handed
// over (measured 2026-10-10: "connect: network is unreachable" -> "[TAA-FATAL] probe
// inference service (fail-closed)"). The fail-closed guarantee lives in the pre-audit
// probe instead, which runs with the network up.
func TestRunWithConfig_LLMProbeFailureDoesNotAbortStartup(t *testing.T) {
	// A regular file where the keys directory belongs: the key-pair step then fails
	// deterministically, and the error it returns is the proof that control reached it
	// -- i.e. that the probe did not abort the startup flow.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	cfg := config.StartupConfig{
		LLM: config.LLMConfig{
			Enabled:            true,
			FailClosed:         true,
			AttestationEnabled: true,
			Endpoint:           "https://127.0.0.1:65534",
			InsecureSkipVerify: true,
			TimeoutMs:          100,
		},
		KeysDir: filepath.Join(blocker, "keys"),
	}

	err := RunWithConfig(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected the key-pair step to fail, got nil")
	}
	if strings.Contains(err.Error(), "probe inference service") {
		t.Fatalf("an unreachable inference service must not abort startup, got: %v", err)
	}
	if !strings.Contains(err.Error(), "SM2") {
		t.Fatalf("expected the probe to be survived and the key-pair step to fail, got: %v", err)
	}
}

func TestLoadOrGenerateTAAKeyPair_FirstBoot(t *testing.T) {
	keysDir := t.TempDir()

	keyPair, loaded, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil {
		t.Fatalf("first boot loadOrGenerateTAAKeyPair failed: %v", err)
	}
	if loaded {
		t.Fatalf("expected loaded=false on first boot, got loaded=true")
	}
	if keyPair == nil || keyPair.PrivateKey == nil || keyPair.PublicKeyPEM == "" {
		t.Fatalf("expected non-nil keyPair with valid keys")
	}

	privPath := filepath.Join(keysDir, defaultSM2PrivateKeyFile)
	pubPath := filepath.Join(keysDir, defaultSM2PublicKeyFile)

	privInfo, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("private key file does not exist: %v", err)
	}
	if privInfo.Mode().Perm() != 0o600 {
		t.Errorf("private key perm = %o, want 0600", privInfo.Mode().Perm())
	}

	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("public key file does not exist: %v", err)
	}
	if pubInfo.Mode().Perm() != 0o644 {
		t.Errorf("public key perm = %o, want 0644", pubInfo.Mode().Perm())
	}

	userData, err := deriveUserData(&keyPair.PrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("deriveUserData failed: %v", err)
	}
	if len(userData) != 64 {
		t.Fatalf("expected 64 bytes userdata, got %d", len(userData))
	}
}

func TestLoadOrGenerateTAAKeyPair_RebootPersistenceAndCryptoRoundTrip(t *testing.T) {
	keysDir := t.TempDir()

	// 第 1 次启动：生成并落盘
	keyPair1, loaded1, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil || loaded1 {
		t.Fatalf("first boot failed: loaded=%v, err=%v", loaded1, err)
	}

	// 使用启动 1 派生的公钥加密一段业务数据（模拟外部平台或客户端信封加密请求）
	plaintext := []byte("confidential-model-dataset-payload-2026")
	sealed, err := teecrypto.SealSM2SM4GCM(&keyPair1.PrivateKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("SealSM2SM4GCM failed: %v", err)
	}

	// 第 2 次启动（模拟重启）：检测到目录中已有密钥，自动加载
	keyPair2, loaded2, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil {
		t.Fatalf("second boot loadOrGenerateTAAKeyPair failed: %v", err)
	}
	if !loaded2 {
		t.Fatalf("expected loaded=true on reboot, got loaded=false")
	}

	// 验证公私钥内容完全一致
	if keyPair1.PrivateKey.D.Cmp(keyPair2.PrivateKey.D) != 0 {
		t.Fatalf("private key D coordinate mismatch after reboot")
	}
	if keyPair1.PublicKeyPEM != keyPair2.PublicKeyPEM {
		t.Fatalf("public key PEM mismatch after reboot")
	}

	// 使用重启后加载的私钥解密先前加密的数据包，确保历史解密能力一致
	decrypted, err := teecrypto.OpenSM2SM4GCM(keyPair2.PrivateKey, sealed)
	if err != nil {
		t.Fatalf("OpenSM2SM4GCM with rebooted key failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted text mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestLoadOrGenerateTAAKeyPair_TightensPermissionsOnReboot(t *testing.T) {
	keysDir := t.TempDir()

	// 首次启动生成
	_, _, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil {
		t.Fatalf("first boot failed: %v", err)
	}

	privPath := filepath.Join(keysDir, defaultSM2PrivateKeyFile)

	// 模拟外部意外将私钥修改为过于宽松的权限 0666，目录修改为 0777
	if err := os.Chmod(privPath, 0o666); err != nil {
		t.Fatalf("chmod private key failed: %v", err)
	}
	if err := os.Chmod(keysDir, 0o777); err != nil {
		t.Fatalf("chmod keysDir failed: %v", err)
	}

	// 重启加载时应自动收紧权限
	_, loaded, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil {
		t.Fatalf("reboot failed: %v", err)
	}
	if !loaded {
		t.Fatalf("expected loaded=true on reboot")
	}

	privInfo, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("stat private key failed: %v", err)
	}
	if privInfo.Mode().Perm() != 0o600 {
		t.Errorf("expected private key permission tightened to 0600, got %o", privInfo.Mode().Perm())
	}

	dirInfo, err := os.Stat(keysDir)
	if err != nil {
		t.Fatalf("stat keysDir failed: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("expected keysDir permission tightened to 0700, got %o", dirInfo.Mode().Perm())
	}
}

func TestLoadOrGenerateTAAKeyPair_MissingPublicKey_SelfHealing(t *testing.T) {
	keysDir := t.TempDir()

	keyPairOrig, _, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil {
		t.Fatalf("initial generation failed: %v", err)
	}

	// 模拟公钥意外丢失
	pubPath := filepath.Join(keysDir, defaultSM2PublicKeyFile)
	if err := os.Remove(pubPath); err != nil {
		t.Fatalf("remove public key failed: %v", err)
	}

	// 重启应触发自愈，从私钥重新导出并写入公钥
	keyPairHealed, loaded, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil {
		t.Fatalf("self-healing load failed: %v", err)
	}
	if !loaded {
		t.Fatalf("expected loaded=true when self-healing from existing private key")
	}
	if keyPairHealed.PublicKeyPEM != keyPairOrig.PublicKeyPEM {
		t.Fatalf("healed public key does not match original public key")
	}

	// 检查公钥文件已被重建
	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("healed public key file does not exist: %v", err)
	}
	if pubInfo.Mode().Perm() != 0o644 {
		t.Errorf("healed public key perm = %o, want 0644", pubInfo.Mode().Perm())
	}
}

func TestLoadOrGenerateTAAKeyPair_MissingPrivateKey_Fails(t *testing.T) {
	keysDir := t.TempDir()

	_, _, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil {
		t.Fatalf("initial generation failed: %v", err)
	}

	// 模拟私钥丢失而公钥残留
	privPath := filepath.Join(keysDir, defaultSM2PrivateKeyFile)
	if err := os.Remove(privPath); err != nil {
		t.Fatalf("remove private key failed: %v", err)
	}

	// 重启必须 Fail-Closed，拒绝重新生成覆写
	_, _, err = loadOrGenerateTAAKeyPair(keysDir)
	if err == nil {
		t.Fatalf("expected error when private key is missing but public key exists, got nil")
	}
	if !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("expected 'refusing to overwrite' error, got: %v", err)
	}
}

func TestLoadOrGenerateTAAKeyPair_CorruptedFile_Fails(t *testing.T) {
	keysDir := t.TempDir()
	privPath := filepath.Join(keysDir, defaultSM2PrivateKeyFile)
	pubPath := filepath.Join(keysDir, defaultSM2PublicKeyFile)

	if err := os.WriteFile(privPath, []byte("NOT_A_VALID_PEM_PRIVATE_KEY"), 0o600); err != nil {
		t.Fatalf("write invalid private key: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte("NOT_A_VALID_PEM_PUBLIC_KEY"), 0o644); err != nil {
		t.Fatalf("write invalid public key: %v", err)
	}

	_, _, err := loadOrGenerateTAAKeyPair(keysDir)
	if err == nil {
		t.Fatalf("expected error for corrupted key files, got nil")
	}
}

func TestLoadOrGenerateTAAKeyPair_KeyMismatch_Fails(t *testing.T) {
	keysDir := t.TempDir()

	// 生成密钥对 A 与 B
	pairA, err := generateTAAKeyPair()
	if err != nil {
		t.Fatalf("generate pair A: %v", err)
	}
	pairB, err := generateTAAKeyPair()
	if err != nil {
		t.Fatalf("generate pair B: %v", err)
	}

	privPEM, err := teecrypto.MarshalSM2PrivateKeyPEM(pairA.PrivateKey)
	if err != nil {
		t.Fatalf("marshal pair A private key: %v", err)
	}

	// 故意组合 Pair A 私钥与 Pair B 公钥
	privPath := filepath.Join(keysDir, defaultSM2PrivateKeyFile)
	pubPath := filepath.Join(keysDir, defaultSM2PublicKeyFile)
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatalf("write pair A private key: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte(pairB.PublicKeyPEM), 0o644); err != nil {
		t.Fatalf("write pair B public key: %v", err)
	}

	_, _, err = loadOrGenerateTAAKeyPair(keysDir)
	if err == nil {
		t.Fatalf("expected error for mismatched key pair, got nil")
	}
	if !strings.Contains(err.Error(), "key mismatch") {
		t.Fatalf("expected 'key mismatch' error, got: %v", err)
	}
}

func TestPrepareAttestationReport(t *testing.T) {
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	t.Run("fallback on non-TEE environment writes empty report and returns false", func(t *testing.T) {
		tempDir := t.TempDir()
		if err := os.Chdir(tempDir); err != nil {
			t.Fatalf("chdir: %v", err)
		}
		defer func() { _ = os.Chdir(origDir) }()

		ctx := context.Background()
		userData := make([]byte, 64)

		passed, err := prepareAttestationReport(ctx, userData, "", "")
		if err != nil {
			t.Fatalf("prepareAttestationReport() error = %v, want nil", err)
		}
		if passed {
			t.Fatal("expected passed = false on fallback")
		}

		// Ensure empty attestation report file was written
		data, err := os.ReadFile(fixedAttestationFile)
		if err != nil {
			t.Fatalf("failed to read %s: %v", fixedAttestationFile, err)
		}
		if len(data) != 0 {
			t.Fatalf("expected empty report file, got %d bytes", len(data))
		}
	})

	t.Run("returns false when report is empty", func(t *testing.T) {
		tempDir := t.TempDir()
		if err := os.Chdir(tempDir); err != nil {
			t.Fatalf("chdir: %v", err)
		}
		defer func() { _ = os.Chdir(origDir) }()

		ctx := context.Background()
		userData := make([]byte, 64)

		// Pre-create empty report file
		if err := os.WriteFile(fixedAttestationFile, nil, 0o600); err != nil {
			t.Fatalf("write empty report: %v", err)
		}

		passed, err := prepareAttestationReport(ctx, userData, "some/hrk.cert", "some/hsk.cert")
		if err != nil {
			t.Fatalf("prepareAttestationReport() error = %v, want nil", err)
		}
		if passed {
			t.Fatal("expected passed = false for empty report")
		}
	})

	t.Run("returns false when self-verification fails with nonexistent certs", func(t *testing.T) {
		tempDir := t.TempDir()
		if err := os.Chdir(tempDir); err != nil {
			t.Fatalf("chdir: %v", err)
		}
		defer func() { _ = os.Chdir(origDir) }()

		restore := attestation.SetReportFetcherForTest(func(ctx context.Context, devicePath string, userData, nonce []byte) ([]byte, error) {
			return make([]byte, attestation.ReportSize), nil
		})
		defer restore()

		ctx := context.Background()
		userData := make([]byte, 64)

		// With mock report generated, self-verification fails cleanly because certs are missing
		passed, err := prepareAttestationReport(ctx, userData, "/nonexistent/hrk.cert", "/nonexistent/hsk.cert")
		if err != nil {
			t.Fatalf("prepareAttestationReport() error = %v, want nil", err)
		}
		if passed {
			t.Fatal("expected passed = false when cert verification fails")
		}
	})

	t.Run("write failure on non-writable directory returns error", func(t *testing.T) {
		tempDir := t.TempDir()
		// Create a directory named fixedAttestationFile so os.WriteFile fails
		if err := os.Mkdir(filepath.Join(tempDir, fixedAttestationFile), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Chdir(tempDir); err != nil {
			t.Fatalf("chdir: %v", err)
		}
		defer func() { _ = os.Chdir(origDir) }()

		ctx := context.Background()
		userData := make([]byte, 64)

		passed, err := prepareAttestationReport(ctx, userData, "", "")
		if err == nil {
			t.Fatal("expected error when writing empty attestation report fails")
		}
		if passed {
			t.Fatal("expected passed = false on write failure")
		}
		if !strings.Contains(err.Error(), "write empty attestation report") {
			t.Fatalf("error = %v, want write empty attestation report error", err)
		}
	})
}
