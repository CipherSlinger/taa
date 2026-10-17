package config

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "taa.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

const fheConfigBody = `{
  "server": { "addr": ":6001", "type": "fhe" },
  "platform": { "addr": "http://127.0.0.1:59999" },
  "fhe": {
    "endpoint": "http://127.0.0.1:58996",
    "dataDir": "/opt/fhe-data",
    "keyCacheDir": "/root/taa/fhe-keys",
    "callbackBaseUrl": "http://172.16.10.130:6001",
    "callbackToken": "shared-token",
    "maxEvalKeyBytes": 6442450944,
    "pollIntervalMs": 5000,
    "requestTimeoutMs": 30000,
    "taskTimeoutMs": 1800000,
    "activateModelOnImport": true
  }
}`

func TestServerTypeDefaultsToTee(t *testing.T) {
	p := writeConfig(t, `{"server": {"addr": ":6001"}}`)
	cfg, err := LoadStartupConfig(p)
	if err != nil {
		t.Fatalf("LoadStartupConfig: %v", err)
	}
	if cfg.ServerType != ServerTypeTEE {
		t.Errorf("ServerType = %q, want %q", cfg.ServerType, ServerTypeTEE)
	}
	if cfg.FHE != nil {
		t.Errorf("FHE = %+v, want nil on a tee instance", cfg.FHE)
	}
}

func TestServerTypeRejectsUnknownValue(t *testing.T) {
	p := writeConfig(t, `{"server": {"addr": ":6001", "type": "gpu"}}`)
	_, err := LoadStartupConfig(p)
	if err == nil {
		t.Fatal("unknown server.type accepted, want error")
	}
	if !strings.Contains(err.Error(), "server.type") {
		t.Errorf("error %q does not name server.type", err)
	}
	if !strings.Contains(err.Error(), "tee") || !strings.Contains(err.Error(), "fhe") {
		t.Errorf("error %q does not list the accepted values", err)
	}
}

func TestFHESectionIsParsedWhenTypeIsFHE(t *testing.T) {
	p := writeConfig(t, fheConfigBody)
	cfg, err := LoadStartupConfig(p)
	if err != nil {
		t.Fatalf("LoadStartupConfig: %v", err)
	}
	if cfg.ServerType != ServerTypeFHE {
		t.Fatalf("ServerType = %q, want %q", cfg.ServerType, ServerTypeFHE)
	}
	if cfg.FHE == nil {
		t.Fatal("FHE = nil, want a parsed section")
	}
	if cfg.FHE.Endpoint != "http://127.0.0.1:58996" {
		t.Errorf("Endpoint = %q", cfg.FHE.Endpoint)
	}
	if cfg.FHE.DataDir != "/opt/fhe-data" {
		t.Errorf("DataDir = %q", cfg.FHE.DataDir)
	}
	if cfg.FHE.KeyCacheDir != "/root/taa/fhe-keys" {
		t.Errorf("KeyCacheDir = %q", cfg.FHE.KeyCacheDir)
	}
	if cfg.FHE.CallbackToken != "shared-token" {
		t.Errorf("CallbackToken = %q", cfg.FHE.CallbackToken)
	}
	if cfg.FHE.MaxEvalKeyBytes != 6442450944 {
		t.Errorf("MaxEvalKeyBytes = %d", cfg.FHE.MaxEvalKeyBytes)
	}
	if cfg.FHE.PollIntervalMs != 5000 || cfg.FHE.RequestTimeoutMs != 30000 || cfg.FHE.TaskTimeoutMs != 1800000 {
		t.Errorf("timeouts = %d/%d/%d", cfg.FHE.PollIntervalMs, cfg.FHE.RequestTimeoutMs, cfg.FHE.TaskTimeoutMs)
	}
	if cfg.FHE.ActivateModelOnImport == nil || !*cfg.FHE.ActivateModelOnImport {
		t.Error("ActivateModelOnImport = false, want true")
	}
}

func TestFHEConfigDefaultsAreFilled(t *testing.T) {
	p := writeConfig(t, `{
	  "server": {"type": "fhe"},
	  "fhe": {
	    "endpoint": "http://127.0.0.1:58996",
	    "dataDir": "/opt/fhe-data",
	    "keyCacheDir": "/root/taa/fhe-keys",
	    "callbackBaseUrl": "http://172.16.10.130:6001",
	    "callbackToken": "t"
	  }}`)
	cfg, err := LoadStartupConfig(p)
	if err != nil {
		t.Fatalf("LoadStartupConfig: %v", err)
	}
	if cfg.FHE.MaxEvalKeyBytes != DefaultFHEMaxEvalKeyBytes {
		t.Errorf("MaxEvalKeyBytes = %d, want the default %d", cfg.FHE.MaxEvalKeyBytes, DefaultFHEMaxEvalKeyBytes)
	}
	if cfg.FHE.PollIntervalMs != DefaultFHEPollIntervalMs {
		t.Errorf("PollIntervalMs = %d", cfg.FHE.PollIntervalMs)
	}
	if cfg.FHE.RequestTimeoutMs != DefaultFHERequestTimeoutMs {
		t.Errorf("RequestTimeoutMs = %d", cfg.FHE.RequestTimeoutMs)
	}
	if cfg.FHE.TaskTimeoutMs != DefaultFHETaskTimeoutMs {
		t.Errorf("TaskTimeoutMs = %d", cfg.FHE.TaskTimeoutMs)
	}
	if cfg.FHE.ActivateModelOnImport == nil || !*cfg.FHE.ActivateModelOnImport {
		t.Error("ActivateModelOnImport must default to true")
	}
}

func TestFHEConfigRejectsMissingRequiredFields(t *testing.T) {
	base := map[string]string{
		"endpoint":        `"http://127.0.0.1:58996"`,
		"dataDir":         `"/opt/fhe-data"`,
		"keyCacheDir":     `"/root/taa/fhe-keys"`,
		"callbackBaseUrl": `"http://172.16.10.130:6001"`,
		"callbackToken":   `"token"`,
	}
	for missing := range base {
		var b strings.Builder
		b.WriteString(`{"server":{"type":"fhe"},"fhe":{`)
		first := true
		for k, v := range base {
			if k == missing {
				continue
			}
			if !first {
				b.WriteString(",")
			}
			first = false
			b.WriteString(`"` + k + `":` + v)
		}
		// An explicitly empty value must be rejected the same way as an absent one.
		if !first {
			b.WriteString(",")
		}
		b.WriteString(`"` + missing + `":""}}`)

		if _, err := LoadStartupConfig(writeConfig(t, b.String())); err == nil {
			t.Errorf("missing/empty %s accepted, want error", missing)
		} else if !strings.Contains(err.Error(), "fhe."+missing) {
			t.Errorf("missing %s: error %q does not name the field", missing, err)
		}
	}
}

func TestFHEConfigRequiredWhenTypeIsFHE(t *testing.T) {
	if _, err := LoadStartupConfig(writeConfig(t, `{"server":{"type":"fhe"}}`)); err == nil {
		t.Fatal("type=fhe with no fhe section accepted, want error")
	}
}

func TestFHESectionIsWarnedAndIgnoredWhenTypeIsTEE(t *testing.T) {
	var logged bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(prev)

	body := `{"server":{"type":"tee"},"fhe":{"endpoint":"http://127.0.0.1:58996","dataDir":"/opt/fhe-data"}}`
	cfg, err := LoadStartupConfig(writeConfig(t, body))
	if err != nil {
		t.Fatalf("LoadStartupConfig: %v", err)
	}
	if cfg.FHE != nil {
		t.Errorf("FHE = %+v, want nil: the section must be ignored on a tee instance", cfg.FHE)
	}
	if !strings.Contains(logged.String(), "WARNING:") || !strings.Contains(logged.String(), "fhe section") {
		t.Errorf("log output %q does not warn about the ignored fhe section", logged.String())
	}
}

func TestFHEConfigRejectsBadEndpoint(t *testing.T) {
	for _, bad := range []string{`"127.0.0.1:58996"`, `"ftp://host"`, `"://"`, `"http://:1"`, `"not a url at all"`} {
		body := `{"server":{"type":"fhe"},"fhe":{
		  "endpoint":` + bad + `,"dataDir":"/d","keyCacheDir":"/k",
		  "callbackBaseUrl":"http://t","callbackToken":"x"}}`
		if _, err := LoadStartupConfig(writeConfig(t, body)); err == nil {
			t.Errorf("endpoint %s accepted, want error", bad)
		} else if !strings.Contains(err.Error(), "fhe.endpoint") {
			t.Errorf("endpoint %s: error %q does not name the field", bad, err)
		}
	}
}

// callbackBaseUrl is the other URL-shaped field, and it gets the same shape
// check as endpoint: a value with no scheme, an unusable scheme, or an empty
// host is rejected at startup rather than stored for the task runner to fail on.
func TestFHEConfigRejectsBadCallbackBaseURL(t *testing.T) {
	for _, bad := range []string{`"172.16.10.130:6001"`, `"ftp://host"`, `"http://:1"`, `"not a url at all"`, `"javascript:1"`, `"://"`} {
		body := `{"server":{"type":"fhe"},"fhe":{
		  "endpoint":"http://h:1","dataDir":"/d","keyCacheDir":"/k",
		  "callbackBaseUrl":` + bad + `,"callbackToken":"x"}}`
		if _, err := LoadStartupConfig(writeConfig(t, body)); err == nil {
			t.Errorf("callbackBaseUrl %s accepted, want error", bad)
		} else if !strings.Contains(err.Error(), "fhe.callbackBaseUrl") {
			t.Errorf("callbackBaseUrl %s: error %q does not name the field", bad, err)
		}
	}
}

// zeroBoundsBody carries a zero for every bounded field. The loader's convention
// is that zero means "unset" and takes the default, so none of these is an
// error; the non-positive check only ever fires for a negative value.
func zeroBoundsBody() string {
	return `{"server":{"type":"fhe"},"fhe":{
	  "endpoint":"http://h:1","dataDir":"/d","keyCacheDir":"/k",
	  "callbackBaseUrl":"http://t","callbackToken":"x",
	  "maxEvalKeyBytes":0,"pollIntervalMs":0,"requestTimeoutMs":0,"taskTimeoutMs":0}}`
}

func TestFHEConfigZeroBoundsTakeDefaults(t *testing.T) {
	cfg, err := LoadStartupConfig(writeConfig(t, zeroBoundsBody()))
	if err != nil {
		t.Fatalf("LoadStartupConfig: %v", err)
	}
	if cfg.FHE.MaxEvalKeyBytes != DefaultFHEMaxEvalKeyBytes {
		t.Errorf("MaxEvalKeyBytes = %d, want the default %d", cfg.FHE.MaxEvalKeyBytes, DefaultFHEMaxEvalKeyBytes)
	}
	if cfg.FHE.PollIntervalMs != DefaultFHEPollIntervalMs {
		t.Errorf("PollIntervalMs = %d, want the default %d", cfg.FHE.PollIntervalMs, DefaultFHEPollIntervalMs)
	}
	if cfg.FHE.RequestTimeoutMs != DefaultFHERequestTimeoutMs {
		t.Errorf("RequestTimeoutMs = %d, want the default %d", cfg.FHE.RequestTimeoutMs, DefaultFHERequestTimeoutMs)
	}
	if cfg.FHE.TaskTimeoutMs != DefaultFHETaskTimeoutMs {
		t.Errorf("TaskTimeoutMs = %d, want the default %d", cfg.FHE.TaskTimeoutMs, DefaultFHETaskTimeoutMs)
	}
}

// A negative bound is rejected even though zero is not: zero is the unset
// sentinel the loader fills in, while a negative one can only come from a
// deliberate (and wrong) edit, so it is reported instead of quietly defaulted.
func TestFHEConfigRejectsNonPositiveBounds(t *testing.T) {
	for _, tc := range []struct {
		field string
		value string
	}{
		{"maxEvalKeyBytes", "-1"},
		{"pollIntervalMs", "-1"},
		{"requestTimeoutMs", "-5000"},
		{"taskTimeoutMs", "-1"},
	} {
		body := `{"server":{"type":"fhe"},"fhe":{
		  "endpoint":"http://h:1","dataDir":"/d","keyCacheDir":"/k",
		  "callbackBaseUrl":"http://t","callbackToken":"x","` + tc.field + `":` + tc.value + `}}`
		if _, err := LoadStartupConfig(writeConfig(t, body)); err == nil {
			t.Errorf("negative %s accepted, want error", tc.field)
		} else if !strings.Contains(err.Error(), "fhe."+tc.field) {
			t.Errorf("negative %s: error %q does not name the field", tc.field, err)
		}
	}
}

// ActivateModelOnImport is a pointer so that "absent" and "explicitly false"
// stay distinct: the field defaults to true, and an absent key read as false
// would turn a missing setting into a deliberate opt-out. This pins all three
// states, including that an explicit null is treated as absent.
func TestFHEActivateModelOnImportDistinguishesFalseFromAbsent(t *testing.T) {
	body := func(field string) string {
		return `{"server":{"type":"fhe"},"fhe":{
		  "endpoint":"http://h:1","dataDir":"/d","keyCacheDir":"/k",
		  "callbackBaseUrl":"http://t","callbackToken":"x"` + field + `}}`
	}
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{"explicit true stays true", `,"activateModelOnImport":true`, true},
		{"explicit false stays false", `,"activateModelOnImport":false`, false},
		{"explicit null defaults to true", `,"activateModelOnImport":null`, true},
		{"absent defaults to true", ``, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadStartupConfig(writeConfig(t, body(tc.raw)))
			if err != nil {
				t.Fatalf("LoadStartupConfig: %v", err)
			}
			if cfg.FHE.ActivateModelOnImport == nil {
				t.Fatal("ActivateModelOnImport = nil, want it resolved")
			}
			if got := *cfg.FHE.ActivateModelOnImport; got != tc.want {
				t.Errorf("ActivateModelOnImport = %v, want %v", got, tc.want)
			}
		})
	}
}

// The "auto" sentinel is not a URL, so it must be exempt from URL validation at
// load time; the address is resolved when the FHE runner is built, which happens
// after the instance is already inside its own network namespace.
func TestFHECallbackBaseURLAcceptsAutoSentinel(t *testing.T) {
	body := strings.Replace(fheConfigBody, `"callbackBaseUrl": "http://172.16.10.130:6001"`,
		`"callbackBaseUrl": "auto"`, 1)
	cfg, err := LoadStartupConfig(writeConfig(t, body))
	if err != nil {
		t.Fatalf("LoadStartupConfig with callbackBaseUrl=auto: %v", err)
	}
	if !IsFHECallbackBaseURLAuto(cfg.FHE.CallbackBaseURL) {
		t.Errorf("CallbackBaseURL = %q, want the auto sentinel", cfg.FHE.CallbackBaseURL)
	}
}

func TestResolveFHECallbackBaseURLKeepsLiteralValue(t *testing.T) {
	got, err := ResolveFHECallbackBaseURL("  http://172.16.10.178:6001  ", ":6001")
	if err != nil {
		t.Fatalf("ResolveFHECallbackBaseURL: %v", err)
	}
	if want := "http://172.16.10.178:6001"; got != want {
		t.Errorf("ResolveFHECallbackBaseURL = %q, want %q", got, want)
	}
}

// A literal value is never re-derived, even when server.addr is malformed: the
// operator named the address, so that value is what the FHE service is told.
func TestResolveFHECallbackBaseURLLiteralIgnoresListenAddr(t *testing.T) {
	if _, err := ResolveFHECallbackBaseURL("http://172.16.10.178:6001", "no-port"); err != nil {
		t.Errorf("ResolveFHECallbackBaseURL(literal, bad addr) error = %v, want nil", err)
	}
}

func TestResolveFHECallbackBaseURLAutoRequiresListenPort(t *testing.T) {
	_, err := ResolveFHECallbackBaseURL(FHECallbackBaseURLAuto, "no-port")
	if err == nil {
		t.Fatal("auto with a server.addr that has no port was accepted")
	}
	if !strings.Contains(err.Error(), "server.addr") {
		t.Errorf("error %q does not name server.addr", err)
	}
}

func TestListenAddrPort(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want string
	}{
		{":6001", "6001"},
		{"0.0.0.0:6001", "6001"},
		{"[::]:6001", "6001"},
	} {
		got, err := listenAddrPort(tc.addr)
		if err != nil {
			t.Errorf("listenAddrPort(%q) error = %v", tc.addr, err)
			continue
		}
		if got != tc.want {
			t.Errorf("listenAddrPort(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
	for _, bad := range []string{"", "6001", "127.0.0.1"} {
		if _, err := listenAddrPort(bad); err == nil {
			t.Errorf("listenAddrPort(%q) accepted, want error", bad)
		}
	}
}

// deriveSelfIPv4 is the `hostname -i` equivalent. The host name is tried
// first; only when it yields nothing usable does the interface list count.
// Loopback and link-local addresses are never returned, because a callback URL
// built from one can only be reached from inside the same namespace.
func TestDeriveSelfIPv4(t *testing.T) {
	lookup := func(addrs []string) func(string) ([]string, error) {
		return func(string) ([]string, error) { return addrs, nil }
	}
	ifaces := func(addrs []string) func() ([]net.Addr, error) {
		return func() ([]net.Addr, error) {
			out := make([]net.Addr, 0, len(addrs))
			for _, raw := range addrs {
				ip := net.ParseIP(raw)
				out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
			}
			return out, nil
		}
	}
	failingLookup := func(string) ([]string, error) { return nil, fmt.Errorf("no such host") }

	for _, tc := range []struct {
		name     string
		hostname string
		lookup   func(string) ([]string, error)
		ifaces   func() ([]net.Addr, error)
		want     string
		wantErr  bool
	}{
		{
			name:     "host name resolves to the pod IP",
			hostname: "pod",
			lookup:   lookup([]string{"127.0.0.1", "10.244.0.89"}),
			ifaces:   ifaces([]string{"172.17.0.1"}),
			want:     "10.244.0.89",
		},
		{
			name:     "loopback-only host name falls back to the interfaces",
			hostname: "hygon-master",
			lookup:   lookup([]string{"127.0.0.1"}),
			ifaces:   ifaces([]string{"127.0.0.1", "172.16.10.178", "10.244.0.1"}),
			want:     "172.16.10.178",
		},
		{
			name:     "unresolvable host name falls back to the interfaces",
			hostname: "unknown",
			lookup:   failingLookup,
			ifaces:   ifaces([]string{"10.244.0.89"}),
			want:     "10.244.0.89",
		},
		{
			name:     "link-local addresses are skipped",
			hostname: "host",
			lookup:   lookup([]string{"169.254.10.1", "192.168.1.5"}),
			ifaces:   nil,
			want:     "192.168.1.5",
		},
		{
			name:     "nothing usable is an error",
			hostname: "host",
			lookup:   lookup([]string{"127.0.0.1"}),
			ifaces:   ifaces([]string{"127.0.0.1"}),
			wantErr:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deriveSelfIPv4(tc.hostname, tc.lookup, tc.ifaces)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("deriveSelfIPv4 = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("deriveSelfIPv4: %v", err)
			}
			if got != tc.want {
				t.Errorf("deriveSelfIPv4 = %q, want %q", got, tc.want)
			}
		})
	}
}
