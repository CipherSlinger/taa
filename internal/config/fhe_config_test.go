package config

import (
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
	body := `{"server":{"type":"tee"},"fhe":{"endpoint":"http://127.0.0.1:58996","dataDir":"/opt/fhe-data"}}`
	cfg, err := LoadStartupConfig(writeConfig(t, body))
	if err != nil {
		t.Fatalf("LoadStartupConfig: %v", err)
	}
	if cfg.FHE != nil {
		t.Errorf("FHE = %+v, want nil: the section must be ignored on a tee instance", cfg.FHE)
	}
}

func TestFHEConfigRejectsBadEndpoint(t *testing.T) {
	for _, bad := range []string{`"127.0.0.1:58996"`, `"ftp://host"`, `"://"`} {
		body := `{"server":{"type":"fhe"},"fhe":{
		  "endpoint":` + bad + `,"dataDir":"/d","keyCacheDir":"/k",
		  "callbackBaseUrl":"http://t","callbackToken":"x"}}`
		if _, err := LoadStartupConfig(writeConfig(t, body)); err == nil {
			t.Errorf("endpoint %s accepted, want error", bad)
		}
	}
}

func TestFHEConfigRejectsNonPositiveBounds(t *testing.T) {
	body := `{"server":{"type":"fhe"},"fhe":{
	  "endpoint":"http://h:1","dataDir":"/d","keyCacheDir":"/k",
	  "callbackBaseUrl":"http://t","callbackToken":"x","maxEvalKeyBytes":-1}}`
	if _, err := LoadStartupConfig(writeConfig(t, body)); err == nil {
		t.Error("negative maxEvalKeyBytes accepted, want error")
	}
}
