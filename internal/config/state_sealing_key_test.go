package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadStartupConfigReadsStateSealingKeySource(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{"storage":{"stateSealingKeySource":"csv-hw"}}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.StateSealingKeySource != StateSealingKeySourceCSVHW {
		t.Fatalf("StateSealingKeySource = %q, want %q", cfg.StateSealingKeySource, StateSealingKeySourceCSVHW)
	}
}

func TestLoadStartupConfigNormalizesStateSealingKeySource(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{"storage":{"stateSealingKeySource":"  CSV-HW  "}}`)

	cfg, err := LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("LoadStartupConfig() error = %v", err)
	}
	if cfg.StateSealingKeySource != StateSealingKeySourceCSVHW {
		t.Fatalf("StateSealingKeySource = %q, want %q", cfg.StateSealingKeySource, StateSealingKeySourceCSVHW)
	}
}

func TestLoadStartupConfigRejectsUnknownStateSealingKeySource(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{"storage":{"stateSealingKeySource":"hsm"}}`)

	if _, err := LoadStartupConfig(path); err == nil {
		t.Fatal("expected an unknown stateSealingKeySource to be rejected")
	} else if !strings.Contains(err.Error(), "stateSealingKeySource") {
		t.Fatalf("error does not name the setting: %v", err)
	}
}

func TestLoadStartupConfigRejectsCSVHWOnFHE(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writeTestConfig(t, path, `{"server":{"type":"fhe"},"storage":{"stateSealingKeySource":"csv-hw"}}`)

	if _, err := LoadStartupConfig(path); err == nil {
		t.Fatal("expected csv-hw on an fhe instance to be rejected")
	} else if !strings.Contains(err.Error(), "stateSealingKeySource") {
		t.Fatalf("error does not name the setting: %v", err)
	}
}

func TestShippedConfigsPinStateSealingKeySource(t *testing.T) {
	cases := []struct {
		relPath string
		want    string
	}{
		{"../../configs/taa-production.json", StateSealingKeySourceCSVHW},
		{"../../configs/taa-initrd.json", StateSealingKeySourceCSVHW},
		{"../../configs/taa-docker.json", StateSealingKeySourceSM2},
		{"../../configs/taa-fhe.json", StateSealingKeySourceSM2},
	}

	for _, tc := range cases {
		t.Run(filepath.Base(tc.relPath), func(t *testing.T) {
			raw, err := os.ReadFile(tc.relPath)
			if err != nil {
				t.Fatalf("read %s: %v", tc.relPath, err)
			}
			var fileCfg startupConfigFile
			if err := json.Unmarshal(raw, &fileCfg); err != nil {
				t.Fatalf("unmarshal %s: %v", tc.relPath, err)
			}
			if fileCfg.Storage.StateSealingKeySource != tc.want {
				t.Fatalf("%s: stateSealingKeySource = %q, want %q",
					tc.relPath, fileCfg.Storage.StateSealingKeySource, tc.want)
			}
		})
	}
}
