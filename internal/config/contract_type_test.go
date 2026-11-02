package config

import (
	"strings"
	"testing"
)

func TestContractTypeSelectsRole(t *testing.T) {
	cases := []struct {
		value string
		want  string
	}{
		{"1", ServerTypeTEE},
		{"2", ServerTypeTEE},
		{"3", ServerTypeDataAnalysis},
		{"4", ServerTypeFHE},
		{" 3 ", ServerTypeDataAnalysis},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("CONTRACT_TYPE", tc.value)
			cfg := StartupConfig{ServerType: ServerTypeTEE}
			if err := applyServerType(&cfg, "data-anaylsis"); err != nil {
				t.Fatalf("applyServerType: %v", err)
			}
			if cfg.ServerType != tc.want {
				t.Fatalf("ServerType = %q, want %q", cfg.ServerType, tc.want)
			}
		})
	}
}

func TestContractTypePrecedence(t *testing.T) {
	// The environment wins over the file.
	t.Setenv("CONTRACT_TYPE", "3")
	cfg := StartupConfig{ServerType: ServerTypeTEE}
	if err := applyServerType(&cfg, "fhe"); err != nil {
		t.Fatalf("applyServerType: %v", err)
	}
	if cfg.ServerType != ServerTypeDataAnalysis {
		t.Fatalf("environment did not win over the file: ServerType = %q", cfg.ServerType)
	}

	// With the environment unset the file decides.
	t.Setenv("CONTRACT_TYPE", "")
	cfg = StartupConfig{ServerType: ServerTypeTEE}
	if err := applyServerType(&cfg, "fhe"); err != nil {
		t.Fatalf("applyServerType: %v", err)
	}
	if cfg.ServerType != ServerTypeFHE {
		t.Fatalf("file value was not applied: ServerType = %q", cfg.ServerType)
	}

	// With neither set the default is left alone.
	cfg = StartupConfig{ServerType: ServerTypeTEE}
	if err := applyServerType(&cfg, ""); err != nil {
		t.Fatalf("applyServerType: %v", err)
	}
	if cfg.ServerType != ServerTypeTEE {
		t.Fatalf("default was not kept: ServerType = %q", cfg.ServerType)
	}
}

func TestContractTypeRejectsUnknownValue(t *testing.T) {
	t.Setenv("CONTRACT_TYPE", "5")
	err := applyServerType(&StartupConfig{ServerType: ServerTypeTEE}, "")
	if err == nil {
		t.Fatal("unknown CONTRACT_TYPE was accepted")
	}
	if !strings.Contains(err.Error(), "CONTRACT_TYPE") {
		t.Errorf("error %q does not name CONTRACT_TYPE", err)
	}
}

// TestContractTypeOverridesTheFileEndToEnd pins the order inside
// LoadStartupConfig: the role has to be resolved before applyStartupConfigFile
// reads it, or an fhe file overridden to data analysis would still skip the
// audit and attestation blocks.
func TestContractTypeOverridesTheFileEndToEnd(t *testing.T) {
	t.Setenv("CONTRACT_TYPE", "3")
	cfg, err := LoadStartupConfig(writeConfig(t, fheConfigBody))
	if err != nil {
		t.Fatalf("LoadStartupConfig: %v", err)
	}
	if cfg.ServerType != ServerTypeDataAnalysis {
		t.Fatalf("ServerType = %q, want %q", cfg.ServerType, ServerTypeDataAnalysis)
	}
	if cfg.FHE != nil {
		t.Fatalf("FHE = %+v, want nil on a data-analysis instance", cfg.FHE)
	}
	if cfg.CodeScan.Engine != "semgrep" {
		t.Errorf("CodeScan.Engine = %q, want semgrep: the fhe-only engine override leaked into a data-analysis instance", cfg.CodeScan.Engine)
	}
}
