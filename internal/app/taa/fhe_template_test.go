package taa

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"taa/internal/codeaudit"
	"taa/internal/config"
)

// shippedFHEConfigPath is the template deploy-fhe.sh renders and starts.
const shippedFHEConfigPath = "../../../configs/taa-fhe.json"

// TestShippedFHEConfigStartsWithoutAnyFileOnDisk pins that the fhe template this
// repository ships can actually start the daemon.
//
// The startup path builds the security configuration unconditionally, and that
// resolves the code scan engine - which is where a selection meets the disk. The
// semgrep engine reads its rules from a path and refuses to construct without
// one, deliberately, so a bootstrap failure is a startup failure rather than a
// scan failure later. deploy-fhe.sh runs an image with an empty /opt and mounts
// only the shared data directory, so a template that selects semgrep cannot come
// up at all: the daemon dies in a restart loop before it ever reaches the FHE
// service. That is why the fhe template selects the engine that carries its rules
// in the binary, and this test is what keeps it that way.
func TestShippedFHEConfigStartsWithoutAnyFileOnDisk(t *testing.T) {
	raw, err := os.ReadFile(shippedFHEConfigPath)
	if err != nil {
		t.Fatalf("read the shipped fhe template: %v", err)
	}

	// The template ships callbackToken empty - it is a template, and the token
	// belongs to the deployment, which deploy-fhe.sh injects - and an empty token
	// is refused by design. Fill that one field and load everything else exactly as
	// shipped; nothing below rewrites another path, which is the point.
	const emptyToken = `"callbackToken": ""`
	if strings.Count(string(raw), emptyToken) != 1 {
		t.Fatalf("the shipped fhe template does not carry exactly one empty callbackToken; deploy-fhe.sh fills that field from the environment and this test relies on doing the same")
	}
	patched := strings.Replace(string(raw), emptyToken, `"callbackToken": "test-token"`, 1)
	path := filepath.Join(t.TempDir(), "taa-fhe.json")
	if err := os.WriteFile(path, []byte(patched), 0o600); err != nil {
		t.Fatalf("write the patched template: %v", err)
	}

	cfg, err := config.LoadStartupConfig(path)
	if err != nil {
		t.Fatalf("the shipped fhe template does not load: %v", err)
	}
	if cfg.ServerType != config.ServerTypeFHE {
		t.Fatalf("the shipped fhe template loads as server.type=%q", cfg.ServerType)
	}

	sec, err := buildSecurityConfig(cfg)
	if err != nil {
		t.Fatalf("the shipped fhe template produces no usable security config: %v", err)
	}
	if got := sec.Engine.Name(); got == codeaudit.EngineNameSemgrep {
		t.Errorf("the shipped fhe template selects the %s engine, which needs a rules file on disk and cannot construct without one", got)
	}

	// The engine is the only part of this path that reads the filesystem - the
	// directories the startup sequence uses are created, not read - so the
	// assertion that matters is that the engine needs nothing. Stating it as "the
	// template's own rules path happens to be missing here" would only hold on a
	// host where it is: point the rules path at a location that does not exist and
	// build again, which fails for a selection that needs a file there on any host.
	probe := cfg
	probe.CodeScan.RulesPath = filepath.Join(t.TempDir(), "no-such-rules")
	if _, err := buildSecurityConfig(probe); err != nil {
		t.Fatalf("the engine in the shipped fhe template needs a file on disk: %v", err)
	}
}
