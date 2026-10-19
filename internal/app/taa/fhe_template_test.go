package taa

import (
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
	cfg := loadShippedFHEConfig(t)

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

// fheStateDir is the directory deploy-fhe.sh binds for TAA's own state; the
// template's storage.keys points at the keys directory inside it.
//
// Both paths in that sentence are literals here because nothing else in the template
// names them. The state directory is HOST_TAA_STATE_DIR in deploy-fhe.sh, and the
// default of that variable is the same literal. The two have to agree, because the
// template is usable on its own - the test above loads it without rendering anything
// into it - and an instance started from a template naming a directory the deployment
// does not bind writes the SM2 key pair and state.sealed into its own writable layer,
// for the next container recreation to take. Writing the literal here is what turns a
// divergence into a failing test rather than a deployment.
const fheStateDir = "/opt/taa-state"

// TestShippedFHEConfigKeepsStateOnTheBinds pins where the fhe template's three
// stateful paths point.
//
// deploy-fhe.sh creates the TAA container with binds and recreates it whenever
// the image or a bind changes. Anything outside a bind lives in the container's
// writable layer and is gone after such a recreate. For the eval key cache that means
// re-downloading 3.1 GiB per user on every deploy, against a cache the design says is
// never evicted; for the result directory it means the finished task's result and
// import-index.json are gone, and import-index.json is the record export resolves a
// result through, so every completed task answers 404 from then on; for the keys
// directory it means the SM2 key pair and the sealed instance state are gone, and
// ModelChecksum is sealed state, so the instance forgets it ever imported a model and
// refuses every data import as "no model imported yet" - while the model package
// itself is still sitting on the bind.
//
// Two paths sit on the shared data bind, whose container path is
// FHE_CONTAINER_DATA_DIR and is also fhe.dataDir. The third is on a bind of its
// own, and that is the point of it: FHE_CONTAINER_DATA_DIR is the tree the FHE
// stack reads, so TAA's SM2 private key under it would be readable from inside
// the FHE containers.
//
// The assertions are about the template as shipped, whose fhe.dataDir is /data -
// the default FHE_CONTAINER_DATA_DIR. deploy-fhe.sh renders fhe.dataDir,
// fhe.keyCacheDir and storage.result from FHE_CONTAINER_DATA_DIR and
// storage.keys from HOST_TAA_STATE_DIR, so a deployment that overrides either
// gets the paths moved with it rather than silently landing back inside the
// container.
func TestShippedFHEConfigKeepsStateOnTheBinds(t *testing.T) {
	cfg := loadShippedFHEConfig(t)
	if cfg.FHE == nil {
		t.Fatal("the shipped fhe template carries no fhe section")
	}

	bind := strings.TrimSuffix(cfg.FHE.DataDir, "/")
	for _, p := range []struct{ name, path string }{
		{"fhe.keyCacheDir", cfg.FHE.KeyCacheDir},
		{"storage.result", cfg.ResultDir},
	} {
		if !strings.HasPrefix(p.path, bind+"/") {
			t.Errorf("%s is %q, outside the data bind %q: container recreation (which deploy-fhe.sh does whenever the image or a bind changes) would destroy it",
				p.name, p.path, bind)
		}
	}

	// Both halves of the exception are worth pinning, and neither one alone says much.
	// "Not on the data bind" is satisfied by the writable layer too, and "persisted
	// somewhere" is satisfied by the tree the FHE stack reads. What the template can
	// decide is that the path is the one the deployment binds; that the deployment
	// then mounts it, and mounts nothing else there, is shell the Go side cannot see.
	if want := fheStateDir + "/keys"; cfg.KeysDir != want {
		t.Errorf("storage.keys is %q, want %q - the path deploy-fhe.sh renders into the state bind it mounts for it; a template naming anything else leaves the SM2 key pair and state.sealed in the container's writable layer",
			cfg.KeysDir, want)
	}
	if strings.HasPrefix(cfg.KeysDir, bind+"/") {
		t.Errorf("storage.keys is %q, inside the data bind %q that the FHE stack mounts as /data: the SM2 private key and state.sealed would be readable from the FHE containers",
			cfg.KeysDir, bind)
	}
}

// loadShippedFHEConfig loads the shipped template exactly as it is.
func loadShippedFHEConfig(t *testing.T) config.StartupConfig {
	t.Helper()

	cfg, err := config.LoadStartupConfig(shippedFHEConfigPath)
	if err != nil {
		t.Fatalf("the shipped fhe template does not load: %v", err)
	}
	return cfg
}
