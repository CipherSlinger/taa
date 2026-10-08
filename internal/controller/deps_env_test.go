package controller

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApplyDepsEnvPreservesPlatformPythonPath(t *testing.T) {
	env := map[string]string{"PYTHONPATH": "/platform/lib", "CUDA_VISIBLE_DEVICES": "0"}

	got := applyDepsEnv(env, "/opt/taa/model-deps/abc")

	if got["PYTHONPATH"] != "/opt/taa/model-deps/abc:/platform/lib" {
		t.Fatalf("PYTHONPATH = %q, want deps dir prepended to the platform value", got["PYTHONPATH"])
	}
	if got["TAA_DEPS_DIR"] != "/opt/taa/model-deps/abc" {
		t.Fatalf("TAA_DEPS_DIR = %q", got["TAA_DEPS_DIR"])
	}
	if got["CUDA_VISIBLE_DEVICES"] != "0" {
		t.Fatal("unrelated env entries must be preserved")
	}
}

func TestApplyDepsEnvWithoutPlatformPythonPath(t *testing.T) {
	got := applyDepsEnv(map[string]string{}, "/opt/taa/model-deps/abc")

	if got["PYTHONPATH"] != "/opt/taa/model-deps/abc" {
		t.Fatalf("PYTHONPATH = %q, want the deps dir alone (no trailing colon)", got["PYTHONPATH"])
	}
}

func TestApplyDepsEnvNoopWhenNoDeps(t *testing.T) {
	env := map[string]string{"PYTHONPATH": "/platform/lib"}

	got := applyDepsEnv(env, "")

	if _, ok := got["TAA_DEPS_DIR"]; ok {
		t.Fatal("TAA_DEPS_DIR must not be set when no dependency package is active")
	}
	if got["PYTHONPATH"] != "/platform/lib" {
		t.Fatalf("PYTHONPATH = %q, must be untouched", got["PYTHONPATH"])
	}
}

func TestApplyDepsEnvDoesNotMutateInput(t *testing.T) {
	env := map[string]string{}

	_ = applyDepsEnv(env, "/deps/abc")

	if len(env) != 0 {
		t.Fatalf("input map was mutated: %#v", env)
	}
}

func TestTrainingEnvUnchangedWithoutDeps(t *testing.T) {
	state, _ := setupTestState(t)

	if got := state.currentDepsDir(); got != "" {
		t.Fatalf("currentDepsDir = %q before any deps import, want empty", got)
	}

	base := map[string]string{"OMP_NUM_THREADS": "8"}
	got := applyDepsEnv(base, state.currentDepsDir())

	if len(got) != len(base) {
		t.Fatalf("env grew from %d to %d entries without an imported dependency package", len(base), len(got))
	}
	for k, v := range base {
		if got[k] != v {
			t.Fatalf("env[%q] = %q, want %q", k, got[k], v)
		}
	}
}

// readSubprocessEnvDump parses an `env`(1) dump written by the training subprocess into a
// map. Each line is KEY=VALUE and a value may itself contain '=', so only the first
// separator counts.
func readSubprocessEnvDump(t *testing.T, path string) map[string]string {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read subprocess env dump %s: %v", path, err)
	}

	env := make(map[string]string)
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			continue
		}
		env[key] = value
	}
	if len(env) == 0 {
		t.Fatalf("subprocess env dump %s contained no KEY=VALUE lines", path)
	}
	return env
}

// unsetAmbientEnv removes key from the process environment for the duration of the test and
// restores it afterwards. The executor builds the child environment from os.Environ(), so an
// ambient value would otherwise leak into the dump and defeat the negative assertion.
func unsetAmbientEnv(t *testing.T, key string) {
	t.Helper()

	old, had := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unset ambient %s: %v", key, err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, old)
		}
	})
}

// runTrainingWithDeps drives the real data-import route (processImportedResource with
// isModel=false) so the env computed at the injection site is exercised end to end: it must
// survive parseRuntimeConfig -> applyDepsEnv -> executeTraining -> executor and reach the
// training subprocess. When importedHash is empty no dependency package is activated.
//
// It returns the environment the subprocess actually observed, plus the state, so callers
// can derive the expected deps directory from the fixture.
func runTrainingWithDeps(t *testing.T, importedHash string) (map[string]string, *TAAState) {
	t.Helper()

	state, _ := setupTestState(t)
	if err := os.MkdirAll(state.Security.GetDepsDir(), 0o755); err != nil {
		t.Fatalf("create deps dir: %v", err)
	}
	if importedHash != "" {
		state.saveDepsSuccess(importedHash, map[string]any{"size": int64(5), "algorithm": "sm3", "value": importedHash})
	}
	// A data import only reaches training when the model is already staged, the active task
	// is not a model import, and no training is running: the fixture satisfies the latter
	// two by construction.
	state.ModelImported = true
	state.RuntimeConfig = `{"commands":["env > envdump.txt"],"env":{"PYTHONPATH":"/platform/lib"}}`

	// A plaintext (unencrypted) archive keeps the route on the "already plaintext" branch,
	// so no decryption key material is needed.
	archive := buildTestArchive(t, map[string]string{"data.txt": "x"})
	req := importRequest{
		ResourceURL: "http://platform.test/data.tar.gz",
		RequestID:   "req-task9",
		TaskID:      "task-task9",
	}

	// The HTTP handler reserves the request/task slot on this same index store before
	// dispatching here. Reproduce that precondition, otherwise the data-import path aborts
	// at the index commit and never reaches training.
	store, err := state.importIndexStore()
	if err != nil {
		t.Fatalf("load import index store: %v", err)
	}
	if err := store.Reserve(req.RequestID, req.TaskID); err != nil {
		t.Fatalf("reserve import slot: %v", err)
	}

	state.processImportedResource(req, 1, false, archive)

	// The subprocess runs with cwd = ModelDir, so the redirect lands there.
	return readSubprocessEnvDump(t, filepath.Join(state.Security.ModelDir, "envdump.txt")), state
}

// TestTrainingSubprocessEnvCarriesDepsDir covers the training-injection clause: with an
// imported dependency package the training subprocess must see TAA_DEPS_DIR, and the
// PYTHONPATH supplied by the platform in runtimeConfig.env must be preserved by prepending
// the deps dir rather than replaced. Removing the applyDepsEnv call on the import path makes
// this fail.
func TestTrainingSubprocessEnvCarriesDepsDir(t *testing.T) {
	unsetAmbientEnv(t, "TAA_DEPS_DIR")

	got, state := runTrainingWithDeps(t, "cafebabe")

	wantDepsDir := filepath.Join(state.Security.GetDepsDir(), "cafebabe")
	if got["TAA_DEPS_DIR"] != wantDepsDir {
		t.Fatalf("subprocess TAA_DEPS_DIR = %q, want %q", got["TAA_DEPS_DIR"], wantDepsDir)
	}
	if want := wantDepsDir + ":/platform/lib"; got["PYTHONPATH"] != want {
		t.Fatalf("subprocess PYTHONPATH = %q, want %q (platform value preserved, not overwritten)", got["PYTHONPATH"], want)
	}
}

// TestTrainingSubprocessEnvHasNoDepsDirWithoutImport is the negative control: with no
// dependency package imported the subprocess environment must not gain TAA_DEPS_DIR and the
// platform PYTHONPATH must pass through untouched.
func TestTrainingSubprocessEnvHasNoDepsDirWithoutImport(t *testing.T) {
	unsetAmbientEnv(t, "TAA_DEPS_DIR")

	got, _ := runTrainingWithDeps(t, "")

	if v, ok := got["TAA_DEPS_DIR"]; ok {
		t.Fatalf("subprocess TAA_DEPS_DIR = %q, want the key absent when no dependency package is imported", v)
	}
	if got["PYTHONPATH"] != "/platform/lib" {
		t.Fatalf("subprocess PYTHONPATH = %q, want the untouched platform value", got["PYTHONPATH"])
	}
}
