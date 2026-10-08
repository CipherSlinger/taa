package controller

import "testing"

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
