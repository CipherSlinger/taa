package mock

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestInstanceDirNameIsStableAndSafe(t *testing.T) {
	if got := instanceDirName(""); got != "i-legacy" {
		t.Fatalf("instanceDirName(\"\") = %q, want i-legacy", got)
	}
	a := instanceDirName("../../etc/passwd")
	b := instanceDirName("../../etc/passwd")
	if a != b {
		t.Fatalf("instanceDirName is not deterministic: %q vs %q", a, b)
	}
	if len(a) != len("i-")+16 {
		t.Fatalf("instanceDirName length = %d, want 18", len(a))
	}
	if filepath.Base(a) != a {
		t.Fatalf("instanceDirName %q escapes its parent", a)
	}
	if a == instanceDirName("another-id") {
		t.Fatal("two different dockerIds share a directory name")
	}
}

func TestInstanceManagerScansExistingInstances(t *testing.T) {
	root := t.TempDir()
	mgr := newInstanceManager(root, Config{})
	b := mgr.getOrCreate("docker-a")
	b.setTarget("http://10.0.0.1:6001")

	reopened := newInstanceManager(root, Config{})
	got := reopened.lookup("docker-a")
	if got == nil {
		t.Fatal("docker-a was not scanned back from disk")
	}
	if got.target() != "http://10.0.0.1:6001" {
		t.Fatalf("target = %q, want http://10.0.0.1:6001", got.target())
	}
}

func TestInstanceManagerMigratesLegacyState(t *testing.T) {
	root := t.TempDir()
	legacy := registerState{
		Received:   true,
		Accepted:   true,
		DockerID:   "legacy-docker",
		ReceivedAt: "2026-01-01T00:00:00Z",
	}
	if err := saveJSONFile(filepath.Join(root, "register-state.json"), legacy); err != nil {
		t.Fatalf("write legacy register state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "reportRes-state.json"), []byte(`{"current":{"received":true},"history":[]}`), 0o644); err != nil {
		t.Fatalf("write legacy report state: %v", err)
	}

	mgr := newInstanceManager(root, Config{})
	b := mgr.lookup("legacy-docker")
	if b == nil {
		t.Fatal("legacy registration was not migrated")
	}
	if !b.register.get().Accepted {
		t.Fatal("migrated register state lost its accepted flag")
	}
	if !b.reportRes.get().Received {
		t.Fatal("migrated report state was not moved")
	}
	if _, err := os.Stat(filepath.Join(root, "register-state.json")); !os.IsNotExist(err) {
		t.Fatal("legacy register-state.json still exists in the root")
	}
	if _, err := os.Stat(filepath.Join(b.dir, "instance.json")); err != nil {
		t.Fatalf("instance.json was not written: %v", err)
	}
}

func TestInstanceManagerDoesNotMigrateOverExistingInstancesDir(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, instancesDirName, "i-existing"), 0o755); err != nil {
		t.Fatalf("create instances dir: %v", err)
	}
	if err := saveJSONFile(filepath.Join(root, "register-state.json"), registerState{DockerID: "stale"}); err != nil {
		t.Fatalf("write stale register state: %v", err)
	}

	newInstanceManager(root, Config{})
	if _, err := os.Stat(filepath.Join(root, "register-state.json")); err != nil {
		t.Fatal("the stale root file was moved even though instances/ already exists")
	}
}

func TestInstanceManagerDefaultPrefersAcceptedThenNewest(t *testing.T) {
	root := t.TempDir()
	mgr := newInstanceManager(root, Config{})

	a := mgr.getOrCreate("docker-a")
	a.register.set(registerState{Received: true, Accepted: true, ReceivedAt: "2026-01-01T00:00:00Z"})
	b := mgr.getOrCreate("docker-b")
	b.register.set(registerState{Received: true, Accepted: true, ReceivedAt: "2026-02-01T00:00:00Z"})
	c := mgr.getOrCreate("docker-c")
	c.register.set(registerState{Received: true, Accepted: false, ReceivedAt: "2026-03-01T00:00:00Z"})

	if got := mgr.defaultID(); got != "docker-b" {
		t.Fatalf("defaultID() = %q, want docker-b", got)
	}

	resolved, err := mgr.resolve(httptest.NewRequest("GET", "/api/register/status", nil))
	if err != nil {
		t.Fatalf("resolve without dockerId: %v", err)
	}
	if resolved.dockerID != "docker-b" {
		t.Fatalf("resolved instance = %q, want docker-b", resolved.dockerID)
	}
}

func TestInstanceManagerResolveRejectsUnknownDockerID(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{})
	req := httptest.NewRequest("GET", "/api/register/status?dockerId=missing", nil)
	if _, err := mgr.resolve(req); err != errInstanceNotFound {
		t.Fatalf("resolve(unknown) error = %v, want errInstanceNotFound", err)
	}
	if _, err := mgr.resolve(httptest.NewRequest("GET", "/api/register/status", nil)); err != errNoInstance {
		t.Fatalf("resolve(empty) error = %v, want errNoInstance", err)
	}
}

func TestInstanceForWriteNeverCreatesDirectoriesForUnknownIDs(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{})
	got := mgr.instanceForWrite("never-registered", false)
	if got.dockerID != "" {
		t.Fatalf("instanceForWrite created bundle for %q, want the legacy bundle", got.dockerID)
	}
	if mgr.lookup("never-registered") != nil {
		t.Fatal("instanceForWrite created a directory for an unknown dockerId")
	}

	created := mgr.instanceForWrite("registered", true)
	if created == nil || created.dockerID != "registered" {
		t.Fatal("instanceForWrite did not create the accepted instance")
	}
}
