package mock

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
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

func TestInstanceManagerRecoversInterruptedMigration(t *testing.T) {
	root := t.TempDir()
	// Simulate a migration killed between moving the files and publishing the
	// staging directory: instances/ is absent and the moved files are in a
	// .instances-migrating-* directory.
	staging := filepath.Join(root, ".instances-migrating-crashed")
	stagedDir := filepath.Join(staging, instanceDirName("legacy-docker"))
	if err := os.MkdirAll(stagedDir, 0o755); err != nil {
		t.Fatalf("create staging dir: %v", err)
	}
	legacy := registerState{
		Received:   true,
		Accepted:   true,
		DockerID:   "legacy-docker",
		ReceivedAt: "2026-01-01T00:00:00Z",
	}
	if err := saveJSONFile(filepath.Join(stagedDir, "register-state.json"), legacy); err != nil {
		t.Fatalf("write staged register state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stagedDir, "reportRes-state.json"), []byte(`{"current":{"received":true},"history":[]}`), 0o644); err != nil {
		t.Fatalf("write staged report state: %v", err)
	}
	// One file had not been moved yet when the process died.
	if err := os.WriteFile(filepath.Join(root, "reportAudit-state.json"), []byte(`{"current":{"received":true},"history":[]}`), 0o644); err != nil {
		t.Fatalf("write root report state: %v", err)
	}

	mgr := newInstanceManager(root, Config{})
	b := mgr.lookup("legacy-docker")
	if b == nil {
		t.Fatal("the interrupted migration lost the registered instance")
	}
	if !b.register.get().Accepted {
		t.Fatal("recovered register state lost its accepted flag")
	}
	if !b.reportRes.get().Received {
		t.Fatal("recovered report state was not restored")
	}
	if !b.reportAudit.get().Received {
		t.Fatal("the file still in the root was not migrated")
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Fatal("the recovered staging directory still exists")
	}

	// A second construction is a no-op: the same state comes back and only the
	// one published instance directory exists.
	reopened := newInstanceManager(root, Config{})
	rb := reopened.lookup("legacy-docker")
	if rb == nil || !rb.register.get().Accepted {
		t.Fatal("a second start did not find the recovered instance")
	}
	entries, err := os.ReadDir(filepath.Join(root, instancesDirName))
	if err != nil {
		t.Fatalf("read instances dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("instances dir = %v, want only the recovered instance", entries)
	}
}

func TestInstanceManagerRecoversMigrationFromGlobMetaStateDir(t *testing.T) {
	// A state dir with glob metacharacters used to make filepath.Glob return
	// ErrBadPattern, skipping recovery entirely and reopening the crash window.
	root := filepath.Join(t.TempDir(), "state[1]")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("create state dir: %v", err)
	}
	staging := filepath.Join(root, ".instances-migrating-crashed")
	stagedDir := filepath.Join(staging, instanceDirName("legacy-docker"))
	if err := os.MkdirAll(stagedDir, 0o755); err != nil {
		t.Fatalf("create staging dir: %v", err)
	}
	if err := saveJSONFile(filepath.Join(stagedDir, "register-state.json"), registerState{
		Received:   true,
		Accepted:   true,
		DockerID:   "legacy-docker",
		ReceivedAt: "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatalf("write staged register state: %v", err)
	}

	mgr := newInstanceManager(root, Config{})
	b := mgr.lookup("legacy-docker")
	if b == nil {
		t.Fatal("recovery was skipped for a state dir containing glob metacharacters")
	}
	if !b.register.get().Accepted {
		t.Fatal("recovered register state lost its accepted flag")
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Fatal("the recovered staging directory still exists")
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

	if got := mgr.defaultBundle(); got == nil || got.dockerID != "docker-b" {
		t.Fatalf("defaultBundle() = %v, want docker-b", got)
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

func TestStaticTargetWinsWhileOnlyOneRealInstanceExists(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{TAATarget: "http://127.0.0.1:6001"})

	// A console probe before registration creates the legacy bundle.
	if _, err := mgr.resolveLenient(httptest.NewRequest("GET", "/api/taa-target", nil)); err != nil {
		t.Fatalf("resolveLenient: %v", err)
	}
	b := mgr.getOrCreate("docker-a")
	b.setTarget("http://10.244.0.7:6001")

	if id, target, err := mgr.targetFor(""); err != nil || id != "docker-a" || target != "http://127.0.0.1:6001" {
		t.Fatalf("targetFor = (%q, %q, %v), want (docker-a, http://127.0.0.1:6001, nil)", id, target, err)
	}

	mgr.getOrCreate("docker-b").setTarget("http://10.244.0.8:6001")
	if id, target, err := mgr.targetFor(""); err != nil || id != "docker-a" || target != "http://10.244.0.7:6001" {
		t.Fatalf("with two instances targetFor = (%q, %q, %v), want docker-a's derived target", id, target, err)
	}
}

func TestInstanceForWriteNeverCreatesDirectoriesForUnknownIDs(t *testing.T) {
	root := t.TempDir()
	mgr := newInstanceManager(root, Config{})
	got := mgr.instanceForWrite("never-registered")
	if got.dockerID != "" {
		t.Fatalf("instanceForWrite created bundle for %q, want the legacy bundle", got.dockerID)
	}
	if mgr.lookup("never-registered") != nil {
		t.Fatal("instanceForWrite created a directory for an unknown dockerId")
	}

	entries, err := os.ReadDir(filepath.Join(root, instancesDirName))
	if err != nil {
		t.Fatalf("read instances dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "i-legacy" {
		t.Fatalf("instances dir = %v, want only i-legacy", entries)
	}
	if _, err := os.Stat(filepath.Join(root, instancesDirName, instanceDirName("never-registered"))); !os.IsNotExist(err) {
		t.Fatal("a directory named after the unknown dockerId exists")
	}

	created := mgr.instanceForRegistration("registered", true)
	if created == nil || created.dockerID != "registered" {
		t.Fatal("instanceForRegistration did not create the accepted instance")
	}
	if mgr.lookup("registered") == nil {
		t.Fatal("instanceForRegistration did not publish the accepted instance")
	}

	rejected := mgr.instanceForRegistration("registered-2", false)
	if rejected.dockerID != "" {
		t.Fatalf("instanceForRegistration created bundle for %q, want the legacy bundle", rejected.dockerID)
	}
	if mgr.lookup("registered-2") != nil {
		t.Fatal("instanceForRegistration created a directory for a rejected registration")
	}
}

func TestMigrationLeavesLegacyFilesInPlaceWhenItFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	root := t.TempDir()
	if err := saveJSONFile(filepath.Join(root, "register-state.json"), registerState{DockerID: "legacy-docker"}); err != nil {
		t.Fatalf("write legacy register state: %v", err)
	}
	// A read-only root makes the staging directory impossible to create.
	if err := os.Chmod(root, 0o555); err != nil {
		t.Fatalf("make the state root read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })

	newInstanceManager(root, Config{})

	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatalf("restore permissions: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "register-state.json")); err != nil {
		t.Fatal("a failed migration moved the legacy file away")
	}
	if _, err := os.Stat(filepath.Join(root, instancesDirName)); !os.IsNotExist(err) {
		t.Fatal("a failed migration still created instances/")
	}
}

func TestConcurrentWritesShareOneLegacyBundle(t *testing.T) {
	root := t.TempDir()
	mgr := newInstanceManager(root, Config{})

	const workers = 16
	got := make([]*instanceStores, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i] = mgr.instanceForWrite(fmt.Sprintf("unknown-%d", i))
		}(i)
	}
	wg.Wait()

	for i, b := range got {
		if b != got[0] {
			t.Fatalf("worker %d got a different legacy bundle", i)
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, instancesDirName))
	if err != nil {
		t.Fatalf("read instances dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "i-legacy" {
		t.Fatalf("instances dir = %v, want only i-legacy", entries)
	}
}

func TestConcurrentGetOrCreateReturnsOneBundle(t *testing.T) {
	mgr := newInstanceManager(t.TempDir(), Config{})

	const workers = 16
	got := make([]*instanceStores, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i] = mgr.getOrCreate("docker-a")
		}(i)
	}
	wg.Wait()

	for i, b := range got {
		if b != got[0] {
			t.Fatalf("worker %d got a different bundle", i)
		}
	}
}
