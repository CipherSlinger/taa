package controller

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func waitForMirror(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func readOrEmpty(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

func TestLogMirrorCopiesOnlyNewBytes(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	srcProgress := filepath.Join(t.TempDir(), "progress.json")
	dstProgress := filepath.Join(t.TempDir(), "progress.json")
	warn := func(string, ...any) { t.Error("unexpected mirror warning") }

	mirror := startLogMirror(context.Background(), srcDir, dstDir, srcProgress, dstProgress, warn)
	if mirror == nil {
		t.Fatal("distinct paths must produce a mirror")
	}
	defer mirror.Stop()

	srcLog := filepath.Join(srcDir, "train.log")
	if err := os.WriteFile(srcLog, []byte("epoch 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitForMirror(t, "the first log line", func() bool {
		return readOrEmpty(filepath.Join(dstDir, "train.log")) == "epoch 1\n"
	})

	file, err := os.OpenFile(srcLog, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("epoch 2\n"); err != nil {
		t.Fatal(err)
	}
	file.Close()
	waitForMirror(t, "the appended line", func() bool {
		return readOrEmpty(filepath.Join(dstDir, "train.log")) == "epoch 1\nepoch 2\n"
	})
}

func TestLogMirrorSyncsOnStop(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	srcProgress := filepath.Join(t.TempDir(), "progress.json")
	dstProgress := filepath.Join(t.TempDir(), "progress.json")

	mirror := startLogMirror(context.Background(), srcDir, dstDir, srcProgress, dstProgress, nil)
	if mirror == nil {
		t.Fatal("distinct paths must produce a mirror")
	}
	// Write and stop before any tick can have run: the final sync is what has to
	// carry the last lines into the terminal training report.
	if err := os.WriteFile(filepath.Join(srcDir, "train.log"), []byte("last line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mirror.Stop()
	mirror.Stop() // idempotent: the normal path and the deferred one both call it

	if got := readOrEmpty(filepath.Join(dstDir, "train.log")); got != "last line\n" {
		t.Fatalf("after Stop the log is %q, want the final line", got)
	}
}

func TestLogMirrorReplacesProgressFile(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	srcProgress := filepath.Join(t.TempDir(), "progress.json")
	dstProgress := filepath.Join(t.TempDir(), "progress.json")

	mirror := startLogMirror(context.Background(), srcDir, dstDir, srcProgress, dstProgress, nil)
	defer mirror.Stop()

	if err := os.WriteFile(srcProgress, []byte(`{"percent":10}`), 0o644); err != nil {
		t.Fatal(err)
	}
	waitForMirror(t, "the first progress write", func() bool {
		return readOrEmpty(dstProgress) == `{"percent":10}`
	})

	if err := os.WriteFile(srcProgress, []byte(`{"percent":55}`), 0o644); err != nil {
		t.Fatal(err)
	}
	waitForMirror(t, "the second progress write", func() bool {
		return readOrEmpty(dstProgress) == `{"percent":55}`
	})

	if _, err := os.Stat(dstProgress + ".mirror-tmp"); !os.IsNotExist(err) {
		t.Fatal("the temporary progress file must not survive the rename")
	}
}

func TestLogMirrorIgnoresSymlinksInTheLogDir(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	srcProgress := filepath.Join(t.TempDir(), "progress.json")
	dstProgress := filepath.Join(t.TempDir(), "progress.json")
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("do not copy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(srcDir, "link.log")); err != nil {
		t.Fatal(err)
	}

	mirror := startLogMirror(context.Background(), srcDir, dstDir, srcProgress, dstProgress, nil)
	defer mirror.Stop()
	if err := os.WriteFile(filepath.Join(srcDir, "real.log"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitForMirror(t, "the real log", func() bool {
		return readOrEmpty(filepath.Join(dstDir, "real.log")) == "ok"
	})
	if _, err := os.Stat(filepath.Join(dstDir, "link.log")); !os.IsNotExist(err) {
		t.Fatal("a symlink in the log directory must not be followed")
	}
}

func TestLogMirrorIsNilWhenPathsMatch(t *testing.T) {
	// The local target writes directly into the watched paths; mirroring them
	// onto themselves would truncate the log.
	dir := t.TempDir()
	progress := filepath.Join(dir, "progress.json")
	if m := startLogMirror(context.Background(), dir, dir, progress, progress, nil); m != nil {
		m.Stop()
		t.Fatal("identical source and destination must not start a mirror")
	}
}

func TestLogMirrorWarnsOncePerDistinctFailure(t *testing.T) {
	// A source that is a file rather than a directory fails every round; the
	// platform channel must see one warning, not two per second.
	notADir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notADir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	warnings := 0
	dstDir := t.TempDir()
	srcProgress := filepath.Join(t.TempDir(), "progress.json")

	mirror := startLogMirror(context.Background(), notADir, dstDir, srcProgress, filepath.Join(dstDir, "p.json"),
		func(string, ...any) {
			mu.Lock()
			warnings++
			mu.Unlock()
		})
	defer mirror.Stop()

	time.Sleep(2*mirrorInterval + 200*time.Millisecond)
	mu.Lock()
	got := warnings
	mu.Unlock()
	if got != 1 {
		t.Fatalf("got %d warnings, want exactly 1 for one distinct failure", got)
	}
}
