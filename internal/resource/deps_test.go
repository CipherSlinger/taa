package resource

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateWheelhouseRequiresRequirementsAndWheel(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "requirements.txt"), "torchvision==0.28.0\n")
		writeFile(t, filepath.Join(dir, "torchvision-0.28.0-py3-none-any.whl"), "x")
		if err := ValidateWheelhouse(dir); err != nil {
			t.Fatalf("ValidateWheelhouse: %v", err)
		}
	})

	t.Run("missing requirements", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "a-1.0-py3-none-any.whl"), "x")
		if err := ValidateWheelhouse(dir); err == nil {
			t.Fatal("expected error when requirements.txt is absent")
		}
	})

	t.Run("missing wheel", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "requirements.txt"), "torchvision==0.28.0\n")
		if err := ValidateWheelhouse(dir); err == nil {
			t.Fatal("expected error when no .whl is present")
		}
	})

	// pip parses wheel filenames case-sensitively: a ".WHL" file is invisible to it, so an
	// archive whose only wheel is upper-cased must be rejected here, not at install time.
	t.Run("uppercase whl extension", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "requirements.txt"), "demo==1.0\n")
		writeFile(t, filepath.Join(dir, "DEMO-1.0-py3-none-any.WHL"), "x")
		err := ValidateWheelhouse(dir)
		if err == nil {
			t.Fatal("expected error for a .WHL file pip cannot see")
		}
		if !strings.Contains(err.Error(), "依赖包内未找到任何 .whl 文件") {
			t.Fatalf("error does not come from the .whl scan: %v", err)
		}
	})

	// A directory named requirements.txt satisfies a bare os.Stat; only the regular-file
	// guard rejects it, so the message must come from that guard.
	t.Run("requirements is a directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "requirements.txt"), 0o755); err != nil {
			t.Fatalf("mkdir requirements.txt: %v", err)
		}
		writeFile(t, filepath.Join(dir, "a-1.0-py3-none-any.whl"), "x")
		err := ValidateWheelhouse(dir)
		if err == nil {
			t.Fatal("expected error when requirements.txt is a directory")
		}
		if !strings.Contains(err.Error(), "不是普通文件") {
			t.Fatalf("error does not come from the regular-file guard: %v", err)
		}
	})

	// The three guard branches below are cheap to cover and are exactly the shape of thing
	// that silently loses its guard later: each one is a single line in the implementation,
	// so nothing else would fail if it were deleted. Each case therefore asserts the message
	// of its own guard -- "an error occurred" alone is satisfied by a downstream os.Stat
	// failing for an unrelated reason.
	t.Run("blank dir", func(t *testing.T) {
		err := ValidateWheelhouse("   ")
		if err == nil {
			t.Fatal("expected error for a blank wheelhouse dir")
		}
		if !strings.Contains(err.Error(), "is required") {
			t.Fatalf("error does not come from the blank-dir guard: %v", err)
		}
	})

	t.Run("missing dir", func(t *testing.T) {
		if err := ValidateWheelhouse(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
			t.Fatal("expected error for a nonexistent wheelhouse dir")
		}
	})

	t.Run("path is a file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "not-a-dir")
		writeFile(t, path, "x")
		err := ValidateWheelhouse(path)
		if err == nil {
			t.Fatal("expected error when the wheelhouse path is a file")
		}
		// The full guard message, not the bare fragment "not a directory": with the guard
		// removed, the downstream os.Stat on "<file>/requirements.txt" fails with ENOTDIR,
		// whose Linux text is also "not a directory" -- the fragment would still match.
		if !strings.Contains(err.Error(), "wheelhouse is not a directory") {
			t.Fatalf("error does not come from the not-a-directory guard: %v", err)
		}
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
