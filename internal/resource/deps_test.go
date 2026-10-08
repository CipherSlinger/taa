package resource

import (
	"os"
	"path/filepath"
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

	// The three guard branches below are cheap to cover and are exactly the shape of thing
	// that silently loses its guard later: each one is a single line in the implementation,
	// so nothing else would fail if it were deleted.
	t.Run("blank dir", func(t *testing.T) {
		if err := ValidateWheelhouse("   "); err == nil {
			t.Fatal("expected error for a blank wheelhouse dir")
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
		if err := ValidateWheelhouse(path); err == nil {
			t.Fatal("expected error when the wheelhouse path is a file")
		}
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
