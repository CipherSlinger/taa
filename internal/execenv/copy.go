package execenv

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// treeSize sums the size of every regular file under root. Symbolic links are
// not followed, so the number cannot be inflated or redirected by one.
func treeSize(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	return total, err
}

// clearDirContents removes everything inside dir but keeps dir itself.
func clearDirContents(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

// copyTree copies a directory tree. Symbolic links and special files are
// refused rather than skipped: a model that ships either is not something this
// path should quietly reinterpret, and following a link would copy data from
// outside the staged tree.
func copyTree(ctx context.Context, src, dst string) error {
	root := filepath.Clean(src)
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		info, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("refuse to follow symlink %s", path)
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case info.Mode().IsRegular():
			return copyFile(path, target, info.Mode().Perm())
		default:
			return fmt.Errorf("unsupported file type %s at %s", info.Mode().Type(), path)
		}
	})
}

// copyFile copies one regular file and verifies the byte count, so a truncated
// copy surfaces here instead of as a model error much later.
func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, in)
	if err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if n != info.Size() {
		return fmt.Errorf("short copy of %s: wrote %d of %d bytes", src, n, info.Size())
	}
	return nil
}
