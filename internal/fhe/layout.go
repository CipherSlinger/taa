// Package fhe drives the Latti FHE service from TAA.
//
// The service exposes a small HTTP surface under /api/v1 and no upload
// endpoint at all: it reads its inputs from a fixed directory layout on local
// disk and writes its results back there. Everything in this package exists to
// honour that contract - build the paths, publish the inputs, create the task,
// wait for the terminal state, and hand the result back.
package fhe

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const evalKeyFileName = "eval_context.bin"

// sharedDirMode is the mode of every directory this package creates inside the
// shared data directory, whatever the process umask is.
//
// 0755 rather than the umask's answer, for the same reason the files published
// into these directories are 0644: the FHE service reads them from a container
// running as another user, and traversal is checked against the mode of every
// directory on the way, so a directory that user cannot enter hides even a
// world-readable file inside it. Nothing in these directories is private - the
// names are content digests and task ids, and the files are already 0644 - so
// the traversal bits cost nothing, and 0755 is exactly what an umask of 022
// produced before this was pinned: the service has been reading through these
// directories all along.
//
// This is the mode of the shared layout only, and applies to <data>/keys,
// <data>/keys/<userID>, <data>/tasks and <data>/tasks/<taskID> through
// Layout.MkdirShared. It is deliberately NOT the mode of:
//
//   - the eval key cache, which is TAA-private and stays 0700 (KeyCache);
//   - the shared root itself, whose mode belongs to the bind mount and to
//     deploy-fhe.sh;
//   - <data>/models, which this package only builds paths for and never
//     creates - deploy-fhe.sh stages it;
//   - <data>/results, which the FHE service writes and TAA reads.
const sharedDirMode os.FileMode = 0o755

// sm3HexPattern matches an SM3 digest: exactly 64 lowercase hex characters.
//
// This is a security boundary, not a formatting preference. Both the eval key
// digest and the model digest are used verbatim as directory names, so a value
// outside this set ("../../etc", an absolute path, a name with a separator)
// would let a caller write and read outside the shared data directory. Every
// path builder in this file runs its identifier through here first.
var sm3HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// taskIDPattern bounds a task id to a single, portable path segment.
var taskIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidHash reports whether s is a usable SM3 hex digest.
func ValidHash(s string) bool {
	return sm3HexPattern.MatchString(s)
}

// ValidTaskID rejects a task id that is not a single safe path segment.
func ValidTaskID(s string) error {
	if !taskIDPattern.MatchString(s) {
		return fmt.Errorf("invalid task id %q: want 1-128 characters of [A-Za-z0-9._-] starting with an alphanumeric", s)
	}
	return nil
}

// Layout builds paths inside the directory TAA and the FHE service share.
//
// Both processes must see the same absolute paths - the contract is a bind
// mount, and a path that resolves differently on either side silently makes the
// service read nothing.
type Layout struct {
	dataDir string
}

// NewLayout returns the layout rooted at dataDir, which must be non-empty.
func NewLayout(dataDir string) Layout {
	return Layout{dataDir: strings.TrimSpace(dataDir)}
}

// DataDir returns the shared root.
func (l Layout) DataDir() string { return l.dataDir }

func (l Layout) root() (string, error) {
	if l.dataDir == "" {
		return "", fmt.Errorf("fhe data dir is empty")
	}
	return l.dataDir, nil
}

func (l Layout) join(parts ...string) (string, error) {
	root, err := l.root()
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{root}, parts...)...), nil
}

// ModelDir is <data>/models/<modelHash>, the parent of the server/ directory the
// service activates. The digest is the model registry id.
func (l Layout) ModelDir(modelHash string) (string, error) {
	if !ValidHash(modelHash) {
		return "", fmt.Errorf("invalid model hash %q: want 64 lowercase hex characters", modelHash)
	}
	return l.join("models", modelHash)
}

// KeyDir is <data>/keys/<userID>. Note the absence of a model id: one eval
// context serves every model, because they all share the same FHE parameter set.
func (l Layout) KeyDir(userID string) (string, error) {
	if !ValidHash(userID) {
		return "", fmt.Errorf("invalid user id %q: want 64 lowercase hex characters", userID)
	}
	return l.join("keys", userID)
}

// KeyPath is the file the service reads: <data>/keys/<userID>/eval_context.bin.
func (l Layout) KeyPath(userID string) (string, error) {
	dir, err := l.KeyDir(userID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, evalKeyFileName), nil
}

// TaskDir is <data>/tasks/<taskID>.
func (l Layout) TaskDir(taskID string) (string, error) {
	if err := ValidTaskID(taskID); err != nil {
		return "", err
	}
	return l.join("tasks", taskID)
}

// TaskInputPath is the input archive the service reads for a task.
func (l Layout) TaskInputPath(taskID string) (string, error) {
	dir, err := l.TaskDir(taskID)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "input.zip"), nil
}

// ResultPath is the archive the service writes for a task.
func (l Layout) ResultPath(taskID string) (string, error) {
	if err := ValidTaskID(taskID); err != nil {
		return "", err
	}
	return l.join("results", taskID, "output.zip")
}

// MkdirShared creates dir, which must be inside the shared data directory, with
// sharedDirMode whatever the process umask is.
//
// os.MkdirAll applies the umask to the mode it is given, so under umask 077
// every directory the publish path created - <data>/keys and <data>/keys/<userID>
// for the eval key, <data>/tasks and <data>/tasks/<taskID> for the input archive
// - landed 0700 and the FHE service could not enter it. The 0644 file inside was
// then unreachable anyway, which is the same failure the file modes were fixed
// for, one path component further out. MkdirAll also leaves the mode of a
// directory that already exists alone, so the chmod below is not conditional on
// this call having created anything: a directory an earlier run made under a
// restrictive umask would otherwise keep it forever.
//
// Every ancestor between dir and the shared root is fixed too, because
// traversal is checked one path component at a time: <data>/keys at 0700 hides
// <data>/keys/<userID> whatever mode that one holds.
//
// The shared root itself is not touched - deploy-fhe.sh creates it and its mode
// belongs to the bind mount - and neither is anything outside it. Directories
// this package does not create are not covered either: <data>/models is staged by
// deploy-fhe.sh and <data>/results is the service's own output directory.
func (l Layout) MkdirShared(dir string) error {
	root, err := l.root()
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return fmt.Errorf("resolve %s against the shared data dir %s: %w", dir, root, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("refusing to create %s: it is outside the shared data dir %s", dir, root)
	}
	if err := os.MkdirAll(dir, sharedDirMode); err != nil {
		return err
	}
	for d := dir; d != root; d = filepath.Dir(d) {
		if err := os.Chmod(d, sharedDirMode); err != nil {
			return err
		}
	}
	return nil
}
