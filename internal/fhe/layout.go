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
	"path/filepath"
	"regexp"
	"strings"
)

const evalKeyFileName = "eval_context.bin"

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
