// Package execenv abstracts where a model's runtimeConfig executes.
//
// TAA always runs a model through /bin/sh, but it does not always run it in its
// own namespaces: when TAA starts from the CSV2 initrd, the interpreter and
// dependencies a model needs may only exist inside the container image, so the
// command has to be handed to that container's namespaces instead. A Target is
// the seam between "what to run" and "where it runs".
//
// The seam carries no security decision. A target only decides where work
// happens; audit, result checking and platform reporting always stay in TAA.
package execenv

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// Spec describes one model execution in TAA's own path view. A target maps
// these to the paths the executed process will see.
type Spec struct {
	ModelDir     string // model code; also the process working directory
	DataDir      string // staged dataset
	OutputDir    string // result directory
	LogDir       string // log directory the report path tails
	ProgressPath string // progress file the report path tails
}

// Target is one place a model can execute.
type Target interface {
	// Name identifies the target in logs.
	Name() string
	// Resolve maps a TAA-side path to the path the executed process sees.
	Resolve(initPath string) string
	// Visible maps a path the executed process sees back to one TAA itself can
	// read and write.
	Visible(targetPath string) string
	// Prepare makes the environment ready for one execution: the directories
	// that must exist and the model/data the process expects to find there.
	Prepare(ctx context.Context, spec Spec) error
	// Cleanup undoes what Prepare staged. It must tolerate a partially prepared
	// environment and must never turn a finished task into a failure.
	Cleanup(ctx context.Context, spec Spec)
	// Command builds the shell invocation for one command line. The caller owns
	// env, stdout and stderr; the target owns where and how the shell starts.
	Command(ctx context.Context, commandLine, workDir string) *exec.Cmd
}

// LocalTarget runs the model directly, in TAA's own namespaces and with the
// host's /bin/sh - the behaviour every deployment had before targets existed.
type LocalTarget struct{}

// NewLocalTarget returns the in-process target.
func NewLocalTarget() LocalTarget {
	return LocalTarget{}
}

var _ Target = LocalTarget{}

// Name implements Target.
func (LocalTarget) Name() string { return "local" }

// Resolve implements Target. Local execution needs no translation.
func (LocalTarget) Resolve(path string) string { return path }

// Visible implements Target. Local execution needs no translation.
func (LocalTarget) Visible(path string) string { return path }

// Prepare implements Target. The result directory is the only thing the
// executor ever created, and it keeps that work with the target that owns the
// filesystem view.
func (LocalTarget) Prepare(_ context.Context, spec Spec) error {
	if err := os.MkdirAll(spec.OutputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	return nil
}

// Cleanup implements Target. Local execution stages nothing, so there is
// nothing to undo.
func (LocalTarget) Cleanup(context.Context, Spec) {}

// Command implements Target. Setpgid gives the child its own process group so a
// stop can SIGKILL the whole tree, not just the shell.
func (LocalTarget) Command(ctx context.Context, commandLine, workDir string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", commandLine)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Dir = workDir
	return cmd
}
