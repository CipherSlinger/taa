//go:build linux

package hctclient

import (
	"os/exec"
	"syscall"
)

// configureProcAttr puts the helper in its own process group so a stop kills
// any children it may have spawned, and keeps it from sharing TAA's terminal
// signals.
func configureProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
