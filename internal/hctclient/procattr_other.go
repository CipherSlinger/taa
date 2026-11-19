//go:build !linux

package hctclient

import "os/exec"

// configureProcAttr is a no-op off Linux; HCT is only supported on Linux.
func configureProcAttr(cmd *exec.Cmd) {}
