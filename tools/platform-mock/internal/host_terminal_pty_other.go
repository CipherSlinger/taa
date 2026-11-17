//go:build !linux

package mock

import (
	"errors"
	"os"
	"syscall"
)

var errPTYUnsupported = errors.New("宿主机终端只在 Linux 上可用")

func openPTY() (*os.File, string, error) { return nil, "", errPTYUnsupported }

func resizePTY(*os.File, uint, uint) error { return errPTYUnsupported }

func newTerminalSysProcAttr() *syscall.SysProcAttr { return nil }

func killSession(int)                       {}
func openPTYSlave(string) (*os.File, error) { return nil, errPTYUnsupported }
