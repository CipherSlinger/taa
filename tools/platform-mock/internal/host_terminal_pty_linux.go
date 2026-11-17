//go:build linux

package mock

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// openPTY allocates a pseudo-terminal pair.
//
// The kernel side is /dev/ptmx: opening it gives a master, and TIOCGPTN names
// the slave. The slave must be unlocked (TIOCSPTLCK) before it can be opened,
// which is the step that is easy to miss and fails as EIO on open otherwise.
func openPTY() (master *os.File, slavePath string, err error) {
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("打开 /dev/ptmx 失败: %w", err)
	}
	master = os.NewFile(uintptr(fd), "/dev/ptmx")

	// TIOCSPTLCK takes a int32 where 0 means unlocked.
	var unlock int32
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, int(unlock)); err != nil {
		master.Close()
		return nil, "", fmt.Errorf("解锁 PTY 从设备失败: %w", err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		master.Close()
		return nil, "", fmt.Errorf("读取 PTY 编号失败: %w", err)
	}
	return master, fmt.Sprintf("/dev/pts/%d", n), nil
}

// resizePTY applies a terminal size to the master side. The kernel propagates it
// to the slave, so the foreground process group sees SIGWINCH as an interactive
// session expects.
func resizePTY(master *os.File, cols, rows uint) error {
	if master == nil || cols == 0 || rows == 0 {
		return nil
	}
	ws := &unix.Winsize{Col: uint16(cols), Row: uint16(rows)}
	return unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, ws)
}

// newTerminalSysProcAttr puts the shell in its own session with the PTY slave as
// its controlling terminal. Without the session the shell is not a process group
// leader, so a terminal-driven signal (Ctrl-C) would have nothing to target, and
// without the controlling terminal job control is inert.
//
// Ctty is the descriptor number in the child: exec sets fds 0/1/2 from the same
// slave file, so 0 is the one to name.
func newTerminalSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
}

// killSession stops every process in the session sid.
//
// Killing the shell's process group is not enough: an interactive shell puts
// each background job in its own process group (that is what job control is),
// and those groups keep running after the shell dies. Session membership, by
// contrast, is inherited by every descendant that does not call setsid itself
// and survives the leader, so it is the only handle that still covers the tree
// once the shell is gone. Measured: `sleep 400 &` outlived a group kill.
//
// Setsid made the shell's pid its session id, so the caller passes the pid it
// started.
func killSession(sid int) {
	if sid <= 0 {
		return
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		// No /proc to walk: the group still stops the shell itself.
		_ = syscall.Kill(-sid, syscall.SIGKILL)
		return
	}
	self := os.Getpid()
	for _, entry := range entries {
		pid, convErr := strconv.Atoi(entry.Name())
		if convErr != nil || pid == self {
			continue
		}
		if processSessionID(pid) == sid {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

// processSessionID reads the session field of /proc/<pid>/stat. The comm field
// can contain spaces and parentheses, so parsing starts after its last ')'.
func processSessionID(pid int) int {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return -1
	}
	closeIdx := bytes.LastIndexByte(data, ')')
	if closeIdx < 0 || closeIdx+2 >= len(data) {
		return -1
	}
	// After comm: state, ppid, pgrp, session — so session is index 3.
	fields := strings.Fields(string(data[closeIdx+2:]))
	if len(fields) < 4 {
		return -1
	}
	sid, err := strconv.Atoi(fields[3])
	if err != nil {
		return -1
	}
	return sid
}

// openPTYSlave opens the slave side of the pair. O_NOCTTY keeps this process
// from acquiring the terminal the shell is about to claim.
func openPTYSlave(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY, 0)
}
