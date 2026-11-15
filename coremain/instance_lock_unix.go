//go:build !windows

package coremain

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const instanceLockName = ".mosdns.lock"

// acquireInstanceLock takes an exclusive lock next to the config file. The
// kernel releases it automatically when the process exits, including SIGKILL,
// so a crash cannot leave a stale lock that blocks the next start.
func acquireInstanceLock(configDir string) (func(), error) {
	dir := strings.TrimSpace(configDir)
	if dir == "" {
		dir = "."
	}
	path := filepath.Join(dir, instanceLockName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open instance lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		pid := readLockPID(f)
		_ = f.Close()
		if pid > 0 {
			return nil, fmt.Errorf("another mosdns instance is already running (pid %d, lock %s); stop it first, or use the service manager to restart mosdns", pid, path)
		}
		return nil, fmt.Errorf("another mosdns instance is already running (lock %s); stop it first, or use the service manager to restart mosdns", path)
	}
	_ = f.Truncate(0)
	_, _ = f.WriteString(strconv.Itoa(os.Getpid()) + "\n")
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

func readLockPID(f *os.File) int {
	b, err := os.ReadFile(f.Name())
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0
	}
	return pid
}
