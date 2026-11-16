//go:build linux

package coremain

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// launchInstallerScript starts the swap outside the running service's cgroup.
//
// The script ends with "systemctl restart mosdns", and a restart kills every
// process in that unit's cgroup - including a child started from inside it.
// That is how an earlier version lost its health check and its rollback: the
// binary had been installed, the restart had been issued, and then the script
// itself was killed. A transient unit lives in its own cgroup and survives.
func launchInstallerScript(path string) error {
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer devnull.Close()

	if _, lookErr := exec.LookPath("systemd-run"); lookErr == nil {
		unit := "mosdns-selfupdate-" + time.Now().Format("20060102-150405")
		cmd := exec.Command("systemd-run", "--unit", unit, "--collect", "--no-block", "--quiet", "/bin/sh", path)
		cmd.Stdout = devnull
		cmd.Stderr = devnull
		if startErr := cmd.Start(); startErr == nil {
			// The transient unit runs the script, so our own copy can go.
			go func() { _ = cmd.Wait() }()
			return nil
		}
	}

	// Without systemd-run the script still gets its own session, which keeps it
	// alive as long as the restart does not reach it through the cgroup.
	cmd := exec.Command("/bin/sh", filepath.Clean(path))
	cmd.Stdout = devnull
	cmd.Stderr = devnull
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot start the install script, %w", err)
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
