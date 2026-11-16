//go:build linux

package coremain

import (
	"os"
	"os/exec"
	"syscall"
)

// launchInstallerScript starts the swap in its own session. The script restarts
// the service, so it must outlive the process that launches it.
func launchInstallerScript(path string) error {
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer devnull.Close()

	cmd := exec.Command("/bin/sh", path)
	cmd.Stdout = devnull
	cmd.Stderr = devnull
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}
