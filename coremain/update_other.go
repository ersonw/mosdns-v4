//go:build !linux

package coremain

import "errors"

// Replacing a running service binary and restarting it is a Linux service
// concern; elsewhere the updater stops after validating the download.
func launchInstallerScript(string) error {
	return errors.New("self-update install is only supported on linux")
}
