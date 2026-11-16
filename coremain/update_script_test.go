package coremain

import (
	"strings"
	"testing"
)

// The install script is the only part of the update that runs outside the
// process, and it must drive the service the same way an operator does. A
// direct systemctl call bypasses whatever the binary's own service command
// does (a status probe that writes to stderr, for one), so the script has to
// go through it.
func TestInstallScriptDrivesServiceThroughBinary(t *testing.T) {
	u := &updater{cfgPath: "/etc/mosdns/config.yaml"}
	script := u.installScript("/tmp/selfupdate", "/tmp/mosdns.new", "", "v4.0.5")

	for _, want := range []string{
		`"$BIN" service restart`,
		`"$BIN" service status 2>&1`,
		`= "running"`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("install script is missing %q\n%s", want, script)
		}
	}
	if strings.Contains(script, "systemctl") {
		t.Errorf("install script still calls systemctl directly\n%s", script)
	}
}

// A rollback has to restart the restored binary the same way, otherwise the
// failed build is still the one being supervised.
func TestInstallScriptRollbackRestartsRestoredBinary(t *testing.T) {
	u := &updater{cfgPath: "/etc/mosdns/config.yaml"}
	script := u.installScript("/tmp/selfupdate", "/tmp/mosdns.new", "/tmp/config.yaml", "v4.0.5")

	if n := strings.Count(script, `"$BIN" service restart`); n != 2 {
		t.Errorf("expected a restart on install and on rollback, got %d", n)
	}
	if !strings.Contains(script, `install -m 644 -o root -g root "$NEWCFG" "$CFG"`) {
		t.Errorf("config is not installed when a new one is generated\n%s", script)
	}
}
