package coremain

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestInstanceLockRejectsSecondProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("single-instance lock is a no-op on windows")
	}
	dir := t.TempDir()
	release, err := acquireInstanceLock(dir)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	defer release()

	cmd := exec.Command(os.Args[0], "-test.run=TestInstanceLockHelperProcess")
	cmd.Env = append(os.Environ(), "MOSDNS_LOCK_HELPER=1", "MOSDNS_LOCK_DIR="+dir)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("second instance acquired the lock, output=%s", out)
	}
	if !strings.Contains(string(out), "already running") {
		t.Fatalf("second instance error is not actionable: %s", out)
	}
}

func TestInstanceLockHelperProcess(t *testing.T) {
	if os.Getenv("MOSDNS_LOCK_HELPER") != "1" {
		return
	}
	release, err := acquireInstanceLock(os.Getenv("MOSDNS_LOCK_DIR"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	release()
	os.Exit(0)
}

func TestInstanceLockReleaseAllowsRestart(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("single-instance lock is a no-op on windows")
	}
	dir := t.TempDir()
	release, err := acquireInstanceLock(dir)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	release()
	release, err = acquireInstanceLock(dir)
	if err != nil {
		t.Fatalf("reacquire after release: %v", err)
	}
	release()
}
