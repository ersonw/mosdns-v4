package coremain

import (
	"testing"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/safe_close"
)

// TestRequestShutdownDrivesTheCloseSignal: the service wrapper and the signal
// watcher reach the running instance only through this registry, so it has to
// hand the close signal to the SafeClose RunMosdns waits on.
func TestRequestShutdownDrivesTheCloseSignal(t *testing.T) {
	sc := safe_close.NewSafeClose()
	m := &Mosdns{sc: sc}
	done := registerActive(m)

	if !RequestShutdown("test shutdown") {
		t.Fatalf("RequestShutdown reported nothing running")
	}
	select {
	case <-sc.ReceiveCloseSignal():
	case <-time.After(time.Second):
		t.Fatalf("close signal was not sent")
	}
	if WaitShutdown(50 * time.Millisecond) {
		t.Fatalf("WaitShutdown returned before the close pass finished")
	}

	clearActive(m, done)
	if RequestShutdown("again") {
		t.Fatalf("RequestShutdown reported a running instance after it closed")
	}
	if !WaitShutdown(time.Second) {
		t.Fatalf("WaitShutdown did not report a finished close pass")
	}
}

// TestRequestShutdownWithoutAnInstance: a signal that arrives before RunMosdns
// registered anything must not block or panic.
func TestRequestShutdownWithoutAnInstance(t *testing.T) {
	if RequestShutdown("nothing running") {
		t.Fatalf("RequestShutdown reported a running instance")
	}
	if !WaitShutdown(time.Second) {
		t.Fatalf("WaitShutdown blocked with no instance")
	}
}
