package coremain

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/safe_close"
	"go.uber.org/zap"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestReadProcCPUTime(t *testing.T) {
	// 150 ticks of utime+stime at USER_HZ=100 is 1.5s.
	stat := "1234 (mosdns worker) S 1 1234 1234 0 -1 4194304 100 0 0 0 100 50 0 0 20 0 1 0 0\n"
	path := writeTemp(t, "stat", stat)
	got, err := readProcCPUTime(path)
	if err != nil {
		t.Fatalf("readProcCPUTime: %v", err)
	}
	if want := 1500 * time.Millisecond; got != want {
		t.Fatalf("cpu time = %v, want %v", got, want)
	}
}

func TestReadProcCPUTimeMalformed(t *testing.T) {
	for _, bad := range []string{"", "no parens here", "1234 (x) S 1 2"} {
		path := writeTemp(t, "bad", bad)
		if _, err := readProcCPUTime(path); err == nil {
			t.Fatalf("readProcCPUTime(%q) returned no error", bad)
		}
	}
}

func TestReadRSSBytes(t *testing.T) {
	path := writeTemp(t, "statm", "100 25 10 5 0 0 0\n")
	got, err := readRSSBytes(path)
	if err != nil {
		t.Fatalf("readRSSBytes: %v", err)
	}
	if want := uint64(25 * os.Getpagesize()); got != want {
		t.Fatalf("rss = %d, want %d", got, want)
	}
}

func TestReadMemTotalBytes(t *testing.T) {
	meminfo := "MemTotal:       1919032 kB\nMemFree:         840000 kB\n"
	path := writeTemp(t, "meminfo", meminfo)
	got, err := readMemTotalBytes(path)
	if err != nil {
		t.Fatalf("readMemTotalBytes: %v", err)
	}
	if want := uint64(1919032) * 1024; got != want {
		t.Fatalf("memtotal = %d, want %d", got, want)
	}
}

func TestReadMemTotalBytesMissing(t *testing.T) {
	path := writeTemp(t, "meminfo", "MemFree: 1 kB\n")
	if _, err := readMemTotalBytes(path); err == nil {
		t.Fatal("expected an error when MemTotal is absent")
	}
}

func TestCPUPercentOfMachine(t *testing.T) {
	// Two seconds of CPU over a five second window on four cores is 10% of the
	// machine, not 40%.
	if got := cpuPercentOfMachine(2*time.Second, 5*time.Second, 4); got != 10 {
		t.Fatalf("cpu percent = %v, want 10", got)
	}
	if got := cpuPercentOfMachine(time.Second, 0, 4); got != 0 {
		t.Fatalf("zero wall should give 0, got %v", got)
	}
}

func TestMemoryPercent(t *testing.T) {
	if got := memoryPercent(900, 1000); got != 90 {
		t.Fatalf("memory percent = %v, want 90", got)
	}
	if got := memoryPercent(900, 0); got != 0 {
		t.Fatalf("unknown total should give 0, got %v", got)
	}
}

func TestGuardScavengesOnceAfterSustain(t *testing.T) {
	opts := guardOptionsFrom(RuntimeConfig{})
	st := &guardState{}
	start := time.Unix(1000, 0)

	// The first sample starts the timer but must not act on its own.
	d := st.decide(start, 0, 95, opts, 2)
	if d.scavenge {
		t.Fatal("scavenge before sustain period elapsed")
	}
	// One interval later the condition still has not held long enough.
	d = st.decide(start.Add(opts.interval), 0, 95, opts, 2)
	if d.scavenge {
		t.Fatal("scavenge within sustain period")
	}
	// After the sustain period it fires.
	act := start.Add(opts.sustain)
	d = st.decide(act, 0, 95, opts, 2)
	if !d.scavenge {
		t.Fatal("expected scavenge after sustain period")
	}
	// And is throttled afterwards.
	d = st.decide(act.Add(opts.interval), 0, 95, opts, 2)
	if d.scavenge {
		t.Fatal("scavenge not throttled")
	}
	// Once memory is back to normal the timer resets.
	d = st.decide(act.Add(2*opts.interval), 0, 40, opts, 2)
	if d.scavenge || !st.memHighSince.IsZero() {
		t.Fatal("memory timer should reset below the threshold")
	}
}

func TestGuardDownshiftAndRestore(t *testing.T) {
	opts := guardOptionsFrom(RuntimeConfig{})
	st := &guardState{}
	start := time.Unix(2000, 0)

	if d := st.decide(start, 95, 0, opts, 2); d.downshift {
		t.Fatal("downshift before sustain period elapsed")
	}
	act := start.Add(opts.sustain)
	d := st.decide(act, 95, 0, opts, 2)
	if !d.downshift {
		t.Fatal("expected downshift after sustained cpu saturation")
	}
	if st.originalProcs != 2 {
		t.Fatalf("original gomaxprocs = %d, want 2", st.originalProcs)
	}

	// Nothing happens during the cooldown.
	d = st.decide(act.Add(opts.cooldown-time.Second), 95, 0, opts, 1)
	if d.restore || d.extend || d.downshift {
		t.Fatalf("unexpected decision during cooldown: %+v", d)
	}

	// Still saturated at the end of the cooldown: extend instead of restoring.
	d = st.decide(act.Add(opts.cooldown), 95, 0, opts, 1)
	if !d.extend || d.restore {
		t.Fatalf("expected extend, got %+v", d)
	}
	if !st.downshifted {
		t.Fatal("state should stay downshifted")
	}

	// Recovered by the next expiry: restore.
	d = st.decide(act.Add(2*opts.cooldown), 20, 0, opts, 1)
	if !d.restore || st.downshifted {
		t.Fatalf("expected restore, got %+v (downshifted=%v)", d, st.downshifted)
	}
}

func TestGuardOptionsFrom(t *testing.T) {
	def := guardOptionsFrom(RuntimeConfig{})
	if def.cpuPercent != 90 || def.memPercent != 90 {
		t.Fatalf("defaults = %+v", def)
	}
	if def.interval != 5*time.Second || def.sustain != 15*time.Second || def.cooldown != 5*time.Minute {
		t.Fatalf("default timings = %+v", def)
	}

	custom := guardOptionsFrom(RuntimeConfig{
		GuardCPUPercent: 80,
		GuardMemPercent: 70,
		GuardInterval:   "2s",
		GuardSustain:    "8s",
		GuardCooldown:   "2m",
	})
	if custom.cpuPercent != 80 || custom.memPercent != 70 {
		t.Fatalf("custom percents = %+v", custom)
	}
	if custom.interval != 2*time.Second || custom.sustain != 8*time.Second || custom.cooldown != 2*time.Minute {
		t.Fatalf("custom timings = %+v", custom)
	}

	// A sustain shorter than the sampling period is meaningless: at least one
	// interval has to pass.
	clamped := guardOptionsFrom(RuntimeConfig{GuardInterval: "10s", GuardSustain: "2s"})
	if clamped.sustain != 10*time.Second {
		t.Fatalf("sustain = %v, want clamping to the interval", clamped.sustain)
	}

	// Invalid durations fall back to the defaults instead of disabling the guard.
	bad := guardOptionsFrom(RuntimeConfig{GuardInterval: "soon", GuardSustain: "0s", GuardCooldown: "nope"})
	if bad.interval != 5*time.Second || bad.sustain != 15*time.Second || bad.cooldown != 5*time.Minute {
		t.Fatalf("fallback timings = %+v", bad)
	}
}

func TestSelfGuardDisabledByDefault(t *testing.T) {
	if err := startSelfGuard(zap.NewNop(), RuntimeConfig{}, safe_close.NewSafeClose()); err != nil {
		t.Fatalf("disabled guard returned error: %v", err)
	}
}
