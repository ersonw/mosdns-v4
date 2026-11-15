package coremain

import (
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

func TestParseMemorySize(t *testing.T) {
	tests := []struct {
		raw     string
		want    int64
		wantErr bool
	}{
		{"256MiB", 256 << 20, false},
		{"256Mi", 256 << 20, false},
		{"1GB", 1 << 30, false},
		{"512MB", 512 << 20, false},
		{"64KiB", 64 << 10, false},
		{"1024", 1024, false},
		{" 128 MiB ", 128 << 20, false},
		{"", 0, true},
		{"abc", 0, true},
		{"-1MiB", 0, true},
		{"10XB", 0, true},
	}
	for _, tt := range tests {
		got, err := parseMemorySize(tt.raw)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseMemorySize(%q) = %d, want an error", tt.raw, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseMemorySize(%q) failed: %v", tt.raw, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseMemorySize(%q) = %d, want %d", tt.raw, got, tt.want)
		}
	}
}

func TestScavengeInterval(t *testing.T) {
	tests := []struct {
		raw  string
		want time.Duration
	}{
		{"", 0},
		{"30s", 0}, // below the minimum: a stop-the-world GC every 30s is a CPU bug
		{"10m", 10 * time.Minute},
		{"2h", 2 * time.Hour},
		{"nonsense", 0},
	}
	for _, tt := range tests {
		if got := scavengeInterval(RuntimeConfig{ScavengeInterval: tt.raw}); got != tt.want {
			t.Errorf("scavengeInterval(%q) = %v, want %v", tt.raw, got, tt.want)
		}
	}
}

func TestApplyRuntimeConfigKeepsDefaultsWhenUnset(t *testing.T) {
	prevGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(prevGC)
	prevLimit := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(prevLimit)
	prevProcs := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(prevProcs)

	if err := applyRuntimeConfig(RuntimeConfig{}); err != nil {
		t.Fatalf("empty config must be accepted: %v", err)
	}
	if got := runtime.GOMAXPROCS(0); got != prevProcs {
		t.Errorf("GOMAXPROCS changed to %d, want %d", got, prevProcs)
	}
}

func TestApplyRuntimeConfigAppliesValues(t *testing.T) {
	prevGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(prevGC)
	prevLimit := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(prevLimit)
	prevProcs := runtime.GOMAXPROCS(0)
	defer runtime.GOMAXPROCS(prevProcs)

	cfg := RuntimeConfig{MaxProcs: 1, GCPercent: 40, MemoryLimit: "96MiB"}
	if err := applyRuntimeConfig(cfg); err != nil {
		t.Fatalf("applyRuntimeConfig: %v", err)
	}
	if got := runtime.GOMAXPROCS(0); got != 1 {
		t.Errorf("GOMAXPROCS = %d, want 1", got)
	}
	// SetGCPercent(-1) reports the current value without keeping the change.
	if got := debug.SetGCPercent(-1); got != 40 {
		t.Errorf("GC percent = %d, want 40", got)
	}
	if got := debug.SetMemoryLimit(-1); got != 96<<20 {
		t.Errorf("memory limit = %d, want %d", got, 96<<20)
	}
}

func TestApplyRuntimeConfigRejectsBadLimit(t *testing.T) {
	prevLimit := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(prevLimit)
	if err := applyRuntimeConfig(RuntimeConfig{MemoryLimit: "lots"}); err == nil {
		t.Fatal("expected an error for an unparsable memory_limit")
	}
}
