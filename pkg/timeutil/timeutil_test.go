package timeutil

import (
	"testing"
	"time"
)

func TestLoadDefault(t *testing.T) {
	loc, err := Load("")
	if err != nil {
		t.Fatalf("Load default: %v", err)
	}
	if loc.String() != Default {
		t.Fatalf("loc = %q, want %q", loc, Default)
	}
}

func TestLoadInvalid(t *testing.T) {
	if _, err := Load("Mars/Olympus"); err == nil {
		t.Fatal("invalid timezone must fail")
	}
}

func TestFormatUnix(t *testing.T) {
	loc, err := Load("Asia/Shanghai")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// 2026-11-13 00:00:00 UTC is 08:00 in Shanghai.
	ts := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC).Unix()
	if got := FormatUnix(ts, "2006-01-02 15:04", loc); got != "2026-11-13 08:00" {
		t.Fatalf("FormatUnix = %q", got)
	}
	if got := FormatUnix(0, "2006-01-02 15:04", loc); got != "" {
		t.Fatalf("zero timestamp = %q, want empty", got)
	}
}
