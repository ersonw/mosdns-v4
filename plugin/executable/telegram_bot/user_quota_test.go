package telegram_bot

import (
	"context"
	"strings"
	"testing"
)

func TestParseByteSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"0", 0},
		{"-", 0},
		{"unlimited", 0},
		{"512", 512},
		{"1KB", 1024},
		{"10MB", 10 << 20},
		{"10GB", 10 << 30},
		{"1TiB", 1 << 40},
		{"2g", 2 << 30},
	}
	for _, c := range cases {
		got, err := parseByteSize(c.in)
		if err != nil || got != c.want {
			t.Fatalf("parseByteSize(%q) = %d/%v, want %d", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"12XB", "-5GB", "abc"} {
		if _, err := parseByteSize(bad); err == nil {
			t.Fatalf("parseByteSize(%q) accepted", bad)
		}
	}
}

func TestParseResetPeriod(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"0", 0},
		{"-", 0},
		{"none", 0},
		{"30d", 30 * 86400},
		{"1w", 7 * 86400},
		{"168h", 168 * 3600},
		{"90m", 90 * 60},
	}
	for _, c := range cases {
		got, err := parseResetPeriod(c.in)
		if err != nil || got != c.want {
			t.Fatalf("parseResetPeriod(%q) = %d/%v, want %d", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"-1d", "abc"} {
		if _, err := parseResetPeriod(bad); err == nil {
			t.Fatalf("parseResetPeriod(%q) accepted", bad)
		}
	}
}

func TestFormatPeriod(t *testing.T) {
	if got := formatPeriod(0); got != "none" {
		t.Fatalf("formatPeriod(0) = %q", got)
	}
	if got := formatPeriod(30 * 86400); got != "30d" {
		t.Fatalf("formatPeriod(30d) = %q", got)
	}
	if got := formatPeriod(3600); got != "1h0m0s" {
		t.Fatalf("formatPeriod(1h) = %q", got)
	}
}

func TestUserLimitAndResetCommands(t *testing.T) {
	p, adm := newRadiusBot()
	reply, err := p.handleText(context.Background(), 123, "/user limit alice 10GB 30d")
	if err != nil {
		t.Fatalf("handleText: %v", err)
	}
	if !strings.Contains(reply, "alice: max=10.0GB reset=30d") {
		t.Fatalf("limit reply = %q", reply)
	}
	if len(adm.quotas) != 1 || adm.quotas[0][0] != "alice" ||
		adm.quotas[0][1] != int64(10<<30) || adm.quotas[0][2] != int64(30*86400) {
		t.Fatalf("quota call = %+v", adm.quotas)
	}

	if _, err := p.handleText(context.Background(), 123, "/user limit alice 0"); err != nil {
		t.Fatalf("handleText unlimited: %v", err)
	}
	if len(adm.quotas) != 2 || adm.quotas[1][1] != int64(0) || adm.quotas[1][2] != int64(-1) {
		t.Fatalf("unlimited quota call = %+v", adm.quotas)
	}

	if _, err := p.handleText(context.Background(), 123, "/user reset alice"); err != nil {
		t.Fatalf("handleText reset: %v", err)
	}
	if len(adm.resets) != 1 || adm.resets[0] != "alice" {
		t.Fatalf("reset call = %+v", adm.resets)
	}
}

func TestUserUsageOutput(t *testing.T) {
	p, adm := newRadiusBot()
	adm.users[0].UsedIn = 1 << 20
	adm.users[0].UsedOut = 2 << 20
	adm.users[0].MaxTotal = 10 << 20
	adm.users[0].ResetPeriod = 30 * 86400
	adm.users[0].PeriodStart = 1700000000

	reply, err := p.handleText(context.Background(), 123, "/user usage alice")
	if err != nil {
		t.Fatalf("handleText: %v", err)
	}
	for _, want := range []string{"alice on radius: enabled", "up: 1.0MB", "down: 2.0MB", "total: 3.0MB / 10.0MB", "remaining: 7.0MB", "reset period: 30d"} {
		if !strings.Contains(reply, want) {
			t.Fatalf("usage missing %q: %s", want, reply)
		}
	}
}
