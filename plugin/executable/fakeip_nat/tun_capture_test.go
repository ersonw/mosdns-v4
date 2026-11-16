package fakeipnat

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCapturePrefixes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "capture.txt")
	body := "# a comment\n\n23.55.179.0/24\n167.82.86.73\n23.55.179.0/24\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := loadCapturePrefixes([]string{"71.18.35.0/24", " "}, path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"71.18.35.0/24", "23.55.179.0/24", "167.82.86.73/32"}
	if len(got) != len(want) {
		t.Fatalf("got %d prefixes %v, want %d %v", len(got), got, len(want), want)
	}
	for i, w := range want {
		if got[i].String() != w {
			t.Fatalf("prefix %d = %q, want %q", i, got[i].String(), w)
		}
	}
}

func TestLoadCapturePrefixesRejectsBadInput(t *testing.T) {
	for _, entry := range []string{"23.55.179.0/24 # inline note", "2001:db8::/32", "not-a-prefix"} {
		if _, err := loadCapturePrefixes([]string{entry}, ""); err == nil {
			t.Fatalf("entry %q was accepted, want an error", entry)
		}
	}
}

func TestCapturesAddr(t *testing.T) {
	p, err := loadCapturePrefixes([]string{"23.55.179.0/24", "167.82.86.73/32"}, "")
	if err != nil {
		t.Fatal(err)
	}
	c := &FakeIPNatPlugin{capturePrefixes: p}

	cases := []struct {
		addr string
		want bool
	}{
		{"23.55.179.10", true},
		{"23.55.180.1", false},
		{"167.82.86.73", true},
		{"167.82.86.74", false},
	}
	for _, tc := range cases {
		addr := mustAddr(t, tc.addr)
		if got := c.capturesAddr(addr); got != tc.want {
			t.Fatalf("capturesAddr(%s) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestCapturesAddrEmptyList(t *testing.T) {
	c := &FakeIPNatPlugin{}
	if c.capturesAddr(mustAddr(t, "23.55.179.10")) {
		t.Fatal("an empty capture list must not accept anything")
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return addr
}
