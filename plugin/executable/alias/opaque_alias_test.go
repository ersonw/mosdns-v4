package alias

import (
	"strings"
	"testing"
)

func TestOpaqueAliasRoundTrip(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.add("ip138.com"); err != nil {
		t.Fatal(err)
	}
	p := &plugin{suffix: ".local", opaque: true, dotRepl: "-", store: s}

	alias := p.aliasName("ip138.com")
	if strings.Contains(alias, "ip138") {
		t.Fatalf("opaque alias still contains the real name: %q", alias)
	}
	real, scheme, ok := p.lookup(alias)
	if !ok || real != "ip138.com" || scheme != schemeHTTP {
		t.Fatalf("lookup(%q) = %q %q %v", alias, real, scheme, ok)
	}

	sub := p.aliasName("cache.ip138.com")
	real, _, ok = p.lookup(sub)
	if !ok || real != "cache.ip138.com" {
		t.Fatalf("subdomain lookup(%q) = %q ok=%v", sub, real, ok)
	}
}

func TestOpaqueAliasDoesNotDecodeForeignName(t *testing.T) {
	s := newTestStore(t)
	if _, _, err := s.add("ip138.com"); err != nil {
		t.Fatal(err)
	}
	p := &plugin{suffix: ".local", opaque: true, dotRepl: "-", store: s}
	alias := opaqueAliasLabel("example.org")
	if _, _, ok := p.lookup(alias + ".local"); ok {
		t.Fatalf("opaque alias for an unserved domain must not resolve")
	}
}
