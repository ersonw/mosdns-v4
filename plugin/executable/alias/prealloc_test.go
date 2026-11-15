package alias

import (
	"net/netip"
	"testing"
)

func TestPreallocateAndLookup(t *testing.T) {
	a, err := newAllocator(netip.MustParsePrefix("198.18.4.0/23"))
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := a.Preallocate([]string{"ip138.com", "ipinfo.io", "ip138.com"})
	if err != nil || mapped != 3 {
		t.Fatalf("mapped=%d err=%v", mapped, err)
	}
	addr, ok := a.Lookup("ip138.com")
	if !ok || addr.String() != "198.18.4.2" {
		t.Fatalf("lookup ip138.com = %v ok=%v", addr, ok)
	}
	if got, _ := a.DomainOf(addr); got != "ip138.com" {
		t.Fatalf("reverse = %q", got)
	}
	if again, err := a.Ensure("ip138.com"); err != nil || again != addr {
		t.Fatalf("ensure must reuse mapping: %v err=%v", again, err)
	}
	if _, ok := a.Lookup("www.ip138.com"); ok {
		t.Fatal("unlisted subdomain must not be preallocated")
	}
}
