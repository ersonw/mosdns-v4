package alias

// alloc.go owns the domain -> virtual address table of the gateway. It is
// deliberately independent from fakeip_nat: the mapping is built from the
// served list, not from an upstream answer, and it lives in this process only.
// A restart rebuilds it on the first query of each name.

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"sync"
)

// allocator hands out stable virtual addresses for domain names. The first
// host of the range is reserved for the tun device (outbound dials are sourced
// from it), so allocation starts at the second host.
type allocator struct {
	mu     sync.RWMutex
	prefix netip.Prefix
	base   uint32 // network address as uint32
	maxOff uint32 // highest usable host offset (broadcast excluded)
	next   uint32 // allocation hint, avoids rescanning from the start

	byDomain map[string]netip.Addr
	byAddr   map[netip.Addr]string
}

// reservedOffset is the first host of the range: the tun device owns it.
const reservedOffset = 1

func newAllocator(prefix netip.Prefix) (*allocator, error) {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return nil, fmt.Errorf("invalid ipv4_range %q: must be an IPv4 prefix", prefix)
	}
	if ones := prefix.Bits(); ones > 30 {
		return nil, fmt.Errorf("invalid ipv4_range %q: need at least 2 usable addresses", prefix)
	}
	masked := prefix.Masked().Addr().As4()
	base := binary.BigEndian.Uint32(masked[:])
	maxOff := uint32(1)<<uint(32-prefix.Bits()) - 1 // last address (broadcast)
	return &allocator{
		prefix:   prefix.Masked(),
		base:     base,
		maxOff:   maxOff,
		next:     reservedOffset + 1,
		byDomain: make(map[string]netip.Addr),
		byAddr:   make(map[netip.Addr]string),
	}, nil
}

// deviceAddr is the address the tun device owns.
func (a *allocator) deviceAddr() netip.Addr {
	return a.addrOf(reservedOffset)
}

func (a *allocator) addrOf(off uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], a.base+off)
	return netip.AddrFrom4(b)
}

func (a *allocator) offsetOf(addr netip.Addr) (uint32, bool) {
	if !addr.Is4() || !a.prefix.Contains(addr) {
		return 0, false
	}
	raw := addr.As4()
	v := binary.BigEndian.Uint32(raw[:])
	return v - a.base, true
}

// Allocate returns the stable virtual address of domain, allocating one when
// the name is seen for the first time. It returns an error when the range is
// exhausted.
func (a *allocator) Allocate(domainName string) (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if addr, ok := a.byDomain[domainName]; ok {
		return addr, nil
	}
	// Host offsets 2..maxOff-1 are available: 1 is the device, maxOff is the
	// broadcast address of the range.
	first, last := uint32(reservedOffset+1), a.maxOff-1
	total := last - first + 1
	off := a.next
	if off < first || off > last {
		off = first
	}
	for i := uint32(0); i < total; i++ {
		candidate := off + i
		if candidate > last {
			candidate = first + (candidate - last - 1)
		}
		addr := a.addrOf(candidate)
		if _, taken := a.byAddr[addr]; taken {
			continue
		}
		a.byDomain[domainName] = addr
		a.byAddr[addr] = domainName
		a.next = candidate + 1
		return addr, nil
	}
	return netip.Addr{}, fmt.Errorf("virtual range %s is exhausted", a.prefix)
}

// Lookup returns the address already mapped to domainName without allocating.
func (a *allocator) Lookup(domainName string) (netip.Addr, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	addr, ok := a.byDomain[domainName]
	return addr, ok
}

// Ensure returns the existing mapping of domainName or allocates one when the
// name is not in the table yet.
func (a *allocator) Ensure(domainName string) (netip.Addr, error) {
	if addr, ok := a.Lookup(domainName); ok {
		return addr, nil
	}
	return a.Allocate(domainName)
}

// Preallocate fills the table for the served names so a name is already
// resolvable before its first query. Existing mappings are left untouched.
func (a *allocator) Preallocate(domainNames []string) (int, error) {
	mapped := 0
	for _, name := range domainNames {
		if _, ok := a.Lookup(name); ok {
			mapped++
			continue
		}
		if _, err := a.Allocate(name); err != nil {
			return mapped, fmt.Errorf("%s: %w", name, err)
		}
		mapped++
	}
	return mapped, nil
}

// DomainOf resolves a virtual address back to the name it was allocated for.
func (a *allocator) DomainOf(addr netip.Addr) (string, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	d, ok := a.byAddr[addr]
	return d, ok
}

// Len reports how many names are currently mapped.
func (a *allocator) Len() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.byDomain)
}

// PurgeDomain drops the mapping of domainName and of every subdomain of it, and
// returns the names that were removed. A later add starts from a fresh address
// instead of inheriting the one the deleted rule used.
func (a *allocator) PurgeDomain(domainName string) []string {
	domainName = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domainName)), ".")
	a.mu.Lock()
	defer a.mu.Unlock()
	removed := make([]string, 0, 4)
	for name, addr := range a.byDomain {
		if name == domainName || strings.HasSuffix(name, "."+domainName) {
			delete(a.byDomain, name)
			delete(a.byAddr, addr)
			removed = append(removed, name)
		}
	}
	return removed
}

// Prune drops the mapping of every name the keep predicate rejects, which is
// how a file reload removes names that are no longer served.
func (a *allocator) Prune(keep func(string) bool) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for name, addr := range a.byDomain {
		if keep(name) {
			continue
		}
		delete(a.byDomain, name)
		delete(a.byAddr, addr)
		n++
	}
	return n
}

// PurgeAll empties both tables. The next allocation starts at the first usable
// host again, which is what clearing the list means.
func (a *allocator) PurgeAll() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := len(a.byDomain)
	a.byDomain = make(map[string]netip.Addr)
	a.byAddr = make(map[netip.Addr]string)
	a.next = reservedOffset + 1
	return n
}
