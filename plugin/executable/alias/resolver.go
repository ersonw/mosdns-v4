package alias

// resolver.go resolves a name at connection time through another plugin (a
// forward or a sequence). It must not lead back into this plugin, otherwise the
// answer would be one of its own virtual addresses.
//
// It is kept apart from egress.go, which now only decides the outlet: the two
// concerns have nothing in common but the file they used to live in.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/executable_seq"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/miekg/dns"
)

const (
	resolveTimeout = 5 * time.Second
	resolvedTTL    = 5 * time.Minute
)

// resolver resolves a name at connection time through another plugin (a forward
// or a sequence). It must not lead back into this plugin, otherwise the answer
// would be one of its own virtual addresses.
type resolver struct {
	tag    string
	parent *coremain.BP

	mu    sync.Mutex
	cache map[string]resolvedEntry
}

type resolvedEntry struct {
	addr netip.Addr
	at   time.Time
}

var errNoResolvedAddress = errors.New("no address resolved")

func (r *resolver) lookup(ctx context.Context, name string) (netip.Addr, error) {
	if r == nil {
		return netip.Addr{}, errNoResolvedAddress
	}
	r.mu.Lock()
	if r.cache == nil {
		r.cache = make(map[string]resolvedEntry, 64)
	}
	if e, ok := r.cache[name]; ok && time.Since(e.at) < resolvedTTL {
		r.mu.Unlock()
		return e.addr, nil
	}
	r.mu.Unlock()

	addr, err := r.query(ctx, name, dns.TypeA)
	if err != nil {
		addr, err = r.query(ctx, name, dns.TypeAAAA)
	}
	if err != nil {
		return netip.Addr{}, err
	}
	r.mu.Lock()
	r.cache[name] = resolvedEntry{addr: addr, at: time.Now()}
	r.mu.Unlock()
	return addr, nil
}

// PurgeDomain drops cached addresses of domain and its subdomains, so a name
// that was just removed or re-added is resolved again on the next connection.
func (r *resolver) PurgeDomain(domainName string) {
	if r == nil {
		return
	}
	domainName = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domainName)), ".")
	r.mu.Lock()
	defer r.mu.Unlock()
	for name := range r.cache {
		if name == domainName || strings.HasSuffix(name, "."+domainName) {
			delete(r.cache, name)
		}
	}
}

// Clear drops every cached address.
func (r *resolver) Clear() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.cache = make(map[string]resolvedEntry, 64)
	r.mu.Unlock()
}

func (r *resolver) query(ctx context.Context, name string, qtype uint16) (netip.Addr, error) {
	m := r.parent.M()
	if m == nil {
		return netip.Addr{}, fmt.Errorf("resolver %q: no mosdns instance", r.tag)
	}
	exec := m.GetExecutables()[r.tag]
	if exec == nil {
		return netip.Addr{}, fmt.Errorf("resolver plugin %q not found", r.tag)
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	q.RecursionDesired = true
	qCtx := query_context.NewContext(q, nil)
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	if err := executable_seq.ExecChainNode(ctx, qCtx, executable_seq.WrapExecutable(exec)); err != nil {
		return netip.Addr{}, fmt.Errorf("resolver %q: %w", r.tag, err)
	}
	resp := qCtx.R()
	if resp == nil {
		return netip.Addr{}, fmt.Errorf("resolver %q returned no answer", r.tag)
	}
	if resp.Rcode != dns.RcodeSuccess {
		return netip.Addr{}, fmt.Errorf("resolver %q: rcode %s", r.tag, dns.RcodeToString[resp.Rcode])
	}
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if addr, err := netip.ParseAddr(v.A.String()); err == nil {
				return addr, nil
			}
		case *dns.AAAA:
			if addr, err := netip.ParseAddr(v.AAAA.String()); err == nil {
				return addr, nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("%w: %s", errNoResolvedAddress, name)
}

// resolveForDial turns a served name into a dialable address on the direct
// outlet.
func (p *plugin) resolveForDial(ctx context.Context, name string) (netip.Addr, error) {
	if p.resolve == nil {
		return netip.Addr{}, fmt.Errorf("resolver is not configured, cannot resolve %s for the direct outlet", name)
	}
	return p.resolve.lookup(ctx, name)
}
