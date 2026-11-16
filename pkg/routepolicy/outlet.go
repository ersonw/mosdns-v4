package routepolicy

import (
	"fmt"
	"sync"

	"github.com/ersonw/mosdns-v4/pkg/egress"
)

// Outlet is one shared exit another plugin can borrow instead of configuring
// its own next hop and proxy.
//
// The decision it publishes names the mark, table, priority and route the exit
// installed, so a borrower can tell the reader who owns what. It carries no
// secret: the proxy URL stays inside the owning plugin, and only its host is
// exposed, which is what a borrower needs to keep its own marking off the
// socket that reaches the proxy.
type Outlet interface {
	OutletTag() string
	OutletDecision() Decision
	OutletDialer() egress.Dialer
	OutletProxyHost() string
}

var (
	outletMu    sync.RWMutex
	outletByTag = make(map[string]Outlet)
)

// RegisterOutlet publishes o under its tag. A second plugin on the same tag is
// a configuration mistake: the borrower would take whichever won the race.
func RegisterOutlet(o Outlet) error {
	if o == nil || o.OutletTag() == "" {
		return fmt.Errorf("route outlet has no tag")
	}
	outletMu.Lock()
	defer outletMu.Unlock()
	if held, ok := outletByTag[o.OutletTag()]; ok && held != o {
		return fmt.Errorf("route outlet %q is already registered", o.OutletTag())
	}
	outletByTag[o.OutletTag()] = o
	return nil
}

// UnregisterOutlet removes tag's outlet. It is called from Close, so a tag can
// be reused after a plugin is torn down.
func UnregisterOutlet(tag string) {
	outletMu.Lock()
	defer outletMu.Unlock()
	delete(outletByTag, tag)
}

// OutletFor returns the outlet registered under tag.
func OutletFor(tag string) (Outlet, bool) {
	outletMu.RLock()
	defer outletMu.RUnlock()
	o, ok := outletByTag[tag]
	return o, ok
}

// Outlets returns every registered outlet, keyed by tag, for diagnostics.
func Outlets() map[string]Outlet {
	outletMu.RLock()
	defer outletMu.RUnlock()
	out := make(map[string]Outlet, len(outletByTag))
	for tag, o := range outletByTag {
		out[tag] = o
	}
	return out
}
