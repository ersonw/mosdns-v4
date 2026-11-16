package routepolicy

import (
	"fmt"
	"sort"
	"strconv"
	"sync"
)

// Claim is one plugin's request to own a piece of the kernel routing state.
//
// The three plugins install overlapping shapes: a mark that selects a table,
// or a source rule that selects one directly. Two plugins that claim the same
// mark, or the same table at the same priority, do not fail loudly on their
// own - the kernel accepts both rules and the second one merely stops being
// reachable - so a claim is recorded here first and a conflict is reported
// while it can still be attributed.
type Claim struct {
	// Owner is the plugin tag. It is the identity that reaches the error and
	// the log, so "which plugin owns table 100" always has an answer.
	Owner string
	// Mark is the fwmark that selects Table. Zero means the plugin routes by
	// source address instead.
	Mark uint32
	// Table is the routing table the plugin writes.
	Table string
	// Priority is the ip rule priority that points at Table.
	Priority int
}

// Key is what uniqueness is enforced on: a mark on its own when the plugin
// routes by mark, otherwise the table and priority pair a source rule uses.
func (c Claim) Key() string {
	if c.Mark != 0 {
		return "mark:" + strconv.FormatUint(uint64(c.Mark), 16)
	}
	return "rule:" + c.Table + ":" + strconv.Itoa(c.Priority)
}

// String is the log form of a claim.
func (c Claim) String() string {
	if c.Mark != 0 {
		return fmt.Sprintf("mark=0x%s table=%s prio=%d", strconv.FormatUint(uint64(c.Mark), 16), orNone(c.Table), c.Priority)
	}
	return fmt.Sprintf("rule table=%s prio=%d", orNone(c.Table), c.Priority)
}

// Registry records which plugin owns which routing object.
//
// It is a process level guard, not a request value: a conflict here is a
// configuration mistake that must be visible before any traffic moves, which
// is why it fails startup instead of being written to a per query slot.
type Registry struct {
	mu     sync.Mutex
	owners map[string]Claim
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{owners: make(map[string]Claim)}
}

var defaultRegistry = NewRegistry()

// Default returns the registry shared by the plugins in this process.
func Default() *Registry { return defaultRegistry }

// Claim records c. Re-claiming the same object by the same owner is accepted,
// because a plugin that restarts re-installs what it already owned. A different
// owner on the same object is an error naming both, so the log points at the
// configuration that has to change.
func (r *Registry) Claim(c Claim) error {
	if c.Owner == "" {
		return fmt.Errorf("route claim %s has no owner", c)
	}
	if c.Table == "" && c.Mark == 0 {
		return fmt.Errorf("route claim by %s names neither a mark nor a table", c.Owner)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	key := c.Key()
	if held, ok := r.owners[key]; ok && held.Owner != c.Owner {
		return fmt.Errorf("route claim %s is already held by %s, %s cannot take it: "+
			"two plugins that write the same object cannot be told apart at runtime",
			c, held.Owner, c.Owner)
	}
	r.owners[key] = c
	return nil
}

// Release drops every claim held by owner, for the path where a plugin shuts
// down and its kernel objects are removed.
func (r *Registry) Release(owner string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, held := range r.owners {
		if held.Owner == owner {
			delete(r.owners, key)
		}
	}
}

// Claims returns every claim, ordered by owner then key, so startup logging can
// print a stable table of who owns what.
func (r *Registry) Claims() []Claim {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Claim, 0, len(r.owners))
	for _, held := range r.owners {
		out = append(out, held)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Owner != out[j].Owner {
			return out[i].Owner < out[j].Owner
		}
		return out[i].Key() < out[j].Key()
	})
	return out
}
