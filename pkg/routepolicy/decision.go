// Package routepolicy holds the values the routing half of a data path must
// pass along the plugin chain, and later the installer that turns them into
// kernel state.
//
// Three plugins decide the same kind of thing - "these destinations are mine,
// send them to this table and this gateway" - and each used to keep that in
// private fields with private names. Once they share one implementation, a
// downstream reader has to be able to tell whose decision it is holding, so the
// values live here as one named struct and travel through pkg/pipeline under
// the plugin's own tag.
package routepolicy

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/ersonw/mosdns-v4/pkg/pipeline"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
)

// Decision is one plugin's routing answer for one query.
//
// Every field is the value the kernel side actually needs, not a plugin
// specific alias: a mark without its table, or a next hop without its device,
// cannot be applied on its own. Keeping them together is what lets the
// installer and the log speak about the same object.
type Decision struct {
	// Mark is the fwmark that selects the table. Zero means the decision is
	// carried by a source rule instead of a mark.
	Mark uint32
	// NFTable owns the nft set and chains that apply the mark, when the
	// decision uses one.
	NFTable string
	// Table is the routing table the marked or sourced traffic looks up.
	Table string
	// Priority is the `ip rule` priority that points at Table.
	Priority int
	// NextHop and Dev describe where that table sends the traffic. NextHop may
	// be empty when the device alone decides the route.
	NextHop string
	Dev     string
	// Source is the address the socket must leave from, when one is pinned.
	Source netip.Addr
}

// DecisionKey is the slot a decision is stored under. There is exactly one
// routing decision per plugin per query, so the owner in the store is what
// separates a fake ip range from an asn prefix on the same chain.
var DecisionKey = pipeline.NewKey[Decision]("routepolicy.decision")

// SetDecision records owner's decision for this query.
func SetDecision(ctx *query_context.Context, owner pipeline.Owner, d Decision) {
	pipeline.Set(ctx, DecisionKey, owner, d)
}

// DecisionFor returns the decision owner recorded, if any.
func DecisionFor(ctx *query_context.Context, owner pipeline.Owner) (Decision, bool) {
	return pipeline.Get(ctx, DecisionKey, owner)
}

// Decisions returns every decision recorded for this query, keyed by plugin
// tag. A log line built from this table names who decided what instead of
// letting the last write win in silence.
func Decisions(ctx *query_context.Context) map[pipeline.Owner]Decision {
	return pipeline.Snapshot(ctx, DecisionKey)
}

// String is the log form of a decision. It is deliberately verbose: the point
// of the value is that a reader can tell two decisions apart.
func (d Decision) String() string {
	mark := "none"
	if d.Mark != 0 {
		mark = "0x" + strconv.FormatUint(uint64(d.Mark), 16)
	}
	via := d.NextHop
	if via == "" {
		via = "device only"
	}
	src := "host address"
	if d.Source.IsValid() {
		src = d.Source.String()
	}
	return fmt.Sprintf("mark=%s nft_table=%s table=%s prio=%d via=%s dev=%s source=%s",
		mark, orNone(d.NFTable), orNone(d.Table), d.Priority, via, orNone(d.Dev), src)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
