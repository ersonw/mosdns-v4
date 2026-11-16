package routepolicy

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Destination marking belongs to the exit, not to the data path that resolves
// the names.
//
// One exit already owns the mark, the table and the rule that point marked
// traffic somewhere. Which destinations carry that mark used to be a private
// detail of each data-plane plugin, which meant the same kernel decision was
// written twice and neither copy could be read back as one object. The set
// below moves the remaining half to the exit as well: a data path maps a name
// to an address and registers it, and the exit does the marking.
//
// The installer owns no route and no rule; those stay with Installer so the
// two halves of one decision can still be installed separately.

// NFTInstaller writes the destination set and the marking chains of one exit.
// It never creates or deletes the nft table itself: the table may also hold
// the objects of the plugin that owns the destinations, and removing it would
// take those with it.
type NFTInstaller struct {
	runner Runner
}

// NewNFTInstaller returns an installer that reaches nft through r.
func NewNFTInstaller(r Runner) *NFTInstaller { return &NFTInstaller{runner: r} }

// nftName turns an owner tag into a name nft accepts. Tags are free-form in the
// configuration, nft identifiers are not.
func nftName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// DestSetName is the set an exit keeps its registered destinations in.
func DestSetName(owner string) string {
	return "dest_" + nftName(owner)
}

func preChainName(owner string) string { return "mark_pre_" + nftName(owner) }
func outChainName(owner string) string { return "mark_out_" + nftName(owner) }

// EnsureDestSet recreates the marking objects of one exit.
//
// Recreating instead of probing one by one is what keeps a crashed process from
// leaving a second copy of the same rule behind, which would mark a packet
// twice for no reason. Destinations are re-registered by their owner after a
// restart anyway, so an empty set is the correct starting point.
//
// exclude is the source range of the borrower. Its own outlet sockets bind
// inside that range, and marking them would send the socket that carries the
// traffic back into the path it came from. An invalid prefix disables the
// exclusion.
func (n *NFTInstaller) EnsureDestSet(ctx context.Context, owner string, d Decision, exclude netip.Prefix) (string, error) {
	if d.Mark == 0 || d.NFTable == "" {
		return "", fmt.Errorf("destination set needs a mark and an nft table, %s has neither", d)
	}
	table := d.NFTable
	set := DestSetName(owner)
	mark := strconv.FormatUint(uint64(d.Mark), 10)

	setup := []struct {
		args     []string
		tolerate bool
	}{
		{args: []string{"add", "table", "ip", table}, tolerate: true},
		{args: []string{"delete", "chain", "ip", table, preChainName(owner)}, tolerate: true},
		{args: []string{"delete", "chain", "ip", table, outChainName(owner)}, tolerate: true},
		{args: []string{"delete", "set", "ip", table, set}, tolerate: true},
		// The timeout keeps the set from growing forever: an address nobody
		// refreshes expires on its own, so there is no sweep loop to maintain.
		{args: []string{"add", "set", "ip", table, set,
			"{ type ipv4_addr; flags timeout; timeout 1h; }"}},
		// Priority 0 puts the mark after the DNAT chain: in fake-ip mode the
		// destination is the real address by then, so one set serves both data
		// planes. The route lookup of a forwarded packet happens after the
		// prerouting hook returns, so a mark set here still decides the route.
		{args: []string{"add", "chain", "ip", table, preChainName(owner),
			"{ type filter hook prerouting priority 0; policy accept; }"}},
		{args: []string{"add", "chain", "ip", table, outChainName(owner),
			"{ type route hook output priority 0; policy accept; }"}},
	}

	for _, cmd := range setup {
		if _, err := n.runner.Run(ctx, "nft", cmd.args...); err != nil && !cmd.tolerate {
			return "", fmt.Errorf("nft %s: %w", strings.Join(cmd.args, " "), err)
		}
	}

	for _, chain := range []string{preChainName(owner), outChainName(owner)} {
		args := []string{"add", "rule", "ip", table, chain, "ip", "daddr", "@" + set}
		if exclude.IsValid() {
			args = append(args, "ip", "saddr", "!=", exclude.String())
		}
		args = append(args, "meta", "mark", "set", mark)
		if _, err := n.runner.Run(ctx, "nft", args...); err != nil {
			return "", fmt.Errorf("nft %s: %w", strings.Join(args, " "), err)
		}
	}
	return set, nil
}

// AddDestinations registers addresses in the exit's set.
func (n *NFTInstaller) AddDestinations(ctx context.Context, table, set string, ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	element := "{ " + strings.Join(ips, ", ") + " }"
	if _, err := n.runner.Run(ctx, "nft", "add", "element", "ip", table, set, element); err != nil {
		return fmt.Errorf("nft add element %s %s: %w", table, set, err)
	}
	return nil
}

// RemoveDestSet drops the chains and the set of one exit. The table stays: it
// may hold the objects of the plugin that owns the destinations.
func (n *NFTInstaller) RemoveDestSet(ctx context.Context, owner, table string) {
	if table == "" {
		return
	}
	for _, chain := range []string{preChainName(owner), outChainName(owner)} {
		_, _ = n.runner.Run(ctx, "nft", "delete", "chain", "ip", table, chain)
	}
	_, _ = n.runner.Run(ctx, "nft", "delete", "set", "ip", table, DestSetName(owner))
}
