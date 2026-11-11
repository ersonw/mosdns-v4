package fakeipnat

// This file builds the SNAT rules for the tun outlet with no proxy configured.
// The outlet opens brand new host sockets, and on linux their source address is
// bound to the first host of the range so the `ip rule from <range>` can steer
// them into the dedicated routing table. Routing picks the gateway before the
// packet leaves, so the source rewrite in postrouting does not disturb it:
//
//	route lookup:  source 198.18.0.1  ->  ip rule  ->  table -> next_hop
//	postrouting:   source 198.18.0.1  ->  masquerade  ->  host address
//
// Without the rewrite the packet would leave the physical interface still
// carrying a 198.18.x.x source, which the upstream gateway usually drops.

// tunSNATTableName is the nft table owned by the tun outlet. It is separate from
// the DNAT table of the nft data path so the two never delete each other's
// rules when both are configured at different times.
func (p *FakeIPNatPlugin) tunSNATTableName() string {
	return p.tablePrefix + "_tun_snat"
}

// tunSNATPlan is the command line that installs the postrouting rewrite. Pure
// data, so the rule text can be asserted without running nft.
func tunSNATPlan(table, dev, cidr string) [][]string {
	if dev == "" || cidr == "" {
		return nil
	}
	return [][]string{
		// A stale table from a previous run would keep old rules alive; drop it
		// first so the installed rule always matches the current config.
		{"delete", "table", "ip", table},
		{"add", "table", "ip", table},
		{"add", "chain", "ip", table, "postrouting", "{ type nat hook postrouting priority 100; policy accept; }"},
		{"add", "rule", "ip", table, "postrouting", "oifname", dev, "ip", "saddr", cidr, "masquerade"},
	}
}
