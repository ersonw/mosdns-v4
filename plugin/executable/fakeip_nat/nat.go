package fakeipnat

// This file implements the NAT side of the plugin. It replaces the external
// nat_map.py helper: the plugin itself keeps the nftables DNAT map in sync
// with the fake ip it handed out, picks a reachable real ip among the
// candidates, writes host routes into the configured table and re-aggregates
// the /32 routes into strict CIDR blocks.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	nftMapName       = "dnat_map"
	candidateLimit   = 15 // how many recent real ips are considered per domain
	probeConcurrency = 10 // parallel reachability probes
	probeTimeout     = time.Second
	pingTimeout      = 3 * time.Second
	commandTimeout   = 10 * time.Second
	natTimeout       = 30 * time.Second
	// natSyncWait bounds how long a DNS query waits for the DNAT entry. It is
	// shorter than natTimeout on purpose: a client that waits too long retries
	// or times out, and a late mapping is still installed for the next query.
	natSyncWait = 3 * time.Second
	// routeAggInterval is how often the NAT data path scans the routing table
	// and folds the host routes that point at the outlet into CIDR blocks. It
	// is a periodic scan rather than a per-write debounce: routes written before
	// a restart, or by a resolution that already left memory, are folded too.
	routeAggInterval = 30 * time.Second
	// knownRealIPLimit caps the addresses read back from sqlite when a route
	// sweep needs to recognise the prefixes this plugin owns.
	knownRealIPLimit = 20000
)

// nftElementRe extracts "fake : real" pairs from `nft list map` output.
var nftElementRe = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

// cmdRunner runs one external command. It exists so nat_test.go can assert on
// the exact nft / ip command sequence without touching the host.
type cmdRunner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	runCtx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	out, err := exec.CommandContext(runCtx, name, args...).CombinedOutput()
	return string(out), err
}

// commandMissing reports whether err says the executable itself was not found.
// On a router that usually means the service PATH has no /usr/sbin, which turns
// every cleanup into a silent no-op, so the caller has to say it out loud.
func commandMissing(err error) bool {
	var execErr *exec.Error
	return errors.As(err, &execErr)
}

func (p *FakeIPNatPlugin) nftTableName() string {
	return "fakeip_" + p.tablePrefix
}

// syncNAT brings the kernel side in sync with the fake ip of one domain.
// It is the Go port of nat_map.py: same table layout, same command sequence.
func (p *FakeIPNatPlugin) syncNAT(ctx context.Context, fakeIP, domain, latestIPs string) bool {
	ctx, cancel := context.WithTimeout(ctx, natTimeout)
	defer cancel()

	// One nft map and one route table are shared by every domain, so the whole
	// sequence is serialized instead of interleaving element writes.
	p.natMu.Lock()
	defer p.natMu.Unlock()

	hop, dev := p.nextHop, p.nextHopDev
	if hop == "" && dev == "" {
		hop, dev = p.systemDefaultRoute(ctx)
	}
	p.L().Debug("fakeip nat: syncing nat mapping",
		zap.String("domain", domain), zap.String("fake_ip", fakeIP),
		zap.String("next_hop", hop), zap.String("next_hop_dev", dev),
		zap.String("route_table", p.routeTable))

	table := p.nftTableName()
	if err := p.ensureNFTTable(ctx, table, dev); err != nil {
		// Without the table an element write has nowhere to go, so leaving
		// host routes behind would only mask the failure.
		p.L().Error("nft table is not ready, nat mapping skipped", zap.String("nft_table", table), zap.Error(err))
		return false
	}

	// Fast path: keep an existing mapping that still works, which is what
	// prevents churn on every re-resolution of the same domain.
	current := p.nftMappings(ctx, table)[fakeIP]
	if p.isFakeAddrString(current) {
		// A mapping that points at a fake ip can only fail: drop it so the
		// candidate selection below replaces it.
		p.L().Warn("nat mapping points at a fake ip, replacing it",
			zap.String("fake_ip", fakeIP), zap.String("real_ip", current))
		current = ""
	}
	if current != "" {
		p.applyHostRoute(ctx, current, hop, dev)
		if p.probe(ctx, current) {
			p.L().Debug("existing nat mapping still reachable, keep it",
				zap.String("fake_ip", fakeIP), zap.String("real_ip", current))
			return true
		}
		p.L().Info("existing nat mapping unreachable, selecting a new real ip",
			zap.String("fake_ip", fakeIP), zap.String("old_real_ip", current))
	}

	candidates := parseCandidateIPs(latestIPs)
	if len(candidates) == 0 {
		ips, err := p.dbCandidates(ctx, domain)
		if err != nil {
			p.L().Warn("load candidate real ips from sqlite failed", zap.String("domain", domain), zap.Error(err))
		}
		candidates = ips
	}
	// An upstream that answered with one of this plugin's own fake addresses
	// must never become the DNAT target: the kernel would rewrite the request
	// to an address that only exists here.
	kept, fake := p.realCandidates(candidates)
	if len(fake) > 0 {
		p.L().Warn("candidate real ips inside the fake range were dropped",
			zap.String("domain", domain), zap.Strings("fake_ips", fake))
	}
	candidates = kept
	if len(candidates) == 0 {
		p.L().Warn("no candidate real ip, nat mapping skipped",
			zap.String("fake_ip", fakeIP), zap.String("domain", domain))
		return false
	}

	// The probes need a route for each candidate, so warm the top ones first.
	warm := len(candidates)
	if warm > 5 {
		warm = 5
	}
	for _, ip := range candidates[:warm] {
		p.applyHostRoute(ctx, ip, hop, dev)
	}

	selected := p.selectReachable(ctx, candidates)
	if selected == "" {
		selected = candidates[0]
		p.L().Warn("all candidate real ips are unreachable, fallback to the first one",
			zap.String("fake_ip", fakeIP), zap.String("real_ip", selected))
	}

	if current != "" {
		if _, err := p.runner.Run(ctx, "nft", "delete", "element", "ip", table, nftMapName, "{ "+fakeIP+" }"); err != nil {
			p.L().Debug("delete stale nat element failed", zap.String("fake_ip", fakeIP), zap.Error(err))
		}
	}
	if _, err := p.runner.Run(ctx, "nft", "add", "element", "ip", table, nftMapName, "{ "+fakeIP+" : "+selected+" }"); err != nil {
		p.L().Error("write nat mapping failed",
			zap.String("fake_ip", fakeIP), zap.String("real_ip", selected), zap.Error(err))
		return false
	}
	p.applyHostRoute(ctx, selected, hop, dev)

	// No collapse here: the periodic scan folds every managed host route, so
	// one resolution never rewrites the table and a burst still ends up
	// aggregated.

	p.L().Info("nat mapping updated",
		zap.String("fake_ip", fakeIP), zap.String("real_ip", selected),
		zap.String("domain", domain), zap.String("route_table", p.routeTable))
	return true
}

// ensureNFTTable creates the table, the dnat map and the three chains the
// python version used. An existing table is left untouched.
func (p *FakeIPNatPlugin) ensureNFTTable(ctx context.Context, table, dev string) error {
	if dump, err := p.runner.Run(ctx, "nft", "list", "table", "ip", table); err == nil {
		if nftTableMatchesConfig(dump, p.cidr, dev, p.mssClamp) {
			p.L().Debug("fakeip nat: nft table already present", zap.String("nft_table", table))
			return nil
		}
		// The table is the one an earlier build left behind: its rules may
		// reach further than this configuration does (an unconditional
		// "oifname X masquerade" being the typical one). Reusing it would keep
		// that behaviour alive, so it is rebuilt from scratch.
		p.L().Info("fakeip nat: rebuilding the nft table so its rules match the configuration",
			zap.String("nft_table", table))
		if _, derr := p.runner.Run(ctx, "nft", "delete", "table", "ip", table); derr != nil {
			return fmt.Errorf("delete the mismatched nft table: %w", derr)
		}
	}

	setup := [][]string{
		{"add", "table", "ip", table},
		{"add", "map", "ip", table, nftMapName, "{ type ipv4_addr : ipv4_addr; }"},
		{"add", "chain", "ip", table, "prerouting", "{ type nat hook prerouting priority -100; policy accept; }"},
		{"add", "rule", "ip", table, "prerouting", "ip", "daddr", p.cidr, "dnat", "to", "ip", "daddr", "map", "@" + nftMapName},
		{"add", "chain", "ip", table, "forward", "{ type filter hook forward priority -10; policy accept; }"},
		{"add", "rule", "ip", table, "forward", "ip", "daddr", p.cidr, "drop"},
		{"add", "chain", "ip", table, "postrouting", "{ type nat hook postrouting priority 100; policy accept; }"},
	}
	if dev != "" {
		// Only the connections this table rewrote are masqueraded. A bare
		// "oifname <dev> masquerade" also matches every other flow leaving that
		// interface - the host's own traffic and whatever another firewall rule
		// set up - and silently SNATs it.
		setup = append(setup, []string{"add", "rule", "ip", table, "postrouting",
			"ct", "status", "dnat", "masquerade"})
	}
	if p.mssClamp > 0 {
		mss := fmt.Sprint(p.mssClamp)
		setup = append(setup,
			// The mangle hook runs before the NAT chain (priority -100), so the
			// client's SYN still carries the fake destination address here.
			[]string{"add", "chain", "ip", table, "mss_clamp", "{ type filter hook prerouting priority mangle; policy accept; }"},
			[]string{"add", "rule", "ip", table, "mss_clamp", "ip", "daddr", p.cidr,
				"tcp", "flags", "syn", "tcp", "option", "maxseg", "size", "set", mss},
			// The server's SYN-ACK arrives already DNATed, so match it through
			// conntrack instead of the destination address.
			[]string{"add", "rule", "ip", table, "mss_clamp", "ct", "status", "dnat",
				"tcp", "flags", "syn", "tcp", "option", "maxseg", "size", "set", mss},
		)
	}

	p.L().Debug("fakeip nat: creating nft table",
		zap.String("nft_table", table), zap.String("egress_dev", dev), zap.Int("commands", len(setup)))
	for _, args := range setup {
		if _, err := p.runner.Run(ctx, "nft", args...); err != nil {
			p.L().Debug("fakeip nat: nft setup command failed",
				zap.Strings("cmd", args), zap.String("nft_table", table), zap.Error(err))
			return fmt.Errorf("nft %s: %w", strings.Join(args, " "), err)
		}
	}
	p.L().Info("nft table created", zap.String("nft_table", table), zap.String("egress_dev", dev))
	return nil
}

// nftTableMatchesConfig reports whether an existing nft table already carries
// the rules this configuration needs. A table from an older build can be
// narrower or wider than the current shape - the postrouting rewrite is the one
// that changed from "oifname <dev> masquerade" to "ct status dnat masquerade" -
// and reusing it would silently keep the old scope. An empty dump proves
// nothing, so it counts as a match.
func nftTableMatchesConfig(dump, cidr, dev string, mssClamp int) bool {
	if strings.TrimSpace(dump) == "" {
		return true
	}
	if !strings.Contains(dump, "dnat to ip daddr map @") {
		return false
	}
	if !strings.Contains(dump, "ip daddr "+cidr+" drop") {
		return false
	}
	masquerades := 0
	for _, line := range strings.Split(dump, "\n") {
		if !strings.Contains(line, "masquerade") {
			continue
		}
		masquerades++
		if !strings.Contains(line, "ct status dnat") {
			return false
		}
	}
	wantMasquerades := 0
	if dev != "" {
		wantMasquerades = 1
	}
	if masquerades != wantMasquerades {
		return false
	}
	if mssClamp > 0 && !strings.Contains(dump, fmt.Sprintf("maxseg size set %d", mssClamp)) {
		return false
	}
	return true
}

// nftMappings reads the whole dnat map: fake ip -> real ip.
func (p *FakeIPNatPlugin) nftMappings(ctx context.Context, table string) map[string]string {
	out, err := p.runner.Run(ctx, "nft", "list", "map", "ip", table, nftMapName)
	if err != nil {
		// A missing table is handled by ensureNFTTable; keep the raw failure
		// available for diagnosis without escalating the level.
		p.L().Debug("fakeip nat: list nft map failed", zap.String("nft_table", table), zap.Error(err))
		return nil
	}
	mappings := parseNFTMappings(out)
	p.L().Debug("fakeip nat: nft map loaded",
		zap.String("nft_table", table), zap.Int("entries", len(mappings)))
	return mappings
}

func parseNFTMappings(out string) map[string]string {
	mappings := make(map[string]string)
	for _, match := range nftElementRe.FindAllStringSubmatch(out, -1) {
		mappings[match[1]] = match[2]
	}
	return mappings
}

// applyHostRoute points a real ip at the egress gateway. Without next_hop and
// next_hop_dev there is nothing to steer, so the route is skipped.
func (p *FakeIPNatPlugin) applyHostRoute(ctx context.Context, ip, hop, dev string) {
	// Mark routing carries the mapped addresses as nft set members instead of
	// host routes. It is checked before the gateway: under marks the address
	// needs no route of its own, so an empty next_hop must not skip the write.
	if p.markActiveNow() {
		if err := p.markRealIP(ctx, ip); err == nil {
			// The mark is what routes this destination into the device, so the
			// device read loop has to recognise it as this plugin's own.
			if p.useTun {
				if addr, perr := netip.ParseAddr(ip); perr == nil {
					p.rememberRealDst(addr)
				}
			}
			p.L().Debug("fakeip nat: real ip marked for the dedicated table",
				zap.String("real_ip", ip), zap.String("route_table", p.routeTable))
			return
		} else {
			p.L().Warn("fakeip nat: marking the real ip failed, falling back to a host route",
				zap.String("real_ip", ip), zap.Error(err))
		}
	}
	if hop == "" && dev == "" {
		p.L().Debug("fakeip nat: host route skipped, no next hop and no device", zap.String("real_ip", ip))
		return
	}

	// Mark routing owns route_table, so a fallback host route goes to the table
	// unmarked traffic uses; writing it into the dedicated table would strand it.
	table := p.hostRouteTable()
	commands := routeWriteCommands(ip+"/32", hop, dev, table)
	if len(commands) == 0 {
		p.L().Debug("fakeip nat: host route skipped, platform has no usable route command",
			zap.String("real_ip", ip), zap.String("next_hop", hop), zap.String("dev", dev))
		return
	}
	for _, cmd := range commands {
		if _, err := p.runner.Run(ctx, cmd[0], cmd[1:]...); err != nil {
			p.L().Warn("apply host route failed",
				zap.String("real_ip", ip), zap.String("route_table", table), zap.Strings("cmd", cmd), zap.Error(err))
			return
		}
	}
	// The route exists now, so it also has to be on record: this row is what a
	// later stop, crash or reload deletes.
	p.rememberManagedRoute(ctx, ip+"/32", hop, dev)
	p.L().Debug("fakeip nat: host route applied",
		zap.String("real_ip", ip), zap.String("next_hop", hop), zap.String("dev", dev),
		zap.String("route_table", table))
}

// aggregateManagedRoutes folds every route that steers traffic to the
// configured gateway/device into CIDR blocks. The list is read from the
// kernel, the originals are kept verbatim, the aggregated blocks are installed
// first and the originals are deleted afterwards, so a packet never falls into
// the gap between the two passes.
func (p *FakeIPNatPlugin) aggregateManagedRoutes() {
	if p.markActiveNow() {
		// Mark routing keeps the mapped addresses out of the routing tables, so
		// there is nothing to fold and nothing to prune.
		p.L().Debug("route aggregation: mark routing owns the mapped addresses, scan skipped")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), natTimeout)
	defer cancel()

	hop, dev := p.nextHop, p.nextHopDev
	if hop == "" && dev == "" {
		hop, dev = p.systemDefaultRoute(ctx)
	}
	if hop == "" && dev == "" {
		p.L().Debug("route aggregation: no next hop and no device, scan skipped")
		return
	}

	original := p.listManagedRoutes(ctx, hop, dev)
	p.collapseManagedRoutes(ctx, original, hop, dev)
	// Aggregation alone only merges: a block whose addresses are no longer
	// resolved anywhere would stay forever. The prune pass drops exactly those,
	// so the table converges instead of growing with every expired answer.
	p.pruneManagedRoutes(ctx, hop, dev)
}

// pruneManagedRoutes deletes managed routes that no longer cover any address the
// plugin is responsible for. An empty known set (database and DNAT map both
// unreadable) skips the pass: deleting on missing evidence would tear down
// routes that are still in use.
func (p *FakeIPNatPlugin) pruneManagedRoutes(ctx context.Context, hop, dev string) {
	known := p.knownRealIPs(ctx)
	if len(known) == 0 {
		p.L().Debug("route prune: no known real ip, scan skipped")
		return
	}

	pruned := 0
	for _, prefix := range p.listManagedRoutes(ctx, hop, dev) {
		if !manageablePrefix(prefix) || prefixCoversAny(prefix, known) {
			continue
		}
		if p.foreignRoute(prefix) {
			continue
		}
		pruned += p.deleteManagedRoutes(ctx, []string{prefix})
	}
	if pruned > 0 {
		p.L().Info("fakeip nat: stale managed routes pruned", zap.Int("routes", pruned), zap.Int("known_real_ips", len(known)))
	}
}

// collapseManagedRoutes installs the aggregated blocks of the given route list
// first and deletes the originals afterwards, so no packet falls into the gap
// between the two passes.
func (p *FakeIPNatPlugin) collapseManagedRoutes(ctx context.Context, original []string, hop, dev string) {
	p.natMu.Lock()
	defer p.natMu.Unlock()

	if len(original) < 2 {
		p.L().Debug("route aggregation: fewer than two managed routes", zap.Int("routes", len(original)))
		return
	}

	prefixes := make([]netip.Prefix, 0, len(original))
	skipped := 0
	for _, route := range original {
		pfx, err := netip.ParsePrefix(route)
		if err != nil || !pfx.Addr().Is4() {
			skipped++
			continue
		}
		// A block wider than /8 cannot come from collapsing host routes; it
		// would merge unrelated space, so it stays out of the pass.
		if pfx.Bits() < 8 {
			skipped++
			continue
		}
		prefixes = append(prefixes, pfx)
	}
	if len(prefixes) < 2 {
		p.L().Debug("route aggregation: not enough collapsible routes",
			zap.Int("routes", len(prefixes)), zap.Int("skipped", skipped))
		return
	}

	collapsed := collapsePrefixes(prefixes)
	kept := make(map[string]struct{}, len(collapsed))
	for _, pfx := range collapsed {
		kept[pfx.String()] = struct{}{}
	}

	table := p.hostRouteTable()
	withTable := func(args []string) []string {
		if table != "" && table != "main" {
			return append(args, "table", table)
		}
		return args
	}

	// Install the aggregated blocks before deleting anything.
	added := 0
	for _, pfx := range collapsed {
		args := []string{"route", "replace", pfx.String()}
		if hop != "" {
			args = append(args, "via", hop)
		}
		if dev != "" {
			args = append(args, "dev", dev)
		}
		if _, err := p.runner.Run(ctx, "ip", withTable(args)...); err == nil {
			added++
			p.rememberManagedRoute(ctx, pfx.String(), hop, dev)
		}
	}

	// Then drop the originals, skipping the blocks the collapse reproduced
	// unchanged: deleting those would undo what the add pass just installed.
	deleted := 0
	for _, pfx := range prefixes {
		if _, ok := kept[pfx.String()]; ok {
			continue
		}
		args := []string{"route", "delete", pfx.String()}
		if _, err := p.runner.Run(ctx, "ip", withTable(args)...); err == nil {
			deleted++
			p.forgetManagedRoute(ctx, pfx.String())
		}
	}

	p.L().Debug("managed routes re-aggregated",
		zap.Int("before", len(prefixes)), zap.Int("skipped", skipped),
		zap.Int("after", len(collapsed)), zap.Int("added", added), zap.Int("deleted", deleted),
		zap.String("next_hop", hop), zap.String("dev", dev))
}

// deleteManagedRoutes removes the given prefixes from the routing table. It is
// the counterpart of collapseManagedRoutes: an aggregation pass replaces a
// batch of /32 with wider blocks, and the blocks themselves are what a stopped
// plugin has to remove again.
func (p *FakeIPNatPlugin) deleteManagedRoutes(ctx context.Context, prefixes []string) int {
	deleted := 0
	for _, prefix := range prefixes {
		commands := routeDeleteCommands(prefix, p.hostRouteTable())
		if len(commands) == 0 {
			continue
		}
		for _, cmd := range commands {
			if _, err := p.runner.Run(ctx, cmd[0], cmd[1:]...); err == nil {
				deleted++
			}
		}
		// Gone from the routing table means gone from the ledger too, so a
		// later sweep does not replay a delete that can no longer succeed.
		p.forgetManagedRoute(ctx, prefix)
	}
	return deleted
}

// cleanupDataPath removes everything the plugin installed: the managed host
// routes (the aggregated blocks included) and, on the fake-ip NAT path, the
// nft table. A stopped or reloaded plugin must not leave state behind, because
// the next process would inherit routes it never wrote.
func (p *FakeIPNatPlugin) cleanupDataPath() {
	ctx, cancel := context.WithTimeout(context.Background(), natTimeout)
	defer cancel()

	hop, dev := p.nextHop, p.nextHopDev
	if hop == "" && dev == "" {
		hop, dev = p.systemDefaultRoute(ctx)
	}

	// The policy rule and the default route of the dedicated table go before the
	// ledger sweep: they are two fixed objects, and leaving them behind would
	// keep steering traffic into a table that no longer has anywhere to send it.
	p.cleanupMarkRouting(ctx)

	p.natMu.Lock()
	defer p.natMu.Unlock()

	// The ledger is the exact record of what this plugin wrote, so it goes
	// first: those prefixes are removed even when the configuration changed and
	// the scan below no longer matches them.
	ledgerDeleted := p.sweepLedgerRoutes(ctx)

	// Only routes that cover an address this plugin is responsible for are
	// removed. A plain gateway/dev filter would also match routes the operator
	// configured by hand, and deleting those on shutdown would break the host.
	known := p.knownRealIPs(ctx)
	routesDeleted := 0
	if hop != "" || dev != "" {
		for _, prefix := range p.listManagedRoutes(ctx, hop, dev) {
			if !manageablePrefix(prefix) || !prefixCoversAny(prefix, known) {
				continue
			}
			if p.foreignRoute(prefix) {
				p.L().Debug("fakeip nat: cleanup left a route the ledger does not own",
					zap.String("prefix", prefix), zap.String("next_hop", hop), zap.String("dev", dev))
				continue
			}
			routesDeleted += p.deleteManagedRoutes(ctx, []string{prefix})
		}
	}

	// The table now carries the DNAT map, the mark set and the mark chains. On
	// the non-tun path nothing else owns it, so it goes away with the data path
	// whether the traffic was rewritten or merely marked.
	// The delete is attempted in tun mode too: the tun path creates no nft table,
	// so anything present was left by a short-lived non-tun run and its DNAT
	// chain would keep rewriting destinations behind the device's back.
	tableDeleted := false
	if _, err := p.runner.Run(ctx, "nft", "delete", "table", "ip", p.nftTableName()); err == nil {
		tableDeleted = true
	}

	p.L().Info("fakeip nat: data path cleaned up",
		zap.Int("ledger_deleted", ledgerDeleted), zap.Int("routes_deleted", routesDeleted),
		zap.Bool("nft_table_deleted", tableDeleted),
		zap.String("next_hop", hop), zap.String("dev", dev))
}

// knownRealIPs returns the real addresses this plugin is responsible for: the
// ones it routed in realip mode, or the DNAT targets of the fake-ip map.
func (p *FakeIPNatPlugin) knownRealIPs(ctx context.Context) []netip.Addr {
	// The database is the durable record: a route written by a previous process
	// covers an address that only the database still remembers, and without it a
	// startup sweep would see an empty set and delete nothing.
	known := make(map[netip.Addr]struct{})
	add := func(addr netip.Addr) {
		if addr.IsValid() && addr.Is4() && !p.isFakeAddr(addr) {
			known[addr] = struct{}{}
		}
	}
	if dbIPs, err := p.dbKnownRealIPs(ctx); err != nil {
		p.L().Debug("fakeip nat: load known real ips from sqlite failed", zap.Error(err))
	} else {
		for _, addr := range dbIPs {
			add(addr)
		}
	}

	if p.realIP {
		p.realMu.Lock()
		for ip := range p.realRoutes {
			if addr, err := netip.ParseAddr(ip); err == nil {
				add(addr)
			}
		}
		p.realMu.Unlock()
	} else if !p.useTun {
		for _, real := range p.nftMappings(ctx, p.nftTableName()) {
			// Only real targets matter for cleanup: a fake ip stored as the value
			// must not extend the set of prefixes the cleanup step may remove.
			if addr, err := netip.ParseAddr(real); err == nil {
				add(addr)
			}
		}
	}

	out := make([]netip.Addr, 0, len(known))
	for addr := range known {
		out = append(out, addr)
	}
	return out
}

// dbKnownRealIPs reads the addresses the plugin recorded while answering. The
// read is capped: a sweep only needs enough addresses to recognise its own
// prefixes, and an unbounded scan would stall startup on a large database.
func (p *FakeIPNatPlugin) dbKnownRealIPs(ctx context.Context) ([]netip.Addr, error) {
	rows, err := p.db.QueryContext(ctx,
		fmt.Sprintf("SELECT DISTINCT real_ip FROM %s LIMIT %d", p.ipTable, knownRealIPLimit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []netip.Addr
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if addr, err := netip.ParseAddr(raw); err == nil && addr.Is4() {
			out = append(out, addr)
		}
	}
	return out, rows.Err()
}

// prefixCoversAny reports whether the prefix contains at least one of the
// addresses. It keeps the cleanup step from touching unrelated routes.
func prefixCoversAny(prefix string, ips []netip.Addr) bool {
	pfx, err := netip.ParsePrefix(prefix)
	if err != nil || !pfx.Addr().Is4() {
		return false
	}
	for _, ip := range ips {
		if pfx.Contains(ip) {
			return true
		}
	}
	return false
}

// manageablePrefix narrows a scanned prefix to the shapes this plugin can have
// written: a host route, or a block produced by collapsing host routes, which
// never goes wider than /8. A hand-configured route such as 0.0.0.0/1 through
// the same gateway covers the same addresses but was not written here and has
// to stay.
func manageablePrefix(prefix string) bool {
	pfx, err := netip.ParsePrefix(prefix)
	if err != nil || !pfx.Addr().Is4() {
		return false
	}
	return pfx.Bits() >= 8
}

// syncRealRoutes installs a /32 host route for every real ip of a resolution
// and debounces the CIDR collapse. It is the whole data plane of realip mode:
// no fake ip is allocated and no DNAT element is written.
func (p *FakeIPNatPlugin) syncRealRoutes(ctx context.Context, ips []string) {
	ctx, cancel := context.WithTimeout(ctx, natTimeout)
	defer cancel()

	// Under marks the addresses only go into the nft set, so no gateway is
	// needed; resolving one would be a wasted call on the answer path.
	var hop, dev string
	if !p.markActiveNow() {
		// Resolved once and cached: this runs on every answer, and asking the
		// kernel for the default route each time is a process spawn per query.
		hop, dev = p.fallbackHopDev(ctx)
		if hop == "" && dev == "" {
			p.L().Debug("realip: no next hop and no device, routes not installed")
			return
		}
	}

	p.natMu.Lock()
	defer p.natMu.Unlock()

	applied := 0
	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() {
			continue
		}
		// A fake ip is not a real target: installing a host route for it would
		// add a route to an address the plugin already owns.
		if p.isFakeAddr(addr) {
			p.L().Debug("fakeip nat: fake ip skipped when installing real routes", zap.String("ip", addr.String()))
			continue
		}
		p.applyHostRoute(ctx, addr.String(), hop, dev)
		p.realMu.Lock()
		p.realRoutes[addr.String()] = struct{}{}
		p.realMu.Unlock()
		applied++
	}

	p.L().Info("realip routes updated",
		zap.Strings("real_ips", ips), zap.String("next_hop", hop), zap.String("dev", dev),
		zap.Int("applied", applied), zap.String("route_table", p.hostRouteTable()))
}

// selectReachable probes every candidate in parallel and returns the first
// reachable one in candidate order, which keeps the choice stable.
func (p *FakeIPNatPlugin) selectReachable(ctx context.Context, candidates []string) string {
	reachable := make([]bool, len(candidates))
	sem := make(chan struct{}, probeConcurrency)
	var wg sync.WaitGroup
	for i, ip := range candidates {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			reachable[i] = p.probe(ctx, ip)
		}(i, ip)
	}
	wg.Wait()

	for i, ok := range reachable {
		p.L().Debug("fakeip nat: candidate probe result",
			zap.String("real_ip", candidates[i]), zap.Bool("reachable", ok))
	}
	for i, ok := range reachable {
		if ok {
			p.L().Debug("fakeip nat: reachable real ip selected", zap.String("real_ip", candidates[i]))
			return candidates[i]
		}
	}
	return ""
}

// probeReachable mirrors the python check: TCP 443/80 first, ping as fallback.
func (p *FakeIPNatPlugin) probeReachable(ctx context.Context, ip string) bool {
	dialer := net.Dialer{Timeout: probeTimeout}
	for _, port := range []string{"443", "80"} {
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
		if err == nil {
			_ = conn.Close()
			p.L().Debug("fakeip nat: tcp probe succeeded", zap.String("real_ip", ip), zap.String("port", port))
			return true
		}
		p.L().Debug("fakeip nat: tcp probe failed",
			zap.String("real_ip", ip), zap.String("port", port), zap.Error(err))
	}

	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if _, err := p.runner.Run(pingCtx, "ping", "-c", "1", "-W", "1", ip); err == nil {
		p.L().Debug("fakeip nat: ping probe succeeded", zap.String("real_ip", ip))
		return true
	}
	p.L().Debug("fakeip nat: all probes failed", zap.String("real_ip", ip))
	return false
}

// dbCandidates falls back to the real ips already recorded for the domain.
func (p *FakeIPNatPlugin) dbCandidates(ctx context.Context, domain string) ([]string, error) {
	query := fmt.Sprintf("SELECT real_ip FROM %s WHERE domain = ? ORDER BY last_seen DESC LIMIT %d", p.ipTable, candidateLimit)
	rows, err := p.db.QueryContext(ctx, query, domain)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	p.L().Debug("fakeip nat: candidate real ips loaded from sqlite",
		zap.String("domain", domain), zap.Int("count", len(ips)))
	return ips, rows.Err()
}

// systemDefaultRoute is the fallback for configurations without next_hop. The
// command shape is platform specific, so the query lives in default_route_*.go.
// fallbackHopDev returns the gateway/device a host route should use when the
// configuration left them empty. The system default route is resolved once and
// cached: this sits on the answer path, where a shell call per query is the
// difference between a fast and a slow plugin. refreshFallbackHopDev is called
// by the maintenance loop, so a default route change is picked up within one
// interval instead of never.
func (p *FakeIPNatPlugin) fallbackHopDev(ctx context.Context) (hop, dev string) {
	if p.nextHop != "" || p.nextHopDev != "" {
		return p.nextHop, p.nextHopDev
	}
	p.sysMu.Lock()
	defer p.sysMu.Unlock()
	if p.sysValid {
		return p.sysHop, p.sysDev
	}
	hop, dev = p.systemDefaultRoute(ctx)
	if hop != "" || dev != "" {
		p.sysHop, p.sysDev, p.sysValid = hop, dev, true
		p.L().Debug("fakeip nat: system default route cached",
			zap.String("next_hop", hop), zap.String("dev", dev))
	}
	return hop, dev
}

// refreshFallbackHopDev drops the cached default route so the next data path
// use resolves it again. Called from the maintenance loop; the lock is taken so
// a refresh cannot race a read.
func (p *FakeIPNatPlugin) refreshFallbackHopDev() {
	if p.nextHop != "" || p.nextHopDev != "" {
		return
	}
	p.sysMu.Lock()
	p.sysValid = false
	p.sysMu.Unlock()
}

func (p *FakeIPNatPlugin) systemDefaultRoute(ctx context.Context) (hop, dev string) {
	hop, dev = readSystemDefaultRoute(ctx, p.runner)
	if hop != "" || dev != "" {
		p.L().Debug("using system default route", zap.String("next_hop", hop), zap.String("dev", dev))
	} else {
		p.L().Debug("fakeip nat: system default route has neither gateway nor device")
	}
	return hop, dev
}

// parseCandidateIPs validates and deduplicates the ip list of one answer.
func parseCandidateIPs(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := make(map[string]struct{})
	ips := make([]string, 0, 8)
	for _, part := range strings.Split(raw, ",") {
		addr, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil || !addr.Is4() {
			continue
		}
		key := addr.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		ips = append(ips, key)
	}
	return ips
}

// realCandidates splits candidate real ips into the usable ones and the ones
// that fall inside the plugin's own range. A fake address can never be a DNAT
// target or the destination of a host route.
func (p *FakeIPNatPlugin) realCandidates(ips []string) (kept, fake []string) {
	kept = make([]string, 0, len(ips))
	for _, ip := range ips {
		if p.isFakeAddrString(ip) {
			fake = append(fake, ip)
			continue
		}
		kept = append(kept, ip)
	}
	return kept, fake
}

// collapsePrefixes merges only perfectly aligned sibling networks, so it never
// widens a route beyond the addresses actually mapped.
func collapsePrefixes(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}

	sorted := make([]netip.Prefix, len(in))
	copy(sorted, in)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Addr() != sorted[j].Addr() {
			return sorted[i].Addr().Less(sorted[j].Addr())
		}
		return sorted[i].Bits() < sorted[j].Bits()
	})

	out := make([]netip.Prefix, 0, len(sorted))
	for _, cur := range sorted {
		out = append(out, cur)
		for len(out) >= 2 {
			merged, ok := mergeSiblings(out[len(out)-2], out[len(out)-1])
			if !ok {
				break
			}
			out = append(out[:len(out)-2], merged)
		}
	}
	return out
}

func mergeSiblings(a, b netip.Prefix) (netip.Prefix, bool) {
	if a.Bits() != b.Bits() || a.Bits() == 0 || a.Bits() > 32 {
		return netip.Prefix{}, false
	}
	if a.Addr().BitLen() != 32 || b.Addr().BitLen() != 32 {
		return netip.Prefix{}, false
	}

	bits := a.Bits()
	mask := ^uint32(0) << uint(32-bits)
	ab, bb := a.Addr().As4(), b.Addr().As4()
	av := binary.BigEndian.Uint32(ab[:])
	bv := binary.BigEndian.Uint32(bb[:])
	if av&mask != av || bv&mask != bv {
		return netip.Prefix{}, false
	}
	// Siblings differ in the single bit right below the prefix and the lower
	// one has that bit cleared.
	if av^bv != uint32(1)<<uint(32-bits) || av&(uint32(1)<<uint(32-bits)) != 0 {
		return netip.Prefix{}, false
	}

	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], av)
	return netip.PrefixFrom(netip.AddrFrom4(buf), bits-1), true
}

// hostRouteTable is the table per-address host routes are written into.
// Mark routing takes route_table over for its dedicated table, which is only
// reachable by packets that already carry the mark. A host route written there
// after a failed set write would therefore route nothing at all, so the fallback
// goes to main: the table unmarked traffic already consults, which is exactly
// the shape the mark path replaced.
func (p *FakeIPNatPlugin) hostRouteTable() string {
	if p.markRoutingEnabled() {
		return "main"
	}
	return p.routeTable
}

// cleanupStaleNFTTable removes the nft table a previous non-tun run left behind.
// Tun mode installs no table of its own, so its presence means a crash, a
// SIGKILL or a mode switch: either way the DNAT chain inside it is still hooked
// in prerouting and would keep rewriting packets the device should have routed.
func (p *FakeIPNatPlugin) cleanupStaleNFTTable(ctx context.Context) {
	table := p.nftTableName()
	// This table's DNAT chain is still wired into prerouting, so "the delete
	// failed" cannot be folded into "there was nothing to delete": existence is
	// checked first and a failure is reported at warning level.
	if _, err := p.runner.Run(ctx, "nft", "list", "table", "ip", table); err != nil {
		p.reportListFailure(err, table)
		return
	}
	if _, err := p.runner.Run(ctx, "nft", "delete", "table", "ip", table); err != nil {
		p.L().Warn("fakeip nat: removing the stale nft table failed",
			zap.String("nft_table", table), zap.Error(err))
		return
	}
	p.L().Info("fakeip nat: removed the nft table a non-tun run left behind", zap.String("nft_table", table))
}

// reportListFailure separates "the table is already gone" from "nft could not be
// run at all": the first is routine, the second leaves a hooked chain behind.
func (p *FakeIPNatPlugin) reportListFailure(err error, table string) {
	if commandMissing(err) {
		p.L().Warn("fakeip nat: nft is not available, stale tables cannot be checked or removed",
			zap.String("nft_table", table), zap.Error(err))
		return
	}
	p.L().Debug("fakeip nat: no stale nft table to remove", zap.String("nft_table", table))
}
