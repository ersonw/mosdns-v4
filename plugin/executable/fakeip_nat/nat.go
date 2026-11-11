package fakeipnat

// This file implements the NAT side of the plugin. It replaces the external
// nat_map.py helper: the plugin itself keeps the nftables DNAT map in sync
// with the fake ip it handed out, picks a reachable real ip among the
// candidates, writes host routes into the configured table and re-aggregates
// the /32 routes into strict CIDR blocks.

import (
	"context"
	"encoding/binary"
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
	if _, err := p.runner.Run(ctx, "nft", "list", "table", "ip", table); err == nil {
		p.L().Debug("fakeip nat: nft table already present", zap.String("nft_table", table))
		return nil
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
		setup = append(setup, []string{"add", "rule", "ip", table, "postrouting", "oifname", dev, "masquerade"})
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
	if hop == "" && dev == "" {
		p.L().Debug("fakeip nat: host route skipped, no next hop and no device", zap.String("real_ip", ip))
		return
	}
	args := []string{"route", "replace", ip + "/32"}
	if hop != "" {
		args = append(args, "via", hop)
	}
	if dev != "" {
		args = append(args, "dev", dev)
	}
	if p.routeTable != "" && p.routeTable != "main" {
		args = append(args, "table", p.routeTable)
	}
	if _, err := p.runner.Run(ctx, "ip", args...); err != nil {
		p.L().Warn("apply host route failed",
			zap.String("real_ip", ip), zap.String("route_table", p.routeTable), zap.Strings("cmd", args), zap.Error(err))
		return
	}
	p.L().Debug("fakeip nat: host route applied",
		zap.String("real_ip", ip), zap.String("next_hop", hop), zap.String("dev", dev),
		zap.String("route_table", p.routeTable))
}

// aggregateManagedRoutes folds every route that steers traffic to the
// configured gateway/device into CIDR blocks. The list is read from the
// kernel, the originals are kept verbatim, the aggregated blocks are installed
// first and the originals are deleted afterwards, so a packet never falls into
// the gap between the two passes.
func (p *FakeIPNatPlugin) aggregateManagedRoutes() {
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

	withTable := func(args []string) []string {
		if p.routeTable != "" && p.routeTable != "main" {
			return append(args, "table", p.routeTable)
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
	withTable := func(args []string) []string {
		if p.routeTable != "" && p.routeTable != "main" {
			return append(args, "table", p.routeTable)
		}
		return args
	}
	deleted := 0
	for _, prefix := range prefixes {
		if _, err := p.runner.Run(ctx, "ip", withTable([]string{"route", "delete", prefix})...); err == nil {
			deleted++
		}
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

	p.natMu.Lock()
	defer p.natMu.Unlock()

	routesDeleted := 0
	if hop != "" || dev != "" {
		routesDeleted = p.deleteManagedRoutes(ctx, p.listManagedRoutes(ctx, hop, dev))
	}

	tableDeleted := false
	if !p.useTun && !p.realIP {
		if _, err := p.runner.Run(ctx, "nft", "delete", "table", "ip", p.nftTableName()); err == nil {
			tableDeleted = true
		}
	}

	p.L().Info("fakeip nat: data path cleaned up",
		zap.Int("routes_deleted", routesDeleted), zap.Bool("nft_table_deleted", tableDeleted),
		zap.String("next_hop", hop), zap.String("dev", dev))
}

// syncRealRoutes installs a /32 host route for every real ip of a resolution
// and debounces the CIDR collapse. It is the whole data plane of realip mode:
// no fake ip is allocated and no DNAT element is written.
func (p *FakeIPNatPlugin) syncRealRoutes(ctx context.Context, ips []string) {
	ctx, cancel := context.WithTimeout(ctx, natTimeout)
	defer cancel()

	hop, dev := p.nextHop, p.nextHopDev
	if hop == "" && dev == "" {
		hop, dev = p.systemDefaultRoute(ctx)
	}
	if hop == "" && dev == "" {
		p.L().Debug("realip: no next hop and no device, routes not installed")
		return
	}

	p.natMu.Lock()
	defer p.natMu.Unlock()

	applied := 0
	for _, ip := range ips {
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() {
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
		zap.Int("applied", applied), zap.String("route_table", p.routeTable))
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
