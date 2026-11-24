package sni_route

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

// markHookPriority runs after fakeip_nat's DNAT (-100) and destination-mark
// chain (0), after asn_tun's mark chain (10), and after VyOS's policy-routing
// mangle chain (-150). The SNI rule only captures packets that carry no mark:
// an earlier mark is already a decision (asn_tun sends Telegram ASNs into
// asn0, for example), and this plugin must not overwrite it and strand the
// flow on the unmatched direct path.
const markHookPriority = 12

type cmdRunner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

type execRunner struct{}

func commandPath(name string) string {
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		path := dir + "/" + name
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return name
}

func (execRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, commandPath(name), args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

type nftParams struct {
	table     string
	mark      uint32
	iface     string
	sources   []netip.Prefix
	bypass    []netip.Prefix
	ports     []int
	blockQUIC bool
}

func nftRules(p nftParams) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\n", p.table)
	fmt.Fprintf(&b, "add set inet %s bypass4 { type ipv4_addr; flags interval; }\n", p.table)
	if len(p.sources) > 0 {
		fmt.Fprintf(&b, "add set inet %s src4 { type ipv4_addr; flags interval; }\n", p.table)
	}
	fmt.Fprintf(&b, "add chain inet %s mark_pre { type filter hook prerouting priority %d; policy accept; }\n", p.table, markHookPriority)

	srcMatch := ""
	if len(p.sources) > 0 {
		srcMatch = "ip saddr @src4 "
	}
	bypassMatch := ""
	if len(p.bypass) > 0 {
		bypassMatch = "ip daddr != @bypass4 "
	}
	ports := nftPortSet(p.ports)
	fmt.Fprintf(&b, "add rule inet %s mark_pre iifname %q %s%s tcp dport %s meta mark == 0 counter meta mark set %d\n",
		p.table, p.iface, srcMatch, bypassMatch, ports, p.mark)
	if p.blockQUIC {
		// QUIC carries its own encrypted DNS and its SNI is not readable by a
		// TLS parser. Dropping it on the captured path makes the client fall
		// back to TCP, where the SNI decision actually applies. The bypass set
		// keeps LAN and fake-IP destinations out of this drop.
		fmt.Fprintf(&b, "add rule inet %s mark_pre iifname %q %s%s udp dport %s meta mark == 0 counter drop\n",
			p.table, p.iface, srcMatch, bypassMatch, ports)
	}

	for _, chunk := range prefixChunks(p.bypass, 100) {
		fmt.Fprintf(&b, "add element inet %s bypass4 { %s }\n", p.table, joinPrefixes(chunk))
	}
	if len(p.sources) > 0 {
		for _, chunk := range prefixChunks(p.sources, 100) {
			fmt.Fprintf(&b, "add element inet %s src4 { %s }\n", p.table, joinPrefixes(chunk))
		}
	}
	return b.String()
}

func nftPortSet(ports []int) string {
	if len(ports) == 1 {
		return strconv.Itoa(ports[0])
	}
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, strconv.Itoa(port))
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

func (p *Plugin) installNft(ctx context.Context) error {
	content := nftRules(nftParams{
		table:     p.args.NftTable,
		mark:      p.mark,
		iface:     p.iface,
		sources:   p.sources,
		bypass:    p.bypass,
		ports:     p.ports,
		blockQUIC: p.args.BlockQUIC,
	})
	f, err := os.CreateTemp("", "sni_route-*.nft")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	// Validate against a throwaway table name: checking the live name would
	// collide with the table still installed during a reload.
	checkPath := path + ".check"
	check := nftRules(nftParams{
		table:     p.args.NftTable + "_check",
		mark:      p.mark,
		iface:     p.iface,
		sources:   p.sources,
		bypass:    p.bypass,
		ports:     p.ports,
		blockQUIC: p.args.BlockQUIC,
	})
	if err := os.WriteFile(checkPath, []byte(check), 0o600); err != nil {
		return err
	}
	defer os.Remove(checkPath)
	if _, err := p.runner.Run(ctx, "nft", "-c", "-f", checkPath); err != nil {
		return fmt.Errorf("nft check: %w", err)
	}

	if err := deleteNft(ctx, p.runner, p.args.NftTable); err != nil {
		p.L().Debug("sni_route: removing old nft table failed", zap.String("table", p.args.NftTable), zap.Error(err))
	}
	p.nftInstalled = true
	if _, err := p.runner.Run(ctx, "nft", "-f", path); err != nil {
		return err
	}
	p.L().Info("sni_route: nft rules installed",
		zap.String("table", p.args.NftTable),
		zap.String("iface", p.iface),
		zap.Int("source_count", len(p.sources)),
		zap.Int("bypass_count", len(p.bypass)),
		zap.Ints("ports", p.ports),
		zap.Bool("block_quic", p.args.BlockQUIC),
		zap.Uint32("mark", p.mark))
	return nil
}

func (p *Plugin) nftTableExists(ctx context.Context, table string) bool {
	_, err := p.runner.Run(ctx, "nft", "list", "table", "inet", table)
	return err == nil
}

func deleteNft(ctx context.Context, runner cmdRunner, table string) error {
	_, err := runner.Run(ctx, "nft", "delete", "table", "inet", table)
	return err
}

func prefixChunks(in []netip.Prefix, size int) [][]netip.Prefix {
	var out [][]netip.Prefix
	for len(in) > 0 {
		n := size
		if n > len(in) {
			n = len(in)
		}
		out = append(out, in[:n])
		in = in[n:]
	}
	return out
}

func joinPrefixes(prefixes []netip.Prefix) string {
	parts := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		parts = append(parts, prefix.String())
	}
	return strings.Join(parts, ", ")
}
