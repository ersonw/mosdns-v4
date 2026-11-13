package asn_tun

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"go.uber.org/zap"
)

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

// nftFile is pure text so a test can compare the complete ruleset without
// running nft. The table is recreated on every install; that is the only
// reliable way to remove chains and sets from a previous version.
func nftFile(table string, mark uint32, prefixes []netip.Prefix, bypass []netip.Addr, skip []netip.Prefix, mirrorDev string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\n", table)
	fmt.Fprintf(&b, "add set inet %s asn4 { type ipv4_addr; flags interval; }\n", table)
	fmt.Fprintf(&b, "add set inet %s bypass4 { type ipv4_addr; flags interval; }\n", table)
	if len(skip) > 0 {
		fmt.Fprintf(&b, "add set inet %s skip4 { type ipv4_addr; flags interval; }\n", table)
	}
	fmt.Fprintf(&b, "add chain inet %s mark_pre { type filter hook prerouting priority 0; policy accept; }\n", table)
	preMatch := ""
	if mirrorDev != "" {
		preMatch = fmt.Sprintf("iifname %q ", mirrorDev)
	}
	skipMatch := ""
	if len(skip) > 0 {
		skipMatch = "ip daddr != @skip4 "
	}
	fmt.Fprintf(&b, "add rule inet %s mark_pre %smeta mark 0 ip daddr != @bypass4 %sip daddr @asn4 meta mark set %d\n", table, preMatch, skipMatch, mark)
	// A mirror/SPAN interface feeds ingress only. The output chain would mark
	// locally generated traffic as well, which is not part of the mirrored
	// stream, so it is installed only in the global (all-interface) mode.
	if mirrorDev == "" {
		fmt.Fprintf(&b, "add chain inet %s mark_out { type route hook output priority 0; policy accept; }\n", table)
		fmt.Fprintf(&b, "add rule inet %s mark_out meta mark 0 ip daddr != @bypass4 %sip daddr @asn4 meta mark set %d\n", table, skipMatch, mark)
	}

	for _, chunk := range prefixChunks(prefixes, 100) {
		fmt.Fprintf(&b, "add element inet %s asn4 { %s }\n", table, joinPrefixes(chunk))
	}
	if len(skip) > 0 {
		for _, chunk := range prefixChunks(skip, 100) {
			fmt.Fprintf(&b, "add element inet %s skip4 { %s }\n", table, joinPrefixes(chunk))
		}
	}
	if len(bypass) > 0 {
		parts := make([]string, 0, len(bypass))
		for _, addr := range bypass {
			parts = append(parts, addr.String())
		}
		fmt.Fprintf(&b, "add element inet %s bypass4 { %s }\n", table, strings.Join(parts, ", "))
	}
	return b.String()
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

func (p *ASNTunPlugin) installNft(ctx context.Context) error {
	// Normalize again at the final write boundary. Cached data, a provider
	// response, or a future caller may contain overlapping prefixes; nft
	// interval sets reject them as "conflicting intervals".
	prefixes := normalizePrefixes(p.prefixes)
	skip := normalizePrefixes(p.skipPrefixes)
	bypass := uniqueAddrs(p.bypass)
	content := nftFile(p.args.NftTable, p.mark, prefixes, bypass, skip, p.mirrorDev)
	f, err := os.CreateTemp("", "asn_tun-*.nft")
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
	// Check on a throwaway table name. Checking the live name would collide
	// with the table that is still present during a refresh, and applying a
	// failed check must never remove a working mark set.
	checkPath := path + ".check"
	checkContent := nftFile(p.args.NftTable+"_check", p.mark, prefixes, bypass, skip, p.mirrorDev)
	if err := os.WriteFile(checkPath, []byte(checkContent), 0o600); err != nil {
		return err
	}
	defer os.Remove(checkPath)
	if _, err := p.runner.Run(ctx, "nft", "-c", "-f", checkPath); err != nil {
		return fmt.Errorf("nft check: %w", err)
	}
	if err := deleteNft(ctx, p.runner, p.args.NftTable); err != nil {
		p.L().Debug("asn_tun: removing old nft table failed", zap.String("table", p.args.NftTable), zap.Error(err))
	}
	// Mark the table as owned before applying it. nft -f is transactional, but
	// an interrupted/failed apply must still be visible to Close so a later
	// shutdown can remove whatever this process created.
	p.nftInstalled = true
	if _, err := p.runner.Run(ctx, "nft", "-f", path); err != nil {
		return err
	}
	p.L().Info("asn_tun: nft set installed",
		zap.String("table", p.args.NftTable),
		zap.String("mirror_dev", p.mirrorDev),
		zap.Int("skip_prefix_count", len(skip)),
		zap.Uint32("mark", p.mark),
		zap.Int("prefix_count", len(prefixes)),
		zap.Int("bypass_count", len(bypass)))
	return nil
}

func (p *ASNTunPlugin) nftTableExists(ctx context.Context, table string) bool {
	_, err := p.runner.Run(ctx, "nft", "list", "table", "inet", table)
	return err == nil
}

func deleteNft(ctx context.Context, runner cmdRunner, table string) error {
	_, err := runner.Run(ctx, "nft", "delete", "table", "inet", table)
	return err
}
