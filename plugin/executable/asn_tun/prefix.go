package asn_tun

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/helperscript"
	"go.uber.org/zap"
)

const (
	prefixURLBase = "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/%d/ipv4-aggregated.txt"
	defaultCache  = "/config/mosdns/asn_tun_prefixes.json"
)

type prefixCache struct {
	Updated time.Time `json:"updated"`
	ASN     []uint32  `json:"asn"`
	IPv4    []string  `json:"ipv4"`
}

func (p *ASNTunPlugin) mergePrefixData(ctx context.Context, data []byte) ([]netip.Prefix, error) {
	mergeScript, mergeDownloaded, err := helperscript.Resolve(ctx, p.configDir, p.args.MergeScript, defaultMergeScript)
	if err != nil {
		return nil, err
	}
	if mergeDownloaded && p.BP != nil {
		p.L().Info("asn_tun: downloaded helper script",
			zap.String("script", defaultMergeScript), zap.String("path", mergeScript))
	}

	merge := exec.CommandContext(ctx, p.args.Python, mergeScript, "--ipv4-only")
	merge.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	merge.Stderr = &stderr
	merged, err := merge.Output()
	if err != nil {
		return nil, fmt.Errorf("merge script %s: %w: %s", mergeScript, err, strings.TrimSpace(stderr.String()))
	}
	prefixes, err := parsePrefixLines(string(merged))
	if err != nil {
		return nil, err
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("merge script returned no IPv4 prefixes")
	}
	return normalizePrefixes(prefixes), nil
}

func (p *ASNTunPlugin) fetchPrefixesBGpq3(ctx context.Context) ([]netip.Prefix, error) {
	fetchScript, fetchDownloaded, err := helperscript.Resolve(ctx, p.configDir, p.args.FetchScript, defaultFetchScript)
	if err != nil {
		return nil, err
	}
	if fetchDownloaded && p.BP != nil {
		p.L().Info("asn_tun: downloaded helper script",
			zap.String("script", defaultFetchScript), zap.String("path", fetchScript))
	}

	asnFile, err := os.CreateTemp("", "asn_tun-asn-*.txt")
	if err != nil {
		return nil, err
	}
	asnPath := asnFile.Name()
	defer os.Remove(asnPath)
	for _, asn := range p.asns {
		if _, err := fmt.Fprintf(asnFile, "AS%d\n", asn); err != nil {
			_ = asnFile.Close()
			return nil, err
		}
	}
	if err := asnFile.Close(); err != nil {
		return nil, err
	}

	prefixFile, err := os.CreateTemp("", "asn_tun-prefixes-*.txt")
	if err != nil {
		return nil, err
	}
	prefixPath := prefixFile.Name()
	if err := prefixFile.Close(); err != nil {
		os.Remove(prefixPath)
		return nil, err
	}
	defer os.Remove(prefixPath)

	fetch := exec.CommandContext(ctx, p.args.Python, fetchScript,
		asnPath, prefixPath, "--ipv4-only", "-w", "4", "-d", "0")
	out, err := fetch.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("fetch script %s: %w: %s", fetchScript, err, strings.TrimSpace(string(out)))
	}
	data, err := os.ReadFile(prefixPath)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("fetch script returned no IPv4 prefixes")
	}
	return p.mergePrefixData(ctx, data)
}

func (p *ASNTunPlugin) fetchPrefixesIPVerse(ctx context.Context) ([]netip.Prefix, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	seen := make(map[string]struct{})
	var out []netip.Prefix
	for _, asn := range p.asns {
		url := fmt.Sprintf(prefixURLBase, asn)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("AS%d: %w", asn, err)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("AS%d: %w", asn, readErr)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("AS%d: HTTP %d", asn, resp.StatusCode)
		}
		parsed, err := parsePrefixLines(string(body))
		if err != nil {
			return nil, fmt.Errorf("AS%d: %w", asn, err)
		}
		for _, prefix := range parsed {
			key := prefix.String()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, prefix)
		}
	}
	var body strings.Builder
	for _, prefix := range out {
		body.WriteString(prefix.String())
		body.WriteByte('\n')
	}
	return p.mergePrefixData(ctx, []byte(body.String()))
}

func parsePrefixLines(body string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	seen := make(map[string]struct{})
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			// The provider is machine generated; one malformed line should not
			// discard a whole ASN's usable list.
			continue
		}
		if !p.Addr().Is4() {
			continue
		}
		prefix := p.Masked()
		if prefix.Bits() < 8 {
			// A /0../7 announcement would mark most of the IPv4 internet. The
			// current providers do not emit those, but a bad upstream must not
			// turn into a global route.
			continue
		}
		key := prefix.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, prefix)
	}
	return out, nil
}

func readPrefixCache(path string, asns []uint32) ([]netip.Prefix, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cache prefixCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, err
	}
	if !sameASNSet(cache.ASN, asns) {
		return nil, fmt.Errorf("cache ASN set differs from configuration")
	}
	var out []netip.Prefix
	for _, raw := range cache.IPv4 {
		p, err := netip.ParsePrefix(raw)
		if err != nil || !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		if p.Bits() < 8 {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("cache contains no IPv4 prefixes")
	}
	return normalizePrefixes(out), nil
}

func writePrefixCache(path string, asns []uint32, prefixes []netip.Prefix) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	cache := prefixCache{Updated: time.Now().UTC(), ASN: append([]uint32(nil), asns...)}
	for _, prefix := range prefixes {
		cache.IPv4 = append(cache.IPv4, prefix.String())
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// normalizePrefixes drops exact duplicates and contained sub-prefixes. nft's
// interval sets reject overlapping intervals, and ASN feeds legitimately
// contain both a /22 and one of its /23s.
func normalizePrefixes(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if !p.IsValid() || !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		if p.Bits() < 8 {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if c := out[i].Addr().Compare(out[j].Addr()); c != 0 {
			return c < 0
		}
		return out[i].Bits() < out[j].Bits()
	})
	merged := out[:0]
	for _, p := range out {
		if len(merged) > 0 && merged[len(merged)-1].Contains(p.Addr()) {
			continue
		}
		merged = append(merged, p)
	}
	return merged
}

func prefixesEqual(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]netip.Prefix(nil), a...)
	y := append([]netip.Prefix(nil), b...)
	sort.Slice(x, func(i, j int) bool { return x[i].String() < x[j].String() })
	sort.Slice(y, func(i, j int) bool { return y[i].String() < y[j].String() })
	for i := range x {
		if x[i].String() != y[i].String() {
			return false
		}
	}
	return true
}

func sameASNSet(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]uint32(nil), a...)
	y := append([]uint32(nil), b...)
	sort.Slice(x, func(i, j int) bool { return x[i] < x[j] })
	sort.Slice(y, func(i, j int) bool { return y[i] < y[j] })
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
