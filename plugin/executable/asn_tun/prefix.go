package asn_tun

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
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

func loadPrefixes(ctx context.Context, asns []uint32, cachePath string) ([]netip.Prefix, error) {
	if strings.TrimSpace(cachePath) == "" {
		cachePath = defaultCache
	}
	prefixes, err := fetchPrefixes(ctx, asns)
	if err == nil && len(prefixes) > 0 {
		_ = writePrefixCache(cachePath, asns, prefixes)
		return prefixes, nil
	}
	if err != nil {
		prefixes, cacheErr := readPrefixCache(cachePath, asns)
		if cacheErr == nil && len(prefixes) > 0 {
			return prefixes, nil
		}
		return nil, fmt.Errorf("fetch prefixes failed (%v), cache unusable: %v", err, cacheErr)
	}
	return nil, fmt.Errorf("no IPv4 prefixes returned for ASN list")
}

func fetchPrefixes(ctx context.Context, asns []uint32) ([]netip.Prefix, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	seen := make(map[string]struct{})
	var out []netip.Prefix
	for _, asn := range asns {
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
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
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
	return out, nil
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
