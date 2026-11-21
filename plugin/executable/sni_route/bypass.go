package sni_route

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/matcher/netlist"
)

// loadBypassProviders expands entries that name a data provider. A plain IP or
// CIDR is handled by parsePrefixes; this path exists so a domestic prefix list
// already loaded for the DNS matchers can be reused verbatim as an nft set.
func loadBypassProviders(bp *coremain.BP, entries []string) ([]netip.Prefix, error) {
	m := bp.M()
	if m == nil {
		return nil, fmt.Errorf("no data manager")
	}
	dm := m.GetDataManager()
	if dm == nil {
		return nil, fmt.Errorf("no data manager")
	}

	var out []netip.Prefix
	seen := make(map[netip.Prefix]struct{})
	add := func(list *netlist.List) {
		list.Sort()
		for _, prefix := range list.Prefixes() {
			if prefix.Addr().Is4In6() {
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			if !prefix.Addr().Is4() {
				continue
			}
			prefix = prefix.Masked()
			if _, ok := seen[prefix]; ok {
				continue
			}
			seen[prefix] = struct{}{}
			out = append(out, prefix)
		}
	}

	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.HasPrefix(raw, "provider:") {
			// Mixed entries are allowed; the plain ones go through the same
			// prefix parser as bypass.
			parsed, err := parsePrefixes([]string{raw})
			if err != nil {
				return nil, err
			}
			for _, prefix := range parsed {
				if _, ok := seen[prefix]; ok {
					continue
				}
				seen[prefix] = struct{}{}
				out = append(out, prefix)
			}
			continue
		}
		name := strings.TrimPrefix(raw, "provider:")
		name, suffix, _ := strings.Cut(name, ":")
		provider := dm.GetDataProvider(name)
		if provider == nil {
			return nil, fmt.Errorf("cannot find provider %s", name)
		}
		data, err := provider.GetData()
		if err != nil {
			return nil, fmt.Errorf("read provider %s: %w", name, err)
		}
		list := netlist.NewList()
		if suffix != "" {
			list, err = netlist.ParseV2rayIPDat(data, suffix)
			if err != nil {
				return nil, fmt.Errorf("parse provider %s:%s: %w", name, suffix, err)
			}
		} else {
			if err := netlist.LoadFromReader(list, bytes.NewReader(data)); err != nil {
				return nil, fmt.Errorf("parse provider %s: %w", name, err)
			}
		}
		add(list)
	}
	return out, nil
}
