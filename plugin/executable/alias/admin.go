package alias

// admin.go exposes the operations a control surface (the telegram bot) needs.
// The plugin owns the list file, so every mutation happens here: the table is
// rebuilt, the file is rewritten atomically, and the state the removed name left
// behind (virtual address, reverse mapping, cached resolution) is dropped in the
// same step.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	aliasadmin "github.com/ersonw/mosdns-v4/pkg/alias_admin"
	fakeipadmin "github.com/ersonw/mosdns-v4/pkg/fakeip_admin"
	"github.com/ersonw/mosdns-v4/pkg/matcher/domain"
	"go.uber.org/zap"
)

var (
	_ aliasadmin.Admin       = (*plugin)(nil)
	_ fakeipadmin.PurgeAdmin = (*plugin)(nil)
)

func (p *plugin) AdminAliasSnapshot(_ context.Context) (aliasadmin.Snapshot, error) {
	p.mu.RLock()
	suffix, replace := p.suffix, p.replace
	p.mu.RUnlock()

	entries := p.store.listEntries()
	out := make([]aliasadmin.Entry, 0, len(entries))
	for _, e := range entries {
		scheme := e.Scheme
		if scheme == "" {
			scheme = p.defScheme
		}
		item := aliasadmin.Entry{Domain: e.Name, Scheme: scheme}
		// Reading the snapshot also repairs an entry that was loaded before
		// the runtime alias table existed; it is idempotent.
		item.Alias = p.aliasName(e.Name)
		if p.alloc != nil {
			if addr, ok := p.alloc.Lookup(e.Name); ok {
				item.IPv4 = addr.String()
			}
		}
		out = append(out, item)
	}
	return aliasadmin.Snapshot{
		Tag:            p.Tag(),
		File:           p.store.path,
		Suffix:         strings.TrimPrefix(suffix, "."),
		ReplaceSuffix:  replace,
		IPv4Range:      p.prefix.String(),
		DefaultScheme:  p.defScheme,
		ProxyActive:    p.proxy != nil,
		Redirect:       p.redirect,
		DotReplacement: p.dotRepl,
		TLS:            p.tlsConfig != nil,
		Total:          len(out),
		Entries:        out,
	}, nil
}

func (p *plugin) AdminAliasAdd(_ context.Context, raw string) (bool, error) {
	e, added, err := p.store.add(raw)
	if err != nil {
		return false, err
	}
	if !added {
		// A duplicate is still a valid served name; make sure a mapping
		// exists for it after a bot restart or an older runtime table.
		p.aliasName(e.Name)
		return false, nil
	}
	if _, err := p.alloc.Ensure(e.Name); err != nil {
		p.log().Warn("alias: preallocate added domain failed", zap.String("domain", e.Name), zap.Error(err))
	}
	// Register the alias now rather than waiting for the first response
	// rewrite: a DNS query may arrive before the browser has seen the page.
	p.aliasName(e.Name)
	return true, nil
}

func (p *plugin) AdminAliasDelete(_ context.Context, raw string) (bool, error) {
	name, removed, err := p.store.del(raw)
	if err != nil {
		return false, err
	}
	if !removed {
		return false, nil
	}
	p.purgeName(name)
	return true, nil
}

func (p *plugin) AdminAliasModify(_ context.Context, oldRaw, newRaw string) error {
	newEntry, err := p.store.mod(oldRaw, newRaw)
	if err != nil {
		return err
	}
	oldName := domain.NormalizeDomain(strings.TrimSpace(oldRaw))
	p.purgeName(oldName)
	p.purgeName(newEntry.Name)
	if _, err := p.alloc.Ensure(newEntry.Name); err != nil {
		p.log().Warn("alias: preallocate modified domain failed", zap.String("domain", newEntry.Name), zap.Error(err))
	}
	p.aliasName(newEntry.Name)
	return nil
}

func (p *plugin) AdminAliasClear(_ context.Context) (int, error) {
	n, err := p.store.clear()
	if err != nil {
		return 0, err
	}
	removed := p.alloc.PurgeAll()
	p.resetAliasMappings()
	if p.resolve != nil {
		p.resolve.Clear()
	}
	p.log().Info("alias: list cleared by admin", zap.Int("domains", n), zap.Int("mappings", removed))
	return n, nil
}

func (p *plugin) AdminAliasSetSuffix(_ context.Context, raw string) error {
	suffix := strings.TrimSpace(strings.ToLower(raw))
	suffix = strings.TrimPrefix(suffix, ".")
	if suffix == "" {
		return fmt.Errorf("suffix is empty")
	}
	if err := validateSuffix(suffix); err != nil {
		return err
	}
	p.mu.Lock()
	p.suffix = "." + suffix
	p.mu.Unlock()
	// Existing alias strings were built with the old suffix. Rebuild them
	// before a DNS query can resolve a stale host name.
	p.resetAliasMappings()
	p.rebuildAliasMappings()
	p.log().Info("alias: suffix changed by admin", zap.String("suffix", "."+suffix))
	return nil
}

// AdminAliasCheckRange validates the segment without touching the running
// device: a new range needs fresh addresses on the tun plane and a new table,
// so the caller writes the config and restarts.
func (p *plugin) AdminAliasCheckRange(_ context.Context, cidr string) error {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return fmt.Errorf("invalid ipv4_range: %w", err)
	}
	if !prefix.Addr().Is4() {
		return fmt.Errorf("ipv4_range %s must be IPv4", cidr)
	}
	if _, err := newAllocator(prefix); err != nil {
		return err
	}
	return nil
}

// AdminAliasReload re-reads the file. A name that disappeared from it loses its
// virtual address, so the next query cannot be answered from a stale rule.
func (p *plugin) AdminAliasReload(_ context.Context) error {
	if err := p.store.reload(); err != nil {
		return err
	}
	dropped := p.alloc.Prune(func(name string) bool {
		_, ok := p.store.matchName(name)
		return ok
	})
	// The store is the source of truth. Drop host aliases whose real name is
	// gone, then rebuild readable aliases for every current entry.
	p.pruneAliasMappings()
	p.preallocateStore()
	p.rebuildAliasMappings()
	p.log().Info("alias: list reloaded from disk",
		zap.Int("domains", p.store.count()), zap.Int("dropped_mappings", dropped),
		zap.Int("aliases", p.aliasMappingCount()))
	return nil
}

// AdminPurgeDomain drops every trace of domain and its subdomains: the virtual
// address of each mapped name, its reverse mapping and any address the resolver
// learned for it.
func (p *plugin) AdminPurgeDomain(_ context.Context, domainName string) (fakeipadmin.PurgeReport, error) {
	name := domain.NormalizeDomain(domainName)
	if name == "" {
		return fakeipadmin.PurgeReport{}, nil
	}
	domains := p.alloc.PurgeDomain(name)
	if p.resolve != nil {
		p.resolve.PurgeDomain(name)
	}
	if len(domains) == 0 {
		return fakeipadmin.PurgeReport{}, nil
	}
	p.log().Debug("alias: domain state purged",
		zap.String("domain", name), zap.Int("mappings", len(domains)))
	return fakeipadmin.PurgeReport{Mappings: len(domains), Domains: domains}, nil
}

// purgeName is the local tail used by the list mutations above.
func (p *plugin) purgeName(name string) {
	domains := p.alloc.PurgeDomain(name)
	p.purgeAliasMappings(name)
	if p.resolve != nil {
		p.resolve.PurgeDomain(name)
	}
	if len(domains) > 0 {
		p.log().Debug("alias: name state purged",
			zap.String("domain", name), zap.Int("mappings", len(domains)))
	}
}

// purgeAliasMappings removes runtime readable aliases whose real host is the
// removed name or one of its subdomains.
func (p *plugin) purgeAliasMappings(name string) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	p.aliasMu.Lock()
	defer p.aliasMu.Unlock()
	for alias, real := range p.aliasByName {
		if real == "" || real == name || strings.HasSuffix(real, "."+name) {
			delete(p.aliasByName, alias)
		}
	}
}

// pruneAliasMappings drops aliases whose real host is no longer served. It
// preserves runtime aliases for wildcard subdomains that are still covered by
// a listed parent.
func (p *plugin) pruneAliasMappings() {
	if p.store == nil {
		return
	}
	p.aliasMu.Lock()
	defer p.aliasMu.Unlock()
	for alias, real := range p.aliasByName {
		if real == "" {
			delete(p.aliasByName, alias)
			continue
		}
		if _, ok := p.store.matchName(real); !ok {
			delete(p.aliasByName, alias)
		}
	}
}

func (p *plugin) resetAliasMappings() {
	p.aliasMu.Lock()
	p.aliasByName = make(map[string]string)
	p.aliasMu.Unlock()
}

func (p *plugin) rebuildAliasMappings() {
	if p.store == nil {
		return
	}
	for _, e := range p.store.listEntries() {
		p.aliasName(e.Name)
	}
}

func (p *plugin) aliasMappingCount() int {
	p.aliasMu.RLock()
	defer p.aliasMu.RUnlock()
	return len(p.aliasByName)
}
