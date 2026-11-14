/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// This file holds the shared tail of every bot command that removes a domain:
// the answers already cached and the records already stored keep influencing
// the next resolution, so they are dropped together with the rule.

package telegram_bot

import (
	"context"
	"fmt"
	"strings"
)

// purgeDomainResult aggregates what one domain purge removed across the plugins
// the bot could reach. Zero values mean "nothing was there", which is the
// normal answer for a domain that was never resolved.
type purgeDomainResult struct {
	Mappings int // fake ip table rows, subdomains included
	RealIPs  int // real ip table rows
	Access   int // access log rows
	Cached   int // cached DNS answers
	FakeIP   int // fakeip plugins that answered
	Caches   int // cache plugins that answered
	Warnings []string
}

func (r purgeDomainResult) removed() bool {
	return r.Mappings > 0 || r.RealIPs > 0 || r.Access > 0 || r.Cached > 0
}

// purgeDomainData drops every record of domain and of its subdomains: the fake
// ip mappings with the learned real addresses, the access log rows, and the
// answers a cache plugin still holds. The provider list entry itself is not
// touched here; only the state a later query would read.
//
// Discovery is by interface, not by tag: a fakeip plugin implementing
// PurgeAdmin and a cache plugin implementing AdminPurgeDomain are both found in
// the running plugin set, so no extra configuration is needed. Errors are
// collected instead of aborting, so one broken plugin does not leave the other
// half of the purge undone.
func (p *telegramBot) purgeDomainData(ctx context.Context, domain string) purgeDomainResult {
	var res purgeDomainResult
	domain = normalizePurgeDomain(domain)
	if domain == "" || p.M() == nil {
		return res
	}

	for tag, ex := range p.M().GetExecutables() {
		if ex == nil {
			continue
		}
		if pa, ok := ex.(domainPurgeAdmin); ok {
			rep, err := pa.AdminPurgeDomain(ctx, domain)
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: purge failed: %v", tag, err))
				continue
			}
			res.FakeIP++
			res.Mappings += rep.Mappings
			res.RealIPs += rep.RealIPs
			res.Access += rep.Access
			continue
		}
		if cp, ok := ex.(cachePurgeAdmin); ok {
			n, err := cp.AdminPurgeDomain(ctx, domain)
			if err != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s: cache purge failed: %v", tag, err))
				continue
			}
			res.Caches++
			res.Cached += n
		}
	}
	return res
}

// purgeSummary is the one-line report appended to a delete reply.
func purgeSummary(r purgeDomainResult, l lang) string {
	if !r.removed() && len(r.Warnings) == 0 {
		return l.t("no cached answer or stored record was left for this domain",
			"该域名没有残留的缓存或记录")
	}
	line := l.t(
		fmt.Sprintf("purged: mappings %d, real ips %d, access rows %d, cached answers %d",
			r.Mappings, r.RealIPs, r.Access, r.Cached),
		fmt.Sprintf("已清理：映射 %d 条、真实 IP %d 条、访问记录 %d 条、缓存应答 %d 条",
			r.Mappings, r.RealIPs, r.Access, r.Cached))
	if len(r.Warnings) > 0 {
		line += "\n" + strings.Join(r.Warnings, "\n")
	}
	return line
}

// normalizePurgeDomain matches the form the fakeip plugin stores: lower case,
// no surrounding space, no trailing dot.
func normalizePurgeDomain(domain string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimSuffix(domain, ".")))
}

// providerPurge removes the state a deleted or replaced rule left behind. The
// provider file keeps its own record of the change (and the backup the script
// wrote); only the cache entries and the stored mapping/real-ip/access rows of
// the names are dropped, so adding the domain again later starts from zero.
func (p *telegramBot) providerPurge(ctx context.Context, action string, values []string, l lang) string {
	switch action {
	case providerDel, providerMod:
	default:
		return ""
	}
	var lines []string
	seen := make(map[string]bool)
	for _, rule := range values {
		domain, ok := ruleDomain(rule)
		if !ok {
			lines = append(lines, l.t(
				fmt.Sprintf("%s: pattern rule, nothing to purge", rule),
				fmt.Sprintf("%s：模式规则，无需清理", rule)))
			continue
		}
		if seen[domain] {
			continue
		}
		seen[domain] = true
		res := p.purgeDomainData(ctx, domain)
		lines = append(lines, domain+": "+purgeSummary(res, l))
	}
	if len(lines) == 0 {
		return ""
	}
	return l.t("rule removed, related state purged:", "规则已删除，关联状态已清理：") +
		"\n" + strings.Join(lines, "\n")
}

// ruleDomain returns the domain a provider rule names, or false when the rule
// is a pattern that cannot be turned into one (keyword: and regexp: rules match
// arbitrary names, so there is nothing to enumerate).
func ruleDomain(rule string) (string, bool) {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return "", false
	}
	lower := strings.ToLower(rule)
	for _, prefix := range []string{"domain:", "full:", "suffix:"} {
		if strings.HasPrefix(lower, prefix) {
			d := strings.TrimSpace(rule[len(prefix):])
			if d == "" {
				return "", false
			}
			return normalizePurgeDomain(d), true
		}
	}
	for _, prefix := range []string{"keyword:", "regexp:", "regex:", "include:", "exclude:"} {
		if strings.HasPrefix(lower, prefix) {
			return "", false
		}
	}
	// A bare rule is a domain literal in every text provider this bot edits.
	if strings.ContainsAny(rule, " /\\") {
		return "", false
	}
	return normalizePurgeDomain(rule), true
}
