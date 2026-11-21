package sni_route

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/executable_seq"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

// resolveMatchers turns query_matcher plugin tags into borrowable matchers.
// The tags must be declared before the sni_route plugin, the same rule that
// applies to egress_route plugin tags.
func resolveMatchers(bp *coremain.BP, tags []string) ([]executable_seq.Matcher, error) {
	if len(tags) == 0 {
		return nil, nil
	}
	available := bp.M().GetMatchers()
	seen := make(map[string]struct{}, len(tags))
	var out []executable_seq.Matcher
	for _, raw := range tags {
		tag := strings.TrimSpace(raw)
		if tag == "" {
			continue
		}
		if _, dup := seen[tag]; dup {
			continue
		}
		seen[tag] = struct{}{}
		matcher, ok := available[tag]
		if !ok || matcher == nil {
			return nil, fmt.Errorf("query matcher %q is not loaded: declare the matcher plugin before sni_route", tag)
		}
		out = append(out, matcher)
	}
	return out, nil
}

// matchSNI runs the borrowed query matchers against a synthetic A query built
// from the TLS server name. The client address is carried in RequestMeta, so a
// matcher that also tests client_ip sees the intercepted client.
func (p *Plugin) matchSNI(ctx context.Context, host string, client netip.Addr) bool {
	if p.rules.Match(host) {
		return true
	}
	if host == "" || len(p.matchers) == 0 {
		return false
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(host), dns.TypeA)
	qCtx := query_context.NewContext(q, &query_context.RequestMeta{ClientAddr: client})
	for _, matcher := range p.matchers {
		matched, err := matcher.Match(ctx, qCtx)
		if err != nil {
			p.L().Warn("sni_route: query matcher failed", zap.String("sni", host), zap.Error(err))
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// domainMatcher matches a TLS server name against a suffix list.
//
// The list is suffix based on purpose: a rule "tiktokv.com" also covers
// "api16-core.tiktokv.com" and "api31-normal-alisg.tiktokv.com". A rule that
// starts with "*." is accepted and means the same thing, because that is how
// people write it.
type domainMatcher struct {
	suffixes []string
	set      map[string]struct{}
}

func newDomainMatcher(entries []string) (*domainMatcher, error) {
	m := &domainMatcher{set: make(map[string]struct{})}
	for _, raw := range entries {
		entry, ok := normalizeDomainRule(raw)
		if !ok {
			continue
		}
		if _, dup := m.set[entry]; dup {
			continue
		}
		m.set[entry] = struct{}{}
		m.suffixes = append(m.suffixes, entry)
	}
	if len(m.suffixes) == 0 {
		return nil, fmt.Errorf("no usable domain rule")
	}
	return m, nil
}

func normalizeDomainRule(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "//") {
		return "", false
	}
	raw = strings.ToLower(raw)
	raw = strings.TrimPrefix(raw, "domain:")
	raw = strings.TrimPrefix(raw, "*.")
	raw = strings.Trim(raw, ".")
	if raw == "" {
		return "", false
	}
	return raw, true
}

func (m *domainMatcher) match(host string) bool {
	if m == nil {
		return false
	}
	host = strings.ToLower(strings.Trim(host, "."))
	if host == "" {
		return false
	}
	if _, ok := m.set[host]; ok {
		return true
	}
	for _, suffix := range m.suffixes {
		if strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func (m *domainMatcher) len() int {
	if m == nil {
		return 0
	}
	return len(m.suffixes)
}

// ruleSet is the matcher plus the file it was read from. It is replaced whole
// on reload, so a dial never sees a half-built suffix list.
type ruleSet struct {
	mu      sync.RWMutex
	matcher *domainMatcher
}

func (r *ruleSet) Match(host string) bool {
	r.mu.RLock()
	m := r.matcher
	r.mu.RUnlock()
	return m.match(host)
}

func (r *ruleSet) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.matcher.len()
}

func (r *ruleSet) Replace(m *domainMatcher) {
	r.mu.Lock()
	r.matcher = m
	r.mu.Unlock()
}

func loadDomainFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		out = append(out, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
