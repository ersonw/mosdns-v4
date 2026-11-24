package sni_route

// proxy_bypass.go resolves the proxy host after the provider has actually
// logged in. egress_route registers an outlet during plugin init, before a
// deferred CBP login can know its relay address; the initial bypass set is
// therefore built around a placeholder. Once the DNS servers are up and the
// provider publishes the real host, the bypass4 set has to learn that address
// or the relay socket itself gets marked and sent back into this exit.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
)

const proxyBypassResolveTimeout = 20 * time.Second

func (p *Plugin) refreshProxyBypassAfterServers() {
	m := p.M()
	if m == nil || p.outlet == nil || p.runCtx == nil {
		return
	}
	select {
	case <-m.ServersStarted():
	case <-p.runCtx.Done():
		return
	}

	deadline := time.Now().Add(proxyBypassResolveTimeout)
	for {
		if p.runCtx.Err() != nil {
			return
		}
		host := p.outlet.OutletProxyHost()
		if host != "" {
			ips, err := net.LookupIP(host)
			if err == nil && len(ips) > 0 {
				var added []netip.Prefix
				for _, ip := range ips {
					v4 := ip.To4()
					if v4 == nil {
						continue
					}
					addr, ok := netip.AddrFromSlice(v4)
					if !ok {
						continue
					}
					prefix := netip.PrefixFrom(addr, 32)
					if p.hasBypass(prefix) {
						continue
					}
					added = append(added, prefix)
				}
				if len(added) > 0 {
					p.bypass = append(p.bypass, added...)
					p.addBypassPrefixes(added)
				}
				p.L().Info("sni_route: proxy bypass resolved after outlet login",
					zap.String("host", host), zap.Int("added", len(added)))
				return
			}
		}
		if time.Now().After(deadline) {
			p.L().Debug("sni_route: proxy bypass still unresolved after outlet login", zap.String("host", host))
			return
		}
		select {
		case <-time.After(500 * time.Millisecond):
		case <-p.runCtx.Done():
			return
		}
	}
}

func (p *Plugin) hasBypass(prefix netip.Prefix) bool {
	for _, existing := range p.bypass {
		if existing == prefix {
			return true
		}
	}
	return false
}

func (p *Plugin) addBypassPrefixes(prefixes []netip.Prefix) {
	if !p.nftInstalled || len(prefixes) == 0 {
		return
	}
	var b strings.Builder
	for _, prefix := range prefixes {
		fmt.Fprintf(&b, "add element inet %s bypass4 { %s }\n", p.args.NftTable, prefix.String())
	}
	f, err := os.CreateTemp("", "sni_route-bypass-*.nft")
	if err != nil {
		p.L().Warn("sni_route: create proxy bypass nft file failed", zap.Error(err))
		return
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err := f.WriteString(b.String()); err != nil {
		_ = f.Close()
		p.L().Warn("sni_route: write proxy bypass nft file failed", zap.Error(err))
		return
	}
	if err := f.Close(); err != nil {
		p.L().Warn("sni_route: close proxy bypass nft file failed", zap.Error(err))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := p.runner.Run(ctx, "nft", "-f", path); err != nil {
		p.L().Warn("sni_route: add proxy bypass nft element failed", zap.Error(err))
		return
	}
	p.L().Info("sni_route: proxy bypass added to nft set",
		zap.Int("added", len(prefixes)), zap.String("table", p.args.NftTable))
}
