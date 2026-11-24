package cbp_proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
)

// MainCandidate is one main-server TCP entry returned by the HTTPS API. It is
// not a CBP node: it only tells the client which main server to authenticate
// against for NODE_LIST.
type MainCandidate struct {
	ID        string
	Role      string
	Addresses []string
	PublicIP  string
}

type bootstrapResponse struct {
	Server *struct {
		PublicIP   string `json:"public_ip"`
		Candidates []struct {
			ID        string   `json:"id"`
			Role      string   `json:"role"`
			Addresses []string `json:"addresses"`
			Endpoint  string   `json:"endpoint"`
			PublicIP  string   `json:"public_ip"`
		} `json:"candidates"`
		CoordinatorAddresses []string `json:"coordinator_addresses"`
		CoordinatorEndpoint  string   `json:"coordinator_endpoint"`
	} `json:"server"`
}

// FetchMainCandidates asks the HTTPS API for main-server TCP candidates.
// The response's edge payload is intentionally ignored: CBP nodes must come
// from NODE_LIST, never from this bootstrap response.
func FetchMainCandidates(ctx context.Context, cfg coremain.ProxyProvideConfig, insecure bool) ([]MainCandidate, error) {
	endpoint := coremain.ProxyProvideBootstrapURL(cfg.Domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("cbp_proxy: create bootstrap request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if token := strings.TrimSpace(cfg.Token); token != "" {
		// Non-desktop API auth. The server only accepts the API key in
		// X-API-Key; never send it as Authorization or impersonate the
		// desktop client's signed identity headers.
		req.Header.Set("X-API-Key", token)
	}
	transport := &http.Transport{
		Proxy:       http.ProxyFromEnvironment,
		DialContext: bootstrapDialContext,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecure,
		},
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cbp_proxy: bootstrap %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("cbp_proxy: read bootstrap: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cbp_proxy: bootstrap HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out bootstrapResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("cbp_proxy: parse bootstrap: %w", err)
	}
	if out.Server == nil {
		return nil, errors.New("cbp_proxy: bootstrap response has no server block")
	}

	serverPublicIP := strings.TrimSpace(out.Server.PublicIP)
	var candidates []MainCandidate
	for _, raw := range out.Server.Candidates {
		addresses := normalizeCandidateAddresses(append(raw.Addresses, raw.Endpoint))
		if len(addresses) == 0 {
			continue
		}
		publicIP := strings.TrimSpace(raw.PublicIP)
		if publicIP == "" {
			publicIP = serverPublicIP
		}
		candidates = append(candidates, MainCandidate{
			ID:        strings.TrimSpace(raw.ID),
			Role:      strings.TrimSpace(raw.Role),
			Addresses: addresses,
			PublicIP:  publicIP,
		})
	}
	if len(candidates) == 0 {
		addresses := normalizeCandidateAddresses(append(out.Server.CoordinatorAddresses, out.Server.CoordinatorEndpoint))
		if len(addresses) > 0 {
			candidates = append(candidates, MainCandidate{
				ID:        "main",
				Role:      "main",
				Addresses: addresses,
				PublicIP:  strings.TrimSpace(out.Server.PublicIP),
			})
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("cbp_proxy: bootstrap returned no main-server TCP candidates")
	}
	return candidates, nil
}

func normalizeCandidateAddresses(raw []string) []string {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, value := range raw {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, "://") {
			u, err := url.Parse(value)
			if err != nil {
				continue
			}
			value = u.Host
		}
		value = strings.TrimSpace(value)
		host, port, err := net.SplitHostPort(value)
		if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
			continue
		}
		normalized := net.JoinHostPort(strings.Trim(host, "[]"), port)
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out
}

// bootstrapDNSServers are used only for the HTTPS bootstrap request. At
// startup mosdns has not opened 127.0.0.1:53 yet, while the system resolver
// points at that same address; resolving api.aa2.dev through the system
// resolver would therefore deadlock. The bootstrap control plane is allowed
// to use these public resolvers independently, then the normal data path
// still uses the configured DNS pipeline.
var bootstrapDNSServers = []string{"1.1.1.1:53", "8.8.8.8:53"}

func bootstrapDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil && ip.IsValid() {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	if strings.EqualFold(host, "localhost") {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}

	addrs, lookupErr := lookupBootstrapHost(ctx, host)
	if lookupErr == nil && len(addrs) > 0 {
		var d net.Dialer
		var lastErr error
		for _, addr := range addrs {
			conn, dialErr := d.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, fmt.Errorf("cbp_proxy: bootstrap dial %s: %w", address, lastErr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func lookupBootstrapHost(ctx context.Context, host string) ([]netip.Addr, error) {
	var lastErr error
	for _, server := range bootstrapDNSServers {
		server := server
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, server)
			},
		}
		addrs, err := resolver.LookupNetIP(ctx, "ip", host)
		if err == nil && len(addrs) > 0 {
			// Prefer IPv4; a host with unreachable IPv6 should not make the
			// bootstrap wait for an IPv6 connect timeout.
			sort.SliceStable(addrs, func(i, j int) bool {
				return addrs[i].Is4() && !addrs[j].Is4()
			})
			return addrs, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no bootstrap DNS server returned an address")
	}
	return nil, lastErr
}
