package egress

import "fmt"

// Provider is the bridge between a protocol plugin and egress_route. A proxy
// link whose first colon-separated segment names a registered provider is
// handed to that provider instead of being parsed as a built-in scheme.
//
// params is everything after the first colon, for example
// "cbp_sg:edge-sg-1". The returned dialer is a normal Dialer: the caller opens
// a connection to the target, writes the request and reads the response. The
// returned proxyHost is the bare host of the far endpoint (no port);
// egress_route uses it to keep the proxy socket itself out of the marking that
// points at this exit. Borrowers resolve this name with the host resolver, so a
// host:port value would fail that lookup.
type Provider interface {
	NewProxyDialer(params string, insecure bool) (Dialer, string, error)
}

// ProviderFunc adapts a function to Provider.
type ProviderFunc func(params string, insecure bool) (Dialer, string, error)

func (f ProviderFunc) NewProxyDialer(params string, insecure bool) (Dialer, string, error) {
	if f == nil {
		return nil, "", fmt.Errorf("egress: nil proxy provider")
	}
	return f(params, insecure)
}
