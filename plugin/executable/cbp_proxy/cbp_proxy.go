// Package cbp_proxy exposes the CBP node list as an egress provider. Its
// proxy syntax is <plugin-tag>:<proxy_provides-tag>:<cbp-node-id-or-label>,
// e.g. "cbp_proxy:cbp_sg:edge-sg-1". The node selector matches ID first and
// falls back to a unique node label.
package cbp_proxy

import (
	"context"
	"fmt"
	"strings"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/egress"
)

const PluginType = "cbp_proxy"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

// Args is intentionally empty: the main-server entries live in the root
// proxy_provides block, not in each egress_route.
type Args struct{}

type plugin struct {
	*coremain.BP
	manager *Manager
	cancel  context.CancelFunc
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	configs := bp.M().GetProxyProvides()
	if len(configs) == 0 {
		return nil, fmt.Errorf("cbp_proxy: proxy_provides is empty, nothing to serve")
	}
	manager, err := NewManager(configs, bp.L())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &plugin{BP: bp, manager: manager, cancel: cancel}
	go manager.RunRefreshLoop(ctx)
	return p, nil
}

// NewProxyDialer receives the part after the plugin tag. The root tag and the
// CBP node ID are separated here; only NODE_LIST entries are eligible.
func (p *plugin) NewProxyDialer(params string, insecure bool) (egress.Dialer, string, error) {
	params = strings.TrimSpace(params)
	if params == "" {
		return nil, "", fmt.Errorf("cbp_proxy: params are empty, want <tag>:<node_id>")
	}
	return p.manager.NewProxyDialer(params, insecure)
}

func (p *plugin) Close() error {
	if p.cancel != nil {
		p.cancel()
	}
	return nil
}
