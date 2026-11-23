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
	"go.uber.org/zap"
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
	bp.L().Info("cbp_proxy: plugin initializing", zap.Int("proxy_provides", len(configs)))
	manager, err := NewManager(configs, bp.L())
	if err != nil {
		bp.L().Error("cbp_proxy: plugin initialization failed", zap.Error(err))
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &plugin{BP: bp, manager: manager, cancel: cancel}
	go manager.RunRefreshLoop(ctx)
	bp.L().Info("cbp_proxy: plugin ready", zap.Int("proxy_provides", len(configs)))
	return p, nil
}

// NewProxyDialer receives the part after the plugin tag. The root tag and the
// CBP node ID are separated here; only NODE_LIST entries are eligible.
func (p *plugin) NewProxyDialer(params string, insecure bool) (egress.Dialer, string, error) {
	p.L().Debug("cbp_proxy: provider dialer requested", zap.String("params", params), zap.Bool("insecure", insecure))
	params = strings.TrimSpace(params)
	if params == "" {
		return nil, "", fmt.Errorf("cbp_proxy: params are empty, want <tag>:<node_id>")
	}
	dialer, host, err := p.manager.NewProxyDialer(params, insecure)
	if err != nil {
		p.L().Warn("cbp_proxy: provider dialer failed", zap.String("params", params), zap.Error(err))
		return nil, "", err
	}
	p.L().Info("cbp_proxy: provider dialer ready", zap.String("params", params), zap.String("proxy_host", host))
	return dialer, host, nil
}

func (p *plugin) Close() error {
	p.L().Debug("cbp_proxy: plugin closing")
	if p.cancel != nil {
		p.cancel()
	}
	return nil
}
