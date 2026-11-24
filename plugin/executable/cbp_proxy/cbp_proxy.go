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
	go func() {
		select {
		case <-bp.M().ServersStarted():
			manager.RunRefreshLoop(ctx)
		case <-ctx.Done():
		}
	}()
	bp.L().Info("cbp_proxy: plugin ready, node refresh and login deferred until DNS servers start",
		zap.Int("proxy_provides", len(configs)))
	return p, nil
}

// NewProxyDialer receives the part after the plugin tag. The root tag and the
// CBP node ID are separated here; only NODE_LIST entries are eligible.
//
// The provider is registered during plugin init, but bootstrap and AUTH are
// deferred until the DNS servers report that they are listening. Doing the
// handshake here would resolve api.aa2.dev through mosdns' own not-yet-open
// 127.0.0.1:53 socket and deadlock the startup pass.
func (p *plugin) NewProxyDialer(params string, insecure bool) (egress.Dialer, string, error) {
	p.L().Debug("cbp_proxy: provider dialer requested", zap.String("params", params), zap.Bool("insecure", insecure))
	params = strings.TrimSpace(params)
	if params == "" {
		return nil, "", fmt.Errorf("cbp_proxy: params are empty, want <tag>:<node_id>")
	}
	tag, nodeName, ok := strings.Cut(params, ":")
	if !ok || strings.TrimSpace(tag) == "" || strings.TrimSpace(nodeName) == "" {
		return nil, "", fmt.Errorf("cbp_proxy: want <tag>:<node_id_or_label>, got %q", params)
	}
	tag = strings.TrimSpace(tag)
	nodeName = strings.TrimSpace(nodeName)
	if _, ok := p.manager.byTag[tag]; !ok {
		return nil, "", fmt.Errorf("cbp_proxy: proxy_provides tag %q is not configured", tag)
	}
	dialer := newStartupDialer(p.manager, params, insecure, p.M().ServersStarted(), p.L())
	p.L().Info("cbp_proxy: provider outlet registered, login deferred until DNS servers start",
		zap.String("params", params), zap.String("node_hint", nodeName))
	// egress_route only needs a non-empty placeholder here: it records the
	// proxy host for its logs and for borrowers' "is this a proxy" decision.
	// The real relay host is only known after bootstrap, which now happens
	// after this registration.
	return dialer, nodeName, nil
}

func (p *plugin) Close() error {
	p.L().Debug("cbp_proxy: plugin closing")
	if p.cancel != nil {
		p.cancel()
	}
	return nil
}
