//go:build !linux

package asn_tun

import (
	"context"
	"fmt"
)

func (p *ASNTunPlugin) setupTun(context.Context) error {
	return fmt.Errorf("asn_tun is only supported on linux")
}

func (p *ASNTunPlugin) cleanupTun(context.Context) {}

func (p *ASNTunPlugin) deleteTunLink(context.Context) {}
