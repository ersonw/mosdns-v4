//go:build !linux

package asn_tun

import (
	"context"
	"fmt"
)

func (p *ASNTunPlugin) setupTun(context.Context) error {
	return fmt.Errorf("asn_tun is only supported on linux")
}
