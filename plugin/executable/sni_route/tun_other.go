//go:build !linux

package sni_route

import (
	"context"
	"fmt"
)

func (p *Plugin) setupTun(context.Context) error {
	return fmt.Errorf("sni_route is only supported on linux")
}

func (p *Plugin) cleanupTun(context.Context) {}

func (p *Plugin) deleteTunLink(context.Context) {}
