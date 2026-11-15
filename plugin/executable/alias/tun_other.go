//go:build !linux

package alias

// The data path needs a tun device and the iproute2 outlet, which this build
// does not provide. The plugin still serves DNS answers, so a caller on an
// unsupported platform gets a clear startup error instead of a silent no-op.

import (
	"context"
	"fmt"
	"net/netip"

	"go.uber.org/zap"
)

type tunPlane struct{}

func startTunPlane(_ *plugin, _ *Args, _ netip.Prefix, _ netip.Addr, _ uint32) (*tunPlane, error) {
	return nil, fmt.Errorf("alias: the tun data path is only implemented on linux")
}

func (t *tunPlane) stop() {}

func (t *tunPlane) readLoop(context.Context)  {}
func (t *tunPlane) writeLoop(context.Context) {}

var _ = zap.String
