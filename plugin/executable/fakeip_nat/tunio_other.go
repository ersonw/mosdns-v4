//go:build !linux && !darwin && !freebsd && !windows

package fakeipnat

// Fallback for targets without a tun implementation: `use_tun` is rejected with
// a clear error instead of silently doing nothing, so the plugin still builds
// and runs everywhere the release matrix covers.

import (
	"context"
	"errors"

	"go.uber.org/zap"
)

var errTunNotSupported = errors.New("the tun data path is not supported on this platform")

func (p *FakeIPNatPlugin) createTunPlatform(context.Context) (string, tunDevice, error) {
	p.L().Warn("fakeip nat: tun data path requested on an unsupported platform",
		zap.String("range", p.cidr))
	return "", nil, errTunNotSupported
}

func (p *FakeIPNatPlugin) tunConfigureCommands(string) []tunCommand { return nil }
