//go:build freebsd

package fakeipnat

// FreeBSD target: /dev/tun<N> is a cloneable layer-3 device. The address-family
// header is explicitly disabled (TUNSIFHEAD) so packets are plain IPv4, and the
// interface is configured with ifconfig/route.

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const (
	// TUNSIFHEAD _IOW('t', 96, int) and TUNSIFMODE _IOW('t', 94, int); x/sys
	// does not export them for freebsd, so the values are spelled out.
	tunSIFHEAD = 0x80047460
	tunSIFMODE = 0x8004745e
)

func (p *FakeIPNatPlugin) createTunPlatform(ctx context.Context) (string, tunDevice, error) {
	dev := p.tunDev
	if dev == "" {
		var err error
		dev, err = p.pickFreeBSDTunName(ctx)
		if err != nil {
			return "", nil, err
		}
	} else {
		p.L().Debug("fakeip nat: using configured tun device", zap.String("dev", dev))
	}
	fd, err := unix.Open("/dev/"+dev, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", nil, fmt.Errorf("open /dev/%s: %w", dev, err)
	}
	// FreeBSD may prefix packets with a 4 byte address family header; the stack
	// expects raw IPv4, so turn it off and keep the point-to-point tun mode.
	if err := unix.IoctlSetInt(fd, tunSIFHEAD, 0); err != nil {
		unix.Close(fd)
		return "", nil, fmt.Errorf("TUNSIFHEAD on %s: %w", dev, err)
	}
	if err := unix.IoctlSetInt(fd, tunSIFMODE, unix.IFF_POINTOPOINT); err != nil {
		unix.Close(fd)
		return "", nil, fmt.Errorf("TUNSIFMODE on %s: %w", dev, err)
	}
	p.L().Info("fakeip nat: tun device ready",
		zap.String("dev", dev), zap.String("header", "none"), zap.String("mode", "point-to-point"))
	return dev, &fdTunDevice{fd: int32(fd), hdrLen: 0, name: dev}, nil
}

func (p *FakeIPNatPlugin) tunConfigureCommands(dev string) []tunCommand {
	return bsdConfigureTunCommands(dev, p.reservedFakeIP(), p.cidr)
}

func (p *FakeIPNatPlugin) pickFreeBSDTunName(ctx context.Context) (string, error) {
	for i := 0; i < maxAutoTunIdx; i++ {
		name := fmt.Sprintf("tun%d", i)
		if _, err := p.runner.Run(ctx, "ifconfig", name); err != nil {
			p.L().Debug("fakeip nat: free tun device found", zap.String("dev", name))
			return name, nil
		}
		p.L().Debug("fakeip nat: tun device already in use", zap.String("dev", name))
	}
	return "", fmt.Errorf("no free tun device in tun0..tun%d", maxAutoTunIdx-1)
}
