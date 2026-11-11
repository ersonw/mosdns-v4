//go:build linux

package fakeipnat

// Linux tun device: /dev/net/tun plus iproute2. Requires CAP_NET_ADMIN.

import (
	"context"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// Linux IFNAMSIZ is 16 bytes including the terminating NUL.
const maxTunNameLen = 15

// createTunPlatform requests (or reuses) the device, attaches to it and returns
// the open handle.
func (p *FakeIPNatPlugin) createTunPlatform(ctx context.Context) (string, tunDevice, error) {
	dev := p.tunDev
	if dev == "" {
		var err error
		dev, err = p.pickTunName(ctx)
		if err != nil {
			return "", nil, err
		}
	} else if len(dev) > maxTunNameLen {
		return "", nil, fmt.Errorf("invalid tun_dev %q: linux device names are limited to %d characters", dev, maxTunNameLen)
	}

	if _, err := p.runner.Run(ctx, "ip", "link", "show", "dev", dev); err != nil {
		// The device does not exist yet, so ask the system for a new one.
		p.L().Debug("fakeip nat: tun device missing, creating it", zap.String("dev", dev))
		if err := p.applyTunCommands(ctx, linuxCreateTunCommands(dev)); err != nil {
			return "", nil, fmt.Errorf("create tun device %q: %w", dev, err)
		}
	} else {
		p.L().Debug("fakeip nat: reusing existing tun device", zap.String("dev", dev))
	}
	d, err := p.openTunDevice(dev)
	if err != nil {
		return "", nil, err
	}
	p.L().Info("fakeip nat: tun device ready", zap.String("dev", dev))
	return dev, d, nil
}

// tunConfigureCommands assigns the reserved address and routes the range into
// the device. The device is already attached, so the link name is final.
func (p *FakeIPNatPlugin) tunConfigureCommands(dev string) []tunCommand {
	return linuxConfigureTunCommands(dev, p.reservedFakeIP(), p.cidr)
}

// pickTunName walks mth0, mth1, ... and takes the first name that is free. A
// device left behind by a previous run is reused when it still carries the
// reserved address, so restarts do not leak one device per start.
func (p *FakeIPNatPlugin) pickTunName(ctx context.Context) (string, error) {
	addr := p.reservedFakeIP()
	for i := 0; i < maxAutoTunIdx; i++ {
		name := fmt.Sprintf("%s%d", defaultTunBase, i)
		if _, err := p.runner.Run(ctx, "ip", "link", "show", "dev", name); err != nil {
			p.L().Debug("fakeip nat: free tun name found", zap.String("dev", name), zap.Int("index", i))
			return name, nil
		}
		if out, err := p.runner.Run(ctx, "ip", "addr", "show", "dev", name); err == nil && strings.Contains(out, addr) {
			p.L().Debug("fakeip nat: reusing leftover tun device with the reserved address",
				zap.String("dev", name), zap.String("addr", addr))
			return name, nil
		}
		p.L().Debug("fakeip nat: tun name already taken, trying the next one",
			zap.String("dev", name), zap.String("addr", addr))
	}
	return "", fmt.Errorf("no free tun device name in %s0..%s%d", defaultTunBase, defaultTunBase, maxAutoTunIdx-1)
}

// openTunDevice attaches to an existing device for packet I/O.
func (p *FakeIPNatPlugin) openTunDevice(dev string) (tunDevice, error) {
	if len(dev) > maxTunNameLen {
		return nil, fmt.Errorf("invalid tun device name %q", dev)
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(dev)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("ifreq for %q: %w", dev, err)
	}
	// IFF_NO_PI: the kernel must not prepend the 4 byte tun flags header, so
	// packets come out exactly as the stack expects them.
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF on %q: %w", dev, err)
	}
	p.L().Debug("tun device opened", zap.String("dev", dev))
	return os.NewFile(uintptr(fd), dev), nil
}
