//go:build linux

package sni_route

import (
	"context"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const maxTunNameLen = 15

func (p *Plugin) setupTun(ctx context.Context) error {
	dev := p.tunDev
	if len(dev) > maxTunNameLen {
		return fmt.Errorf("tun_dev %q exceeds %d characters", dev, maxTunNameLen)
	}
	created := false
	if _, err := p.runner.Run(ctx, "ip", "link", "show", "dev", dev); err != nil {
		if _, err := p.runner.Run(ctx, "ip", "tuntap", "add", "dev", dev, "mode", "tun"); err != nil {
			return fmt.Errorf("create tun %q: %w", dev, err)
		}
		created = true
	}
	p.tunCreated = created
	f, err := openTunDevice(dev)
	if err != nil {
		return err
	}
	mtu := p.args.TunMTU
	if _, err := p.runner.Run(ctx, "ip", "link", "set", "dev", dev, "mtu", fmt.Sprint(mtu), "up"); err != nil {
		_ = f.Close()
		return fmt.Errorf("bring up tun %q: %w", dev, err)
	}
	if _, err := p.runner.Run(ctx, "ip", "addr", "replace", p.tunAddr.String()+"/32", "dev", dev); err != nil {
		_ = f.Close()
		return fmt.Errorf("assign tun address: %w", err)
	}
	// The stack is IPv4-only. Leaving IPv6 enabled makes the kernel inject
	// MLD/DAD into the device, which the stack would only drop.
	_, _ = p.runner.Run(ctx, "sysctl", "-w", "net.ipv6.conf."+dev+".disable_ipv6=1")

	p.tunFile = f
	p.L().Info("sni_route: tun device ready",
		zap.String("dev", dev),
		zap.String("addr", p.tunAddr.String()+"/32"),
		zap.Int("mtu", mtu))
	return nil
}

func (p *Plugin) cleanupTun(ctx context.Context) {
	if !p.tunCreated || p.tunDev == "" {
		return
	}
	p.deleteTunLink(ctx)
}

func (p *Plugin) deleteTunLink(ctx context.Context) {
	if p.tunDev == "" {
		return
	}
	if _, err := p.runner.Run(ctx, "ip", "link", "show", "dev", p.tunDev); err != nil {
		return
	}
	if _, err := p.runner.Run(ctx, "ip", "link", "del", "dev", p.tunDev); err != nil {
		p.L().Debug("sni_route: deleting tun link failed", zap.String("dev", p.tunDev), zap.Error(err))
		return
	}
	p.L().Info("sni_route: tun link removed", zap.String("dev", p.tunDev))
}

func openTunDevice(dev string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(dev)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("ifreq %q: %w", dev, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF %q: %w", dev, err)
	}
	return os.NewFile(uintptr(fd), dev), nil
}

func parseLinkNames(out string) map[string]bool {
	names := make(map[string]bool)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSuffix(fields[1], ":")
		if i := strings.IndexByte(name, '@'); i >= 0 {
			name = name[:i]
		}
		names[name] = true
	}
	return names
}
