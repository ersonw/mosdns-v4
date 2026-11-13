//go:build linux

package asn_tun

import (
	"context"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const maxTunNameLen = 15

func (p *ASNTunPlugin) setupTun(ctx context.Context) error {
	dev, err := p.chooseTunName(ctx)
	if err != nil {
		return err
	}
	if _, err := p.runner.Run(ctx, "ip", "link", "show", "dev", dev); err != nil {
		if _, err := p.runner.Run(ctx, "ip", "tuntap", "add", "dev", dev, "mode", "tun"); err != nil {
			return fmt.Errorf("create tun %q: %w", dev, err)
		}
	}
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

	p.tunDev = dev
	p.tunFile = f
	p.L().Info("asn_tun: tun device ready",
		zap.String("dev", dev),
		zap.String("addr", p.tunAddr.String()+"/32"),
		zap.Int("mtu", mtu))
	return nil
}

func (p *ASNTunPlugin) chooseTunName(ctx context.Context) (string, error) {
	if len(p.tunDev) > maxTunNameLen {
		return "", fmt.Errorf("tun_dev %q exceeds %d characters", p.tunDev, maxTunNameLen)
	}
	out, err := p.runner.Run(ctx, "ip", "-o", "link", "show")
	if err != nil {
		return "", fmt.Errorf("list links: %w", err)
	}
	existing := parseLinkNames(out)
	if p.tunDev != "" {
		// A configured name is intentional: reuse it even if it exists.
		if existing[p.tunDev] {
			return p.tunDev, nil
		}
		return p.tunDev, nil
	}
	for i := 0; i < 64; i++ {
		name := fmt.Sprintf("asn%d", i)
		if !existing[name] {
			return name, nil
		}
	}
	return "", fmt.Errorf("no free asn tun name")
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
