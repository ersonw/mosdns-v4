//go:build darwin

package fakeipnat

// macOS target: the device is an utun control socket (AF_SYSTEM + SYSPROTO_CONTROL).
// Creating one needs no special entitlement; assigning the address and the
// route needs root, and a failure is reported instead of aborting the plugin.

import (
	"context"
	"fmt"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const (
	utunControlProtocol = 2 // SYSPROTO_CONTROL
	utunOptIfName       = 2 // UTUN_OPT_IFNAME
	utunHeaderLen       = 4
)

// createTunPlatform opens (and thereby creates) the utun device and returns it
// together with its kernel assigned name.
func (p *FakeIPNatPlugin) createTunPlatform(ctx context.Context) (string, tunDevice, error) {
	unit, err := p.darwinTunUnit(ctx)
	if err != nil {
		return "", nil, err
	}
	fd, name, err := openUtun(unit)
	if err != nil {
		return "", nil, err
	}
	p.L().Info("fakeip nat: utun device ready", zap.Int("unit", unit), zap.String("dev", name))
	return name, &fdTunDevice{fd: int32(fd), hdrLen: utunHeaderLen, name: name}, nil
}

// tunConfigureCommands gives the device the reserved /32 and routes the range.
func (p *FakeIPNatPlugin) tunConfigureCommands(dev string) []tunCommand {
	return bsdConfigureTunCommands(dev, p.reservedFakeIP(), p.cidr)
}

// darwinTunUnit decides which utun unit to ask the kernel for.
//
// On macOS the unit number of a *new* utun is assigned by the kernel: connect()
// with a non-zero unit only succeeds if that unit already exists, otherwise it
// fails with EBUSY ("resource busy"). So the only reliable way to create a fresh
// device is unit 0, which tells the kernel to pick the first free one; the real
// name is then read back from UTUN_OPT_IFNAME.
func (p *FakeIPNatPlugin) darwinTunUnit(ctx context.Context) (int, error) {
	if dev := p.tunDev; dev != "" {
		var unit int
		if _, err := fmt.Sscanf(dev, "utun%d", &unit); err != nil || unit < 0 {
			return 0, fmt.Errorf("invalid tun_dev %q: darwin expects utun<N>", dev)
		}
		// The configured device already exists: it belongs to another process
		// (VPN client, system service) and cannot be taken over.
		if _, err := p.runner.Run(ctx, "ifconfig", dev); err == nil {
			return 0, fmt.Errorf("tun_dev %q already exists on darwin and cannot be reused; remove tun_dev to let the kernel assign a free utun", dev)
		}
		p.L().Warn("fakeip nat: darwin assigns utun numbers itself, ignoring the requested unit",
			zap.String("requested", dev))
		return 0, nil
	}
	p.L().Debug("fakeip nat: letting the kernel assign a free utun unit")
	return 0, nil
}

// openUtun connects to com.apple.net.utun_control. A negative unit lets the
// kernel choose the first free one.
func openUtun(unit int) (int, string, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, utunControlProtocol)
	if err != nil {
		return -1, "", fmt.Errorf("utun socket: %w", err)
	}
	var ctl unix.CtlInfo
	copy(ctl.Name[:], "com.apple.net.utun_control")
	if err := unix.IoctlCtlInfo(fd, &ctl); err != nil {
		unix.Close(fd)
		return -1, "", fmt.Errorf("CTLIOCGINFO: %w", err)
	}
	sa := &unix.SockaddrCtl{ID: ctl.Id, Unit: uint32(unit)}
	if err := unix.Connect(fd, sa); err != nil {
		unix.Close(fd)
		return -1, "", fmt.Errorf("connect utun%d: %w", unit, err)
	}
	name, err := unix.GetsockoptString(fd, utunControlProtocol, utunOptIfName)
	if err != nil {
		unix.Close(fd)
		return -1, "", fmt.Errorf("UTUN_OPT_IFNAME: %w", err)
	}
	return fd, name, nil
}
