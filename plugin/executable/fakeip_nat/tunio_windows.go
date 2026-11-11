//go:build windows

package fakeipnat

// Windows target: the device is a Wintun adapter (wintun.dll). The dll has to
// sit next to the executable; netsh configures the address and the range route.
// Creating/opening an adapter needs Administrator.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const (
	// wintunSessionCapacity is the size of the ring shared with the driver.
	wintunSessionCapacity = 0x400000
	// wintunTunnelType is only a label shown by Windows for the adapter.
	wintunTunnelType = "mosdns-fakeip"
)

type wintunDevice struct {
	adapter *wintun.Adapter
	session wintun.Session

	mu       sync.Mutex
	deadline time.Time
}

func (p *FakeIPNatPlugin) createTunPlatform(ctx context.Context) (string, tunDevice, error) {
	name, err := p.windowsTunName()
	if err != nil {
		return "", nil, err
	}
	p.L().Debug("fakeip nat: creating wintun adapter",
		zap.String("dev", name), zap.String("tunnel_type", wintunTunnelType), zap.Uint32("capacity", wintunSessionCapacity))
	adapter, err := wintun.CreateAdapter(name, wintunTunnelType, nil)
	if err != nil {
		return "", nil, fmt.Errorf("create wintun adapter %q (wintun.dll required, Administrator): %w", name, err)
	}
	session, err := adapter.StartSession(wintunSessionCapacity)
	if err != nil {
		_ = adapter.Close()
		return "", nil, fmt.Errorf("start wintun session on %q: %w", name, err)
	}
	p.L().Debug("wintun adapter created", zap.String("dev", name))
	p.L().Info("fakeip nat: wintun device ready", zap.String("dev", name))
	return name, &wintunDevice{adapter: adapter, session: session}, nil
}

// tunConfigureCommands sets the reserved /32 and adds the range route.
func (p *FakeIPNatPlugin) tunConfigureCommands(dev string) []tunCommand {
	return windowsConfigureTunCommands(dev, p.reservedFakeIP(), p.cidr, p.tunMTU)
}

// windowsTunName takes tun_dev when set, otherwise the first mth0..mth63 the
// wintun driver does not already have.
func (p *FakeIPNatPlugin) windowsTunName() (string, error) {
	if dev := p.tunDev; dev != "" {
		if len(dev) > wintun.AdapterNameMax {
			return "", fmt.Errorf("invalid tun_dev %q: windows adapter names are limited to %d characters", dev, wintun.AdapterNameMax)
		}
		p.L().Debug("fakeip nat: using configured wintun adapter", zap.String("dev", dev))
		return dev, nil
	}
	for i := 0; i < maxAutoTunIdx; i++ {
		name := fmt.Sprintf("%s%d", defaultTunBase, i)
		adapter, err := wintun.OpenAdapter(name)
		if err != nil {
			p.L().Debug("fakeip nat: free wintun adapter name found", zap.String("dev", name))
			return name, nil
		}
		_ = adapter.Close()
		p.L().Debug("fakeip nat: wintun adapter name already in use", zap.String("dev", name))
	}
	return "", fmt.Errorf("no free wintun adapter name in %s0..%s%d", defaultTunBase, defaultTunBase, maxAutoTunIdx-1)
}

func (d *wintunDevice) Read(p []byte) (int, error) {
	for {
		timeout := uint32(windows.INFINITE)
		d.mu.Lock()
		dl := d.deadline
		d.mu.Unlock()
		if !dl.IsZero() {
			remain := time.Until(dl)
			if remain <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timeout = uint32(remain/time.Millisecond) + 1
		}

		switch st, err := windows.WaitForSingleObject(d.session.ReadWaitEvent(), timeout); {
		case err != nil:
			return 0, err
		case st == uint32(windows.WAIT_TIMEOUT):
			return 0, os.ErrDeadlineExceeded
		}

		pkt, err := d.session.ReceivePacket()
		if err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
				continue
			}
			// End() on shutdown surfaces here, and the pump then exits.
			return 0, err
		}
		n := copy(p, pkt)
		d.session.ReleaseReceivePacket(pkt)
		return n, nil
	}
}

func (d *wintunDevice) Write(p []byte) (int, error) {
	pkt, err := d.session.AllocateSendPacket(len(p))
	if err != nil {
		return 0, err
	}
	copy(pkt, p)
	d.session.SendPacket(pkt)
	return len(p), nil
}

func (d *wintunDevice) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	d.deadline = t
	d.mu.Unlock()
	return nil
}

func (d *wintunDevice) Close() error {
	d.session.End()
	return d.adapter.Close()
}
