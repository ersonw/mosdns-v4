package fakeipnat

// This file is the platform independent half of the tun device handling. Every
// release target (darwin, linux, freebsd, windows) implements the same small
// interface, so the packet pump, the userspace stack and the rest of the plugin
// stay identical across operating systems.
//
// The platform opens (and thereby creates) the device first and configures the
// address/route afterwards: on darwin and windows the interface only exists
// while its handle is held, so it must not be reopened between setup and
// pumping.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	// tunPollInterval bounds how long a read may block where deadlines are
	// supported, so shutdown is noticed even if the descriptor cannot be closed
	// from another goroutine.
	tunPollInterval = time.Second
	// tunReadSlack leaves room for a packet that grew after checksum rewrite.
	tunReadSlack = 64
)

// tunDevice is the minimal view of a tun interface the pump needs. Windows has
// no file descriptor, so Read/Write/Close are the only common operations.
type tunDevice interface {
	Read(buf []byte) (int, error)
	Write(pkt []byte) (int, error)
	// SetReadDeadline may be a no-op on platforms without deadline support.
	SetReadDeadline(t time.Time) error
	Close() error
}

// tunCommand is one external command used to create or configure the device.
type tunCommand struct {
	args []string
	// optional commands (route cleanup, for instance) are attempted but their
	// failure does not abort the setup.
	optional bool
}

// setupTun asks the platform for the device, keeps it open, assigns the
// reserved address and routes the range into it.
func (p *FakeIPNatPlugin) setupTun(ctx context.Context) (tunDevice, error) {
	requested := p.tunDev
	if requested == "" {
		p.L().Debug("fakeip nat: requesting an auto named tun device",
			zap.String("base", defaultTunBase), zap.Int("max_index", maxAutoTunIdx-1))
	} else {
		p.L().Debug("fakeip nat: requesting the configured tun device", zap.String("dev", requested))
	}
	name, d, err := p.createTunPlatform(ctx)
	if err != nil {
		return nil, err
	}
	if err := p.applyTunCommands(ctx, p.tunConfigureCommands(name)); err != nil {
		_ = d.Close()
		return nil, err
	}
	p.tunDev = name
	p.L().Info("tun data path ready",
		zap.String("dev", name),
		zap.String("addr", p.reservedFakeIP()),
		zap.String("range", p.cidr))
	return d, nil
}

// applyTunCommands runs the planned commands in order with the given runner.
func (p *FakeIPNatPlugin) applyTunCommands(ctx context.Context, cmds []tunCommand) error {
	p.L().Debug("fakeip nat: applying tun commands", zap.Int("count", len(cmds)))
	for _, c := range cmds {
		if len(c.args) == 0 {
			continue
		}
		out, err := p.runner.Run(ctx, c.args[0], c.args[1:]...)
		if err != nil {
			if c.optional {
				p.L().Debug("optional tun command failed",
					zap.Strings("cmd", c.args), zap.String("out", out), zap.Error(err))
				continue
			}
			p.L().Debug("fakeip nat: required tun command failed",
				zap.Strings("cmd", c.args), zap.String("out", out), zap.Error(err))
			// The command output carries the real reason (for example
			// "ifconfig: ioctl (SIOCAIFADDR): Destination address required"),
			// so it travels with the error instead of staying at debug level.
			msg := strings.TrimSpace(out)
			if msg != "" {
				return fmt.Errorf("%s: %w: %s", strings.Join(c.args, " "), err, msg)
			}
			return fmt.Errorf("%s: %w", strings.Join(c.args, " "), err)
		}
		p.L().Debug("fakeip nat: tun command applied", zap.Strings("cmd", c.args))
	}
	return nil
}

// runTunDevice pumps packets between the device and the userspace stack until
// ctx is cancelled.
func (p *FakeIPNatPlugin) runTunDevice(ctx context.Context, d tunDevice, st *tunStack) error {
	p.L().Info("tun device attached", zap.String("dev", p.tunDev))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		p.readFromTun(ctx, d, st)
	}()
	go func() {
		defer wg.Done()
		p.writeToTun(ctx, d, st)
	}()

	<-ctx.Done()
	p.L().Debug("fakeip nat: shutting down tun device loops", zap.String("dev", p.tunDev))
	if err := d.Close(); err != nil {
		p.L().Warn("fakeip nat: close tun device failed", zap.String("dev", p.tunDev), zap.Error(err))
	}
	wg.Wait()
	p.L().Info("tun device detached", zap.String("dev", p.tunDev))
	return nil
}

func (p *FakeIPNatPlugin) readFromTun(ctx context.Context, d tunDevice, st *tunStack) {
	buf := make([]byte, int(st.mtu)+tunReadSlack)
	for {
		if ctx.Err() != nil {
			return
		}
		_ = d.SetReadDeadline(time.Now().Add(tunPollInterval))
		n, err := d.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// A deadline hit is expected: it is how shutdown is noticed on
			// platforms without a closable descriptor.
			if os.IsTimeout(err) {
				continue
			}
			p.L().Debug("tun read stopped", zap.Error(err))
			return
		}
		if n < ipv4HeaderMinLen {
			p.L().Debug("fakeip nat: short packet dropped", zap.Int("len", n))
			continue
		}
		// A freshly created device still has IPv6 enabled, and the kernel feeds
		// its own neighbour discovery traffic into the tun. Only IPv4 is
		// proxied, so everything else is dropped before it reaches the stack.
		if v := buf[0] >> 4; v != 4 {
			p.L().Debug("fakeip nat: non-ipv4 packet dropped",
				zap.Int("len", n), zap.Uint8("version", v))
			continue
		}
		// Parsing is only needed for the log line, so it is gated by the level:
		// the hot path stays allocation free when debug logging is off.
		if ce := p.L().Check(zap.DebugLevel, "fakeip nat: packet from tun"); ce != nil {
			if desc, perr := describePacket(buf[:n]); perr != nil {
				ce.Write(zap.Int("len", n), zap.Error(perr))
			} else {
				ce.Write(zap.Int("len", n), zap.String("packet", desc))
			}
		}
		// The device is this plugin's inlet, not a general packet sink: a
		// packet some other route pushed into it has no mapping and no outlet
		// assignment, so it is dropped here instead of being handed to the
		// stack and dialled out.
		if !p.ownsTunDestination(buf[:n]) {
			if ce := p.L().Check(zap.DebugLevel, "fakeip nat: packet for an unowned destination dropped"); ce != nil {
				ce.Write(zap.Int("len", n))
			}
			continue
		}
		// A packet whose TTL ran out is answered here, because the stack never
		// forwards: this is the first hop traceroute sees.
		if reply, drop := st.precheck(buf[:n]); drop {
			if reply == nil {
				p.L().Debug("fakeip nat: ttl expired packet dropped, no reply built")
				continue
			}
			if _, werr := d.Write(reply); werr != nil {
				p.L().Warn("fakeip nat: write icmp time exceeded failed",
					zap.Int("len", len(reply)), zap.Error(werr))
			} else {
				p.L().Debug("fakeip nat: icmp time exceeded sent", zap.Int("len", len(reply)))
			}
			continue
		}
		// Keep the bytes the client sent: an ICMP error must quote them, or
		// the client kernel cannot match it to its socket.
		if n >= ipv4HeaderMinLen && buf[9] == protoUDP {
			p.rememberClientQuote(buf[:n])
		}
		// Echo requests for a fake ip are forwarded to the real ip: the stack
		// would drop them, because the destination is not a local address.
		if p.handleICMPEcho(st, buf[:n]) {
			continue
		}
		// The packet is copied into the stack, so reusing buf is safe.
		st.inject(buf[:n])
	}
}

func (p *FakeIPNatPlugin) writeToTun(ctx context.Context, d tunDevice, st *tunStack) {
	for {
		pkt := st.nextPacket(ctx)
		if pkt == nil {
			p.L().Debug("fakeip nat: tun write loop stopped", zap.String("dev", p.tunDev))
			return
		}
		n, err := d.Write(pkt)
		if err != nil {
			// The device is gone: the read loop stops right after this, but the
			// whole data path is unavailable, so warn instead of hiding it.
			p.L().Warn("fakeip nat: tun write failed",
				zap.String("dev", p.tunDev), zap.Int("len", n), zap.Error(err))
			return
		}
		p.L().Debug("fakeip nat: packet to tun", zap.String("dev", p.tunDev), zap.Int("len", n))
	}
}
