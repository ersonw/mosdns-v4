//go:build linux

package alias

// tun_linux.go owns the platform side of the data path: request the device,
// give it the first host of the range with the range mask (the kernel then
// derives the connected route for the whole segment), pin the outlet into a
// dedicated table, and pump packets between the device and the stack.

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/routepolicy"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const (
	autoDevBase   = "lga"
	maxAutoDevIdx = 64
	maxDevNameLen = 15
	cmdTimeout    = 8 * time.Second
)

type tunPlane struct {
	dev     string
	file    *os.File
	stk     *tunStack
	owner   *plugin
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	writeMu sync.Mutex
	once    sync.Once
	clean   []func()
}

var cleanupTunOnce sync.Once

func startTunPlane(p *plugin, cfg *Args, prefix netip.Prefix, local netip.Addr, mtu uint32) (*tunPlane, error) {
	ctx := context.Background()
	if strings.TrimSpace(cfg.TunDev) == "" {
		// A killed process leaves its auto-named devices behind; they keep the
		// same address and connected route, so packets would be steered into
		// an interface nobody reads. Remove them once per process before the
		// first alias tag creates its own.
		cleanupTunOnce.Do(func() { cleanupStaleTunDevs(ctx) })
	}
	dev, err := pickTunDev(ctx, cfg.TunDev)
	if err != nil {
		return nil, err
	}
	if err := ensureTunDev(ctx, dev); err != nil {
		return nil, err
	}
	if err := configureTunDev(ctx, dev, local, prefix, mtu); err != nil {
		return nil, err
	}

	f, err := openTunDev(dev)
	if err != nil {
		return nil, err
	}

	stk, err := newTunStack(mtu, local)
	if err != nil {
		f.Close()
		return nil, err
	}
	p.startStack(stk)

	planeCtx, cancel := context.WithCancel(context.Background())
	t := &tunPlane{dev: dev, file: f, stk: stk, owner: p, cancel: cancel}
	if clean := installOutletRoute(planeCtx, p, cfg, local, prefix.Masked()); len(clean) > 0 {
		t.clean = append(t.clean, clean...)
	}

	checkIPForward(p)

	t.wg.Add(2)
	go t.readLoop(planeCtx)
	go t.writeLoop(planeCtx)

	p.log().Info("alias: tun data path started",
		zap.String("dev", dev), zap.String("address", local.String()),
		zap.Int("prefix_len", prefix.Bits()), zap.Uint32("mtu", mtu),
		zap.String("outlet_dev", cfg.NextHopDev), zap.String("outlet_next_hop", cfg.NextHop),
		zap.String("route_table", cfg.RouteTable))
	return t, nil
}

// checkIPForward warns when the kernel would drop packets that come from the
// tun device and go back to the client, which is every answer this plane emits.
func checkIPForward(p *plugin) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return
	}
	if strings.TrimSpace(string(b)) != "1" {
		p.log().Warn("alias: net.ipv4.ip_forward is 0; answers from the tun device to the client will be dropped")
	}
}

func (t *tunPlane) stop() {
	t.once.Do(func() {
		t.cancel()
		t.stk.close()
		_ = t.file.Close()
		t.wg.Wait()
		for _, fn := range t.clean {
			fn()
		}
		_, _ = runCmd(context.Background(), "ip", "link", "del", "dev", t.dev)
	})
}

func (t *tunPlane) readLoop(ctx context.Context) {
	defer t.wg.Done()
	buf := make([]byte, 64*1024)
	for {
		n, err := t.file.Read(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		if n <= 0 {
			continue
		}
		// ICMP echo to a virtual address is answered by the plugin itself:
		// the netstack has no endpoint for it and the mapping only carries a
		// name. Everything else goes into the stack.
		if handled, reply := t.owner.icmpEchoReply(buf[:n]); handled {
			if len(reply) > 0 {
				t.writePacket(reply)
			}
			continue
		}
		t.stk.inject(buf[:n])
	}
}

func (t *tunPlane) writePacket(pkt []byte) {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if _, err := t.file.Write(pkt); err != nil {
		t.owner.log().Debug("alias: write icmp reply failed", zap.Error(err))
	}
}

func (t *tunPlane) writeLoop(ctx context.Context) {
	defer t.wg.Done()
	for {
		pkt := t.stk.nextPacket(ctx)
		if pkt == nil {
			return
		}
		if _, err := t.file.Write(pkt); err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
	}
}

// cleanupStaleTunDevs removes auto-named devices left by a previous process.
// It only touches the lgaN namespace used when tun_dev is unset.
func cleanupStaleTunDevs(ctx context.Context) {
	out, err := runCmd(ctx, "ip", "-o", "link", "show")
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name := strings.TrimSuffix(f[1], ":")
		if idx := strings.IndexByte(name, '@'); idx >= 0 {
			name = name[:idx]
		}
		if !autoTunName(name) {
			continue
		}
		_, _ = runCmd(ctx, "ip", "link", "del", "dev", name)
	}
}

func autoTunName(name string) bool {
	if !strings.HasPrefix(name, autoDevBase) || len(name) == len(autoDevBase) {
		return false
	}
	for _, r := range name[len(autoDevBase):] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// pickTunDev takes the lowest free "lgaN".
func pickTunDev(ctx context.Context, configured string) (string, error) {
	if configured != "" {
		if len(configured) > maxDevNameLen {
			return "", fmt.Errorf("invalid tun_dev %q: linux names are limited to %d characters", configured, maxDevNameLen)
		}
		return configured, nil
	}
	out, err := runCmd(ctx, "ip", "-o", "link", "show")
	if err != nil {
		return "", fmt.Errorf("list links: %w", err)
	}
	used := map[string]struct{}{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name := strings.TrimSuffix(f[1], ":")
		if idx := strings.IndexByte(name, '@'); idx >= 0 {
			name = name[:idx]
		}
		used[name] = struct{}{}
	}
	for i := 0; i < maxAutoDevIdx; i++ {
		name := fmt.Sprintf("%s%d", autoDevBase, i)
		if _, taken := used[name]; taken {
			continue
		}
		return name, nil
	}
	return "", fmt.Errorf("no free tun name in %s0..%s%d", autoDevBase, autoDevBase, maxAutoDevIdx-1)
}

func ensureTunDev(ctx context.Context, dev string) error {
	if _, err := runCmd(ctx, "ip", "link", "show", "dev", dev); err == nil {
		return nil
	}
	if _, err := runCmd(ctx, "ip", "tuntap", "add", "dev", dev, "mode", "tun"); err != nil {
		return fmt.Errorf("create tun %q: %w", dev, err)
	}
	return nil
}

// configureTunDev gives the device the first host of the range with the range
// mask, so the kernel builds the connected route for the whole segment.
func configureTunDev(ctx context.Context, dev string, local netip.Addr, prefix netip.Prefix, mtu uint32) error {
	if _, err := runCmd(ctx, "ip", "link", "set", "dev", dev, "mtu", strconv.Itoa(int(mtu)), "up"); err != nil {
		return fmt.Errorf("set %s mtu/up: %w", dev, err)
	}
	addr := local.String() + "/" + strconv.Itoa(prefix.Bits())
	if _, err := runCmd(ctx, "ip", "addr", "replace", addr, "dev", dev); err != nil {
		return fmt.Errorf("assign %s to %s: %w", addr, dev, err)
	}
	// The kernel keeps IPv6 on a new interface and floods the IPv4-only stack
	// with MLD/DAD noise; the failure is ignored because a restricted netns
	// may refuse the sysctl write.
	_, _ = runCmd(ctx, "sysctl", "-w", "net.ipv6.conf."+dev+".disable_ipv6=1")
	return nil
}

// installOutletRoute pins the direct outlet: one default route in a dedicated
// table, plus an ip rule matching the device source address. Without a pinned
// interface or next hop the host table is left alone.
func installOutletRoute(ctx context.Context, p *plugin, cfg *Args, local netip.Addr, prefix netip.Prefix) []func() {
	hop := strings.TrimSpace(cfg.NextHop)
	dev := strings.TrimSpace(cfg.NextHopDev)
	if hop == "" && dev == "" {
		return nil
	}
	table := strings.TrimSpace(cfg.RouteTable)
	if table == "" {
		table = "100"
	}
	prio := cfg.RulePriority
	if prio <= 0 {
		prio = 1200
	}

	routeArgs := []string{"route", "replace", "default"}
	if hop != "" {
		routeArgs = append(routeArgs, "via", hop)
	}
	if dev != "" {
		routeArgs = append(routeArgs, "dev", dev)
	}
	routeArgs = append(routeArgs, "table", table)
	if _, err := runCmd(ctx, "ip", routeArgs...); err != nil {
		p.log().Warn("alias: install outlet route failed", zap.String("table", table), zap.Error(err))
		return nil
	}
	// A source rule is identified by its table and priority, not by a mark; the
	// claim keeps that pair from being silently shared with another plugin.
	if err := routepolicy.Default().Claim(routepolicy.Claim{
		Owner: p.Tag(), Table: table, Priority: prio,
	}); err != nil {
		p.log().Error("alias: routing object already owned", zap.Error(err))
	}

	// Traffic the host itself sends to the virtual range must stay on the
	// connected tun route. Without this higher-priority exception, the outlet
	// rule below would match the device source address and send a local
	// request to the real gateway instead of the plugin.
	bypassPrio := prio - 1
	if bypassPrio > 0 {
		bypassArgs := []string{"rule", "add", "from", local.String(), "to", prefix.String(), "table", "main", "prio", strconv.Itoa(bypassPrio)}
		_, _ = runCmd(ctx, "ip", "rule", "del", "from", local.String(), "to", prefix.String(), "table", "main", "prio", strconv.Itoa(bypassPrio))
		if _, err := runCmd(ctx, "ip", bypassArgs...); err != nil {
			p.log().Warn("alias: add virtual-range bypass rule failed",
				zap.String("from", local.String()), zap.String("to", prefix.String()), zap.Error(err))
		}
	}

	ruleArgs := []string{"rule", "add", "from", local.String(), "table", table, "prio", strconv.Itoa(prio)}
	// A rule left behind by a previous run makes add fail with EEXIST; drop it
	// first, ignoring the not-found case.
	_, _ = runCmd(ctx, "ip", "rule", "del", "from", local.String(), "table", table, "prio", strconv.Itoa(prio))
	if _, err := runCmd(ctx, "ip", ruleArgs...); err != nil {
		p.log().Warn("alias: add outlet rule failed", zap.String("from", local.String()), zap.Error(err))
		return nil
	}
	p.log().Info("alias: outlet routing installed",
		zap.String("table", table), zap.String("next_hop", hop),
		zap.String("dev", dev), zap.String("from", local.String()), zap.Int("prio", prio))

	return []func(){
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
			defer cancel()
			_, _ = runCmd(ctx, "ip", "rule", "del", "from", local.String(), "table", table, "prio", strconv.Itoa(prio))
			if bypassPrio > 0 {
				_, _ = runCmd(ctx, "ip", "rule", "del", "from", local.String(), "to", prefix.String(), "table", "main", "prio", strconv.Itoa(bypassPrio))
			}
			_, _ = runCmd(ctx, "ip", "route", "del", "default", "table", table)
		},
	}
}

func openTunDev(dev string) (*os.File, error) {
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

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, text)
	}
	return text, nil
}
