package fakeipnat

// This file is the capture side of the traffic watch. The tun plane observes
// every IPv4 packet it accepts; the non-tun fakeip plane never sees packets in
// Go, so it polls the kernel conntrack table instead. Both feed trafficWatch,
// which keeps the newest flows for the Telegram message.

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	fakeipadmin "github.com/ersonw/mosdns-v4/pkg/fakeip_admin"
	"go.uber.org/zap"
)

const (
	// watchPollInterval is how often the non-tun plane refreshes conntrack. It
	// is also the message edit cadence, so it is deliberately slower than a
	// packet rate and faster than a human refresh.
	watchPollInterval = 2 * time.Second
	// watchConntrackTimeout bounds one conntrack read so a stuck command
	// cannot outlive the plugin.
	watchConntrackTimeout = 8 * time.Second
)

// AdminWatchStart implements fakeipadmin.WatchAdmin.
func (p *FakeIPNatPlugin) AdminWatchStart(ctx context.Context, sourceIP string) error {
	source, err := normalizeWatchSource(sourceIP)
	if err != nil {
		return err
	}
	if p.watch == nil {
		return fmt.Errorf("traffic watch is not initialized")
	}
	if p.useTun {
		p.tunMu.Lock()
		running := p.tunStarted
		p.tunMu.Unlock()
		if !running {
			return fmt.Errorf("tun data path is not running, cannot watch live traffic")
		}
	}
	first := p.watch.add(source)
	if !first {
		return nil
	}
	if p.useTun {
		// The tun reader is authoritative, but conntrack is a useful fallback:
		// traffic can be carried by the nft path while the tun route is not
		// active, and a failed tun reader leaves tunStarted true. This poll
		// must never turn a valid tun watch into an error.
		if p.runner != nil {
			if err := p.startConntrackWatch(ctx, source, false); err != nil {
				p.L().Debug("traffic watch: conntrack fallback unavailable",
					zap.String("source_ip", source), zap.Error(err))
			}
		}
		p.L().Info("traffic watch started on the tun plane", zap.String("source_ip", source))
		return nil
	}
	if err := p.startConntrackWatch(ctx, source, true); err != nil {
		p.watch.remove(source)
		return err
	}
	p.L().Info("traffic watch started on the conntrack plane", zap.String("source_ip", source))
	return nil
}

// AdminWatchSnapshot implements fakeipadmin.WatchAdmin.
func (p *FakeIPNatPlugin) AdminWatchSnapshot(ctx context.Context, sourceIP string, limit int) ([]fakeipadmin.TrafficEvent, uint64, error) {
	source, err := normalizeWatchSource(sourceIP)
	if err != nil {
		return nil, 0, err
	}
	if p.watch == nil {
		return nil, 0, fmt.Errorf("traffic watch is not initialized")
	}
	events, version, ok := p.watch.snapshot(source, limit)
	if !ok {
		return nil, 0, fmt.Errorf("source %s is not watched", source)
	}
	return events, version, nil
}

// AdminWatchStop implements fakeipadmin.WatchAdmin.
func (p *FakeIPNatPlugin) AdminWatchStop(ctx context.Context, sourceIP string) error {
	source, err := normalizeWatchSource(sourceIP)
	if err != nil {
		return err
	}
	if p.watch == nil {
		return nil
	}
	last := p.watch.remove(source)
	if !last {
		return nil
	}
	p.watchMu.Lock()
	cancel := p.conntrackCancels[source]
	delete(p.conntrackCancels, source)
	p.watchMu.Unlock()
	if cancel != nil {
		cancel()
	}
	p.L().Info("traffic watch stopped", zap.String("source_ip", source))
	return nil
}

func normalizeWatchSource(raw string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid source ip %q: %w", raw, err)
	}
	if !addr.Is4() {
		return "", fmt.Errorf("source ip %q is not IPv4; the fakeip data plane is IPv4 only", raw)
	}
	return addr.String(), nil
}

// startConntrackWatch performs one read synchronously. In strict mode (the
// non-tun plane) a missing or unusable conntrack command is reported to the
// administrator instead of showing an empty live message. In fallback mode
// (the tun plane) the initial read is best-effort and the loop still starts.
func (p *FakeIPNatPlugin) startConntrackWatch(ctx context.Context, source string, strict bool) error {
	if p.runner == nil {
		return fmt.Errorf("conntrack reader is not available")
	}
	if err := p.pollConntrack(ctx, source); err != nil {
		if strict {
			return err
		}
		p.L().Debug("traffic watch: initial conntrack poll failed",
			zap.String("source_ip", source), zap.Error(err))
	}

	p.watchMu.Lock()
	if p.conntrackCancels == nil {
		p.conntrackCancels = make(map[string]context.CancelFunc)
	}
	if _, exists := p.conntrackCancels[source]; exists {
		p.watchMu.Unlock()
		return nil
	}
	if p.watchCtx == nil {
		p.watchCtx, p.watchCancel = context.WithCancel(context.Background())
	}
	runCtx, cancel := context.WithCancel(p.watchCtx)
	p.conntrackCancels[source] = cancel
	p.watchWG.Add(1)
	p.watchMu.Unlock()

	go p.conntrackLoop(runCtx, source)
	return nil
}

func (p *FakeIPNatPlugin) conntrackLoop(ctx context.Context, source string) {
	defer p.watchWG.Done()
	ticker := time.NewTicker(watchPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.pollConntrack(ctx, source); err != nil {
				p.L().Debug("traffic watch: conntrack poll failed",
					zap.String("source_ip", source), zap.Error(err))
			}
		}
	}
}

// conntrackOutput runs conntrack once, falling back to the absolute path used
// on routers whose service PATH omits /usr/sbin.
func (p *FakeIPNatPlugin) conntrackOutput(ctx context.Context, source string) (string, error) {
	args := []string{"-L", "-f", "ipv4", "-s", source}
	out, err := p.runner.Run(ctx, "conntrack", args...)
	if err == nil || !commandMissing(err) {
		return out, err
	}
	return p.runner.Run(ctx, "/usr/sbin/conntrack", args...)
}

func (p *FakeIPNatPlugin) pollConntrack(ctx context.Context, source string) error {
	runCtx, cancel := context.WithTimeout(ctx, watchConntrackTimeout)
	defer cancel()
	out, err := p.conntrackOutput(runCtx, source)
	if err != nil {
		msg := strings.TrimSpace(out)
		if msg != "" {
			return fmt.Errorf("conntrack -L -s %s: %w: %s", source, err, msg)
		}
		return fmt.Errorf("conntrack -L -s %s: %w", source, err)
	}
	now := time.Now().Unix()
	for _, line := range strings.Split(out, "\n") {
		proto, tuples, ok := parseConntrackLine(line)
		if !ok {
			continue
		}
		client, real, ok := pickConntrackTuples(source, tuples)
		if !ok {
			continue
		}
		if client.dport == 0 && client.dst == "" {
			continue
		}
		event := fakeipadmin.TrafficEvent{
			Time:            now,
			ClientIP:        source,
			ClientPort:      client.sport,
			DestinationPort: client.dport,
			DestinationIP:   client.dst,
			Protocol:        proto,
		}
		event.Domain, event.FakeIP, event.DestinationIP = p.describeWatchDestination(ctx, client.dst, real, true)
		p.watch.record(event)
	}
	return nil
}

// describeWatchDestination turns the destination tuple into what the
// administrator should read: the domain when the fake ip has one, and the real
// address when either the reply tuple or the learned mapping provides it.
func (p *FakeIPNatPlugin) describeWatchDestination(ctx context.Context, dst, replyReal string, lookupDB bool) (domain, fakeIP, destination string) {
	destination = dst
	if p.isFakeAddrString(dst) {
		fakeIP = dst
		if p.runtime != nil {
			domain, _ = p.runtime.domainOf(dst)
		}
		if domain == "" && lookupDB && p.db != nil {
			lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			if d, err := p.domainForFakeIP(lookupCtx, dst); err == nil {
				domain = d
			}
			cancel()
		}
	} else {
		if p.runtime != nil {
			domain, _ = p.runtime.domainOfReal(dst)
		}
		if domain == "" && p.watchNames != nil {
			domain, _ = p.watchNames.lookup(dst)
		}
		if domain == "" && lookupDB && p.db != nil {
			allowed := true
			if p.watchNames != nil {
				allowed = p.watchNames.dbLookupAllowed(dst)
			}
			if allowed {
				if p.watchNames != nil {
					p.watchNames.markDBLookup(dst)
				}
				lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				if d, err := p.domainForRealIP(lookupCtx, dst); err == nil {
					domain = d
					if p.watchNames != nil {
						p.watchNames.remember(dst, d)
					}
				}
				cancel()
			}
		}
		// A real IP outside the memory and historical tables can still be
		// named by PTR. This runs in the background and feeds the same cache,
		// so the current message is not blocked on DNS.
		if domain == "" {
			p.reverseLookupWatchName(dst)
		}
		if domain != "" && p.runtime != nil {
			if fake, ok := p.runtime.fakeOf(domain); ok {
				fakeIP = fake
			}
		}
	}
	if replyReal != "" && !p.isFakeAddrString(replyReal) {
		destination = replyReal
	} else if domain != "" && p.runtime != nil {
		for _, ip := range p.runtime.realsOf(domain) {
			if !p.isFakeAddrString(ip) {
				destination = ip
				break
			}
		}
	}
	return domain, fakeIP, destination
}

// observeTunPacket records one accepted IPv4 packet. It runs after the ownership
// check, so it only sees traffic this plugin actually carries. The runtime
// indexes answer without SQLite; a cache miss simply leaves the domain blank
// until the relay fills it in, which is the next packet of the same flow.
func (p *FakeIPNatPlugin) observeTunPacket(pkt []byte) {
	if p.watch == nil || !p.watch.active() {
		return
	}
	flow, ok := parseWatchPacket(pkt)
	if !ok {
		return
	}
	source := flow.src.String()
	if !p.watch.watched(source) {
		return
	}
	event := fakeipadmin.TrafficEvent{
		Time:            time.Now().Unix(),
		ClientIP:        source,
		ClientPort:      flow.srcPort,
		DestinationIP:   flow.dst.String(),
		DestinationPort: flow.dstPort,
		Protocol:        flow.proto,
		Packets:         1,
	}
	event.Domain, event.FakeIP, event.DestinationIP = p.describeWatchDestination(context.Background(), flow.dst.String(), "", false)
	p.watch.record(event)
}

// stopTrafficWatch cancels every conntrack capture and waits for the loops.
func (p *FakeIPNatPlugin) stopTrafficWatch() {
	p.watchMu.Lock()
	if p.watchCancel != nil {
		p.watchCancel()
		p.watchCancel = nil
	}
	p.watchCtx = nil
	p.conntrackCancels = nil
	p.watchMu.Unlock()
	p.watchWG.Wait()
}

type conntrackTuple struct {
	src   string
	dst   string
	sport uint16
	dport uint16
}

// parseConntrackLine reads one `conntrack -L` line. Every `src=` starts a new
// tuple, which is how the original and reply directions stay separate in the
// DNAT case.
func parseConntrackLine(line string) (string, []conntrackTuple, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", nil, false
	}
	proto := strings.ToLower(fields[0])
	switch proto {
	case "tcp", "udp", "icmp":
	default:
		return "", nil, false
	}

	var tuples []conntrackTuple
	var cur *conntrackTuple
	flush := func() {
		if cur != nil && cur.src != "" && cur.dst != "" {
			tuples = append(tuples, *cur)
		}
		cur = nil
	}
	for _, field := range fields[1:] {
		switch {
		case strings.HasPrefix(field, "src="):
			flush()
			cur = &conntrackTuple{src: strings.TrimPrefix(field, "src=")}
		case strings.HasPrefix(field, "dst="):
			if cur == nil {
				continue
			}
			cur.dst = strings.TrimPrefix(field, "dst=")
		case strings.HasPrefix(field, "sport="):
			if cur == nil {
				continue
			}
			if n, err := strconv.ParseUint(strings.TrimPrefix(field, "sport="), 10, 16); err == nil {
				cur.sport = uint16(n)
			}
		case strings.HasPrefix(field, "dport="):
			if cur == nil {
				continue
			}
			if n, err := strconv.ParseUint(strings.TrimPrefix(field, "dport="), 10, 16); err == nil {
				cur.dport = uint16(n)
			}
		}
	}
	flush()
	if len(tuples) == 0 {
		return "", nil, false
	}
	return proto, tuples, true
}

// pickConntrackTuples selects the client's direction and the reply source that
// carries the real destination.
func pickConntrackTuples(source string, tuples []conntrackTuple) (conntrackTuple, string, bool) {
	clientIdx := -1
	for i, t := range tuples {
		if t.src == source {
			clientIdx = i
			break
		}
	}
	if clientIdx < 0 {
		return conntrackTuple{}, "", false
	}
	client := tuples[clientIdx]
	var replyReal string
	for i, t := range tuples {
		if i == clientIdx || t.src == source || t.src == "" {
			continue
		}
		replyReal = t.src
		break
	}
	return client, replyReal, true
}
