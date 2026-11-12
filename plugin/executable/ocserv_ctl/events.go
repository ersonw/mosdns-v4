package ocserv_ctl

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// updownEvent is one connect/disconnect report from the ocserv up/down hook.
// The hook runs outside mosdns, so the wire format is deliberately plain JSON
// with a single object per line; unknown fields from a newer script are
// ignored instead of failing the whole event.
type updownEvent struct {
	Event   string `json:"event"`
	Reason  string `json:"reason,omitempty"`
	User    string `json:"user"`
	RealIP  string `json:"real_ip"`
	VPNIP   string `json:"vpn_ip"`
	VPNIPv6 string `json:"vpn_ipv6,omitempty"`
	Device  string `json:"device,omitempty"`
	Group   string `json:"group,omitempty"`
	RXBytes int64  `json:"rx_bytes,omitempty"`
	TXBytes int64  `json:"tx_bytes,omitempty"`
	Geo     string `json:"geo,omitempty"`
	ISP     string `json:"isp,omitempty"`
	AS      string `json:"as,omitempty"`
	IPType  string `json:"ip_type,omitempty"`
	Time    string `json:"time,omitempty"`
}

// eventReply is written back on the same connection. The hook ignores it, but
// it makes a manual `nc -U` test obvious.
type eventReply struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Count int    `json:"count,omitempty"`
}

type eventStore struct {
	mu     sync.Mutex
	ring   []updownEvent
	file   *os.File
	limit  int
	closed bool
}

// defaultEventLog keeps the up/down history across restarts when event_log is
// not set explicitly.
const defaultEventLog = "/run/mosdns/ocserv-events.jsonl"

// AdminEvents returns the newest recorded events, newest first. A non-empty
// user filters case-insensitively. It is the read side exposed as /vpn events:
// when event_log is set (or defaulted), the JSONL file is the source so history
// survives a restart; the in-memory ring is only a fallback.
func (p *ocservCtl) AdminEvents(limit int, user string) (string, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 5000 {
		limit = 5000
	}
	user = strings.TrimSpace(user)

	if p.args.EventLog != "" {
		items, err := readEventLog(p.args.EventLog, limit, user)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("read event_log %s: %w", p.args.EventLog, err)
			}
		} else if len(items) > 0 {
			return formatEvents(items), nil
		}
	}

	if p.args.EventSocket == "" {
		return "", fmt.Errorf("event_socket is not configured")
	}
	if limit > p.args.EventBuffer {
		limit = p.args.EventBuffer
	}

	p.events.mu.Lock()
	items := make([]updownEvent, 0, len(p.events.ring))
	for i := len(p.events.ring) - 1; i >= 0; i-- {
		if user != "" && !strings.EqualFold(p.events.ring[i].User, user) {
			continue
		}
		items = append(items, p.events.ring[i])
		if len(items) >= limit {
			break
		}
	}
	p.events.mu.Unlock()

	if len(items) == 0 {
		if user == "" {
			return "no events recorded yet", nil
		}
		return fmt.Sprintf("no events recorded for %s", user), nil
	}
	return formatEvents(items), nil
}

// readEventLog returns up to limit matching events, newest first. A malformed
// or partially written line is skipped instead of breaking the whole history.
func readEventLog(path string, limit int, user string) ([]updownEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	items := make([]updownEvent, 0, limit)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev updownEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if user != "" && !strings.EqualFold(ev.User, user) {
			continue
		}
		items = append(items, ev)
		if len(items) > limit {
			items = items[len(items)-limit:]
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
	return items, nil
}

func formatEvents(items []updownEvent) string {
	var b strings.Builder
	for _, e := range items {
		b.WriteString(formatEvent(e))
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatEvent(e updownEvent) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] event=%s user=%s real_ip=%s", e.Time, e.Event, e.User, e.RealIP)
	if e.VPNIP != "" {
		fmt.Fprintf(&b, " vpn_ip=%s", e.VPNIP)
	}
	if e.VPNIPv6 != "" {
		fmt.Fprintf(&b, " vpn_ipv6=%s", e.VPNIPv6)
	}
	if e.Device != "" {
		fmt.Fprintf(&b, " device=%s", e.Device)
	}
	if e.Group != "" {
		fmt.Fprintf(&b, " group=%s", e.Group)
	}
	if e.Geo != "" {
		fmt.Fprintf(&b, " geo=%q", e.Geo)
	}
	if e.ISP != "" {
		fmt.Fprintf(&b, " isp=%q", e.ISP)
	}
	if e.AS != "" {
		fmt.Fprintf(&b, " as=%q", e.AS)
	}
	if e.IPType != "" {
		fmt.Fprintf(&b, " type=%q", e.IPType)
	}
	if e.Event == "disconnect" || e.RXBytes > 0 || e.TXBytes > 0 {
		fmt.Fprintf(&b, " rx_bytes=%d tx_bytes=%d", e.RXBytes, e.TXBytes)
	}
	return b.String()
}

// startEvents creates the unix socket the ocserv up/down hook writes to. A
// stale socket file from a previous run is removed first; the listener is
// per-process and rebuilt on every start.
func (p *ocservCtl) startEvents() error {
	path := p.args.EventSocket
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("event_socket dir: %w", err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("event_socket remove stale: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("event_socket listen %s: %w", path, err)
	}
	// The hook runs as root while mosdns may run as a service account. 0660
	// is enough for root and keeps the channel closed to everyone else.
	if err := os.Chmod(path, 0o660); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return fmt.Errorf("event_socket chmod: %w", err)
	}

	p.events.mu.Lock()
	p.events.limit = p.args.EventBuffer
	if p.args.EventLog != "" {
		if err := os.MkdirAll(filepath.Dir(p.args.EventLog), 0o755); err != nil {
			_ = ln.Close()
			_ = os.Remove(path)
			return fmt.Errorf("event_log dir: %w", err)
		}
		f, err := os.OpenFile(p.args.EventLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			_ = ln.Close()
			_ = os.Remove(path)
			return fmt.Errorf("event_log open: %w", err)
		}
		p.events.file = f
	}
	p.events.mu.Unlock()

	p.eventLn = ln
	p.eventWG.Add(1)
	go p.acceptEvents()
	p.L().Info("ocserv event socket listening",
		zap.String("socket", path), zap.String("log", p.args.EventLog),
		zap.Int("buffer", p.args.EventBuffer))
	return nil
}

func (p *ocservCtl) acceptEvents() {
	defer p.eventWG.Done()
	for {
		conn, err := p.eventLn.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			p.L().Warn("ocserv event accept failed", zap.Error(err))
			return
		}
		go p.handleEventConn(conn)
	}
}

func (p *ocservCtl) handleEventConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), 256*1024)
	count := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev updownEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			p.writeEventReply(conn, eventReply{Error: "invalid json: " + err.Error()})
			continue
		}
		if err := p.validateEvent(&ev); err != nil {
			p.writeEventReply(conn, eventReply{Error: err.Error()})
			continue
		}
		p.recordEvent(ev)
		count++
		p.writeEventReply(conn, eventReply{OK: true, Count: count})
	}
	if err := sc.Err(); err != nil {
		p.L().Debug("ocserv event connection ended", zap.Error(err))
	}
}

func (p *ocservCtl) writeEventReply(conn net.Conn, r eventReply) {
	raw, err := json.Marshal(r)
	if err != nil {
		return
	}
	_, _ = conn.Write(append(raw, '\n'))
}

func (p *ocservCtl) validateEvent(ev *updownEvent) error {
	ev.Event = strings.ToLower(strings.TrimSpace(ev.Event))
	if ev.Event == "" {
		// Older hooks call the field "reason"; accept it as an alias.
		ev.Event = strings.ToLower(strings.TrimSpace(ev.Reason))
	}
	switch ev.Event {
	case "connect", "disconnect":
	default:
		return fmt.Errorf("event must be connect or disconnect, got %q", ev.Event)
	}
	ev.User = strings.TrimSpace(ev.User)
	if ev.User == "" {
		return fmt.Errorf("user is required")
	}
	if !validUser(ev.User) {
		return fmt.Errorf("invalid user %q", ev.User)
	}
	ev.RealIP = strings.TrimSpace(ev.RealIP)
	if ev.RealIP != "" && !validIPLiteral(ev.RealIP) {
		return fmt.Errorf("invalid real_ip %q", ev.RealIP)
	}
	ev.VPNIP = strings.TrimSpace(ev.VPNIP)
	if ev.VPNIP != "" && !validIPLiteral(ev.VPNIP) {
		return fmt.Errorf("invalid vpn_ip %q", ev.VPNIP)
	}
	ev.VPNIPv6 = strings.TrimSpace(ev.VPNIPv6)
	if ev.VPNIPv6 != "" && !validIPLiteral(ev.VPNIPv6) {
		return fmt.Errorf("invalid vpn_ipv6 %q", ev.VPNIPv6)
	}
	if ev.RXBytes < 0 || ev.TXBytes < 0 {
		return fmt.Errorf("byte counters must not be negative")
	}
	if strings.TrimSpace(ev.Time) == "" {
		ev.Time = time.Now().Format("2006-01-02 15:04:05")
	}
	return nil
}

func validIPLiteral(s string) bool {
	return net.ParseIP(s) != nil
}

func (p *ocservCtl) recordEvent(ev updownEvent) {
	p.events.mu.Lock()
	defer p.events.mu.Unlock()
	if p.events.closed {
		return
	}
	p.events.ring = append(p.events.ring, ev)
	if p.events.limit > 0 && len(p.events.ring) > p.events.limit {
		p.events.ring = p.events.ring[len(p.events.ring)-p.events.limit:]
	}
	if p.events.file != nil {
		if raw, err := json.Marshal(ev); err == nil {
			if _, err := p.events.file.Write(append(raw, '\n')); err != nil {
				p.L().Warn("ocserv event log write failed", zap.Error(err))
			}
		}
	}
	p.L().Debug("ocserv updown event",
		zap.String("event", ev.Event), zap.String("user", ev.User),
		zap.String("real_ip", ev.RealIP), zap.String("vpn_ip", ev.VPNIP))
}

func (p *ocservCtl) closeEvents() error {
	p.events.mu.Lock()
	p.events.closed = true
	p.events.mu.Unlock()

	var err error
	if p.eventLn != nil {
		if e := p.eventLn.Close(); e != nil {
			err = e
		}
		p.eventWG.Wait()
		if e := os.Remove(p.args.EventSocket); e != nil && !os.IsNotExist(e) {
			err = e
		}
	}
	p.events.mu.Lock()
	if p.events.file != nil {
		if e := p.events.file.Close(); e != nil {
			err = e
		}
		p.events.file = nil
	}
	p.events.mu.Unlock()
	return err
}
