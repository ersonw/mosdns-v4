/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// Package ocserv_ctl maps a DNS client address to the ocserv user that owns
// it, by asking ocserv through occtl. It is a data-enrichment step, not a
// control surface: the plugin runs on the query chain, reads the request
// source address, and marks the query when the address belongs to a
// connected ocserv session.
package ocserv_ctl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/executable_seq"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"go.uber.org/zap"
)

const PluginType = "ocserv_ctl"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*ocservCtl)(nil)

// Args configures how the plugin reaches ocserv.
type Args struct {
	// Socket is the occtl socket file, e.g. /run/ocserv/occtl.socket.
	// "auto" probes the common locations (see autoSocketCandidates) and uses
	// the first one that exists, which is what a VyOS box needs because its
	// socket path differs from the upstream default.
	// At most one of Socket and Addr may be set. With neither set the plugin
	// stays disabled and every query passes straight through.
	Socket string `yaml:"socket"`
	// Addr is a TCP endpoint (host:port) used only when ocserv was built to
	// accept occtl over TCP. occtl itself decides how to parse the value.
	Addr string `yaml:"addr"`
	// OcctlPath is the occtl binary. Default is "occtl" from PATH.
	OcctlPath string `yaml:"occtl_path"`
	// Timeout bounds a single occtl call, in seconds. Default is 3.
	// The query is never blocked longer than this.
	Timeout int `yaml:"timeout"`
	// CacheTTL is how long the user list is reused before querying again,
	// in seconds. Default is 15.
	CacheTTL int `yaml:"cache_ttl"`
	// Mark is added to the query context when the client address belongs to
	// a connected user. Zero means "do not mark", only log.
	Mark uint `yaml:"mark"`
	// ConfigPath is the ocserv configuration file. It is read on demand to
	// learn the IPv4 lease pool (ipv4-network) and the config-per-user
	// directory used to pin addresses. Only the admin commands need it.
	ConfigPath string `yaml:"config_path"`
	// SystemdUnit is the systemd unit controlled by /vpn reload and
	// /vpn restart. Default is "ocserv".
	SystemdUnit string `yaml:"systemd_unit"`
	// SystemctlPath is the systemctl binary. Default is "systemctl".
	SystemctlPath string `yaml:"systemctl_path"`
	// DisabledRestart blocks /vpn restart, which drops every connected
	// session. Reload stays available.
	DisabledRestart bool `yaml:"disable_restart"`
	// EventSocket is a unix socket the plugin creates for the ocserv up/down
	// hook. The hook writes one JSON event per line; the plugin validates it,
	// keeps the newest EventBuffer events in memory and appends them to
	// EventLog. Empty disables the channel.
	EventSocket string `yaml:"event_socket"`
	// EventLog is a JSONL file that outlives a restart. Empty keeps events in
	// memory only.
	EventLog string `yaml:"event_log"`
	// EventBuffer is how many events AdminEvents keeps in memory. Default 500.
	EventBuffer int `yaml:"event_buffer"`
}

func (a *Args) initDefault() error {
	if a.Socket != "" && a.Addr != "" {
		return fmt.Errorf("socket and addr are mutually exclusive")
	}
	a.OcctlPath = strings.TrimSpace(a.OcctlPath)
	if a.OcctlPath == "" {
		a.OcctlPath = "occtl"
	}
	if a.Timeout <= 0 {
		a.Timeout = 3
	}
	if a.CacheTTL <= 0 {
		a.CacheTTL = 15
	}
	a.ConfigPath = strings.TrimSpace(a.ConfigPath)
	a.SystemctlPath = strings.TrimSpace(a.SystemctlPath)
	if a.SystemctlPath == "" {
		a.SystemctlPath = "systemctl"
	}
	a.SystemdUnit = strings.TrimSpace(a.SystemdUnit)
	if a.SystemdUnit == "" {
		a.SystemdUnit = "ocserv"
	}
	a.EventSocket = strings.TrimSpace(a.EventSocket)
	a.EventLog = strings.TrimSpace(a.EventLog)
	if a.EventBuffer <= 0 {
		a.EventBuffer = 500
	}
	if a.EventBuffer > 5000 {
		a.EventBuffer = 5000
	}
	return nil
}

// enabled reports whether an ocserv endpoint was configured at all. Without
// one the plugin is a passive pass-through, so a config that does not use
// ocserv needs no special casing.
func (a *Args) enabled() bool {
	return a.Socket != "" || a.Addr != ""
}

func (a *Args) endpoint() string {
	if a.Socket != "" {
		return a.Socket
	}
	return a.Addr
}

// autoSocket is the value of socket that asks the plugin to find the occtl
// socket itself. Deployments differ: Debian/upstream use /run/ocserv, VyOS and
// older packages keep /var/run/ocserv, and some builds name it occtl.sock.
const autoSocket = "auto"

// autoSocketCandidates is probed in order when socket: auto is set.
var autoSocketCandidates = []string{
	"/run/ocserv/occtl.socket",
	"/var/run/ocserv/occtl.socket",
	"/run/ocserv/occtl.sock",
	"/var/run/ocserv/occtl.sock",
	"/run/ocserv/socket",
	"/var/run/ocserv/socket",
}

// ocservUser is one row of "occtl --json show users".
type ocservUser struct {
	ID       string
	Username string
	RemoteIP string // "Remote IP": the address the client connects from
	VPNIP    string // "IPv4": the address assigned inside the tunnel
}

type ocservCtl struct {
	*coremain.BP
	args *Args

	mu        sync.Mutex
	users     []ocservUser
	fetchedAt time.Time
	noticedAt time.Time
	// socketPath is the discovered path when args.Socket == "auto".
	socketPath string
	// allocMu serializes address allocation so two concurrent bot commands
	// cannot hand out the same free address.
	allocMu sync.Mutex

	events  eventStore
	eventLn net.Listener
	eventWG sync.WaitGroup
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	return newOcservCtl(bp, args.(*Args))
}

func newOcservCtl(bp *coremain.BP, args *Args) (coremain.Plugin, error) {
	if err := args.initDefault(); err != nil {
		return nil, err
	}
	p := &ocservCtl{BP: bp, args: args}
	if err := p.startEvents(); err != nil {
		return nil, err
	}
	if !args.enabled() {
		bp.L().Info("ocserv ctl plugin disabled, no socket or addr configured")
		return p, nil
	}
	// With socket: auto the path may not exist yet (ocserv can be down at
	// startup), so resolution is deferred to the first use.
	bp.L().Info("ocserv ctl plugin initialized",
		zap.String("endpoint", args.endpoint()),
		zap.String("occtl", args.OcctlPath),
		zap.String("ocserv_config", args.ConfigPath),
		zap.String("systemd_unit", args.SystemdUnit),
		zap.Int("timeout", args.Timeout),
		zap.Int("cache_ttl", args.CacheTTL),
		zap.Uint("mark", args.Mark))
	return p, nil
}

// endpoint returns the socket or TCP endpoint to pass to occtl. In auto mode
// the first existing candidate wins and is cached; a missing socket is retried
// on the next call, so a late ocserv start is picked up without a restart.
func (p *ocservCtl) endpoint() (string, error) {
	if !strings.EqualFold(p.args.Socket, autoSocket) {
		return p.args.endpoint(), nil
	}
	p.mu.Lock()
	cached := p.socketPath
	p.mu.Unlock()
	if cached != "" {
		return cached, nil
	}
	for _, cand := range autoSocketCandidates {
		if _, err := os.Stat(cand); err == nil {
			p.mu.Lock()
			p.socketPath = cand
			p.mu.Unlock()
			p.L().Info("ocserv ctl socket discovered", zap.String("socket", cand))
			return cand, nil
		}
	}
	return "", fmt.Errorf("occtl socket not found, probed: %s", strings.Join(autoSocketCandidates, ", "))
}

// Exec identifies the source address before the rest of the chain runs. A
// failed or slow occtl call is logged and skipped: DNS resolution must not
// depend on the VPN control socket.
func (p *ocservCtl) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	if !p.args.enabled() || !p.available() {
		return executable_seq.ExecChainNode(ctx, qCtx, next)
	}
	client := qCtx.ReqMeta().ClientAddr
	if client.IsValid() && !client.IsUnspecified() {
		if u := p.identify(ctx, client.String()); u != nil {
			p.L().Debug("ocserv user identified",
				zap.String("client_ip", client.String()),
				zap.String("user", u.Username),
				zap.String("id", u.ID),
				zap.String("vpn_ip", u.VPNIP))
			if p.args.Mark > 0 {
				qCtx.AddMark(p.args.Mark)
			}
		} else {
			p.L().Debug("no ocserv user for client ip", zap.String("client_ip", client.String()))
		}
	}
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (p *ocservCtl) Close() error {
	return p.closeEvents()
}

// AdminExec runs one occtl command against the configured endpoint and
// returns its combined output. It is the escape hatch used by telegram_bot to
// expose the full occtl command set; it is not called from the DNS path.
func (p *ocservCtl) AdminExec(ctx context.Context, argv []string) (string, error) {
	if !p.args.enabled() {
		return "", fmt.Errorf("ocserv_ctl is not configured: set socket or addr")
	}
	if len(argv) == 0 {
		return "", fmt.Errorf("empty occtl command")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.args.Timeout)*time.Second)
	defer cancel()

	ep, err := p.endpoint()
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, p.args.OcctlPath, append([]string{"-s", ep}, argv...)...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("occtl %v: %w", argv, err)
	}
	return out.String(), nil
}

// available reports whether the configured endpoint is usable right now. A
// unix socket that does not exist yet (ocserv not started, or occtl disabled
// on the server) is a normal situation: skip identification and keep the
// query chain moving. The notice is throttled so a missing socket cannot
// flood the debug log.
func (p *ocservCtl) available() bool {
	if p.args.Socket == "" {
		return true
	}
	ep, err := p.endpoint()
	if err != nil {
		p.mu.Lock()
		if time.Since(p.noticedAt) > time.Second {
			p.noticedAt = time.Now()
			p.L().Debug("occtl socket not available, skipping identification",
				zap.String("socket", p.args.Socket), zap.String("reason", err.Error()))
		}
		p.mu.Unlock()
		return false
	}
	_, statErr := os.Stat(ep)
	if statErr == nil {
		return true
	}
	p.mu.Lock()
	if time.Since(p.noticedAt) > time.Second {
		p.noticedAt = time.Now()
		p.L().Debug("occtl socket not available, skipping identification",
			zap.String("socket", ep), zap.String("stat_error", statErr.Error()))
	}
	p.mu.Unlock()
	return false
}

// identify returns the session owning ip, or nil when no connected user matches.
func (p *ocservCtl) identify(ctx context.Context, ip string) *ocservUser {
	users := p.table(ctx)
	for i := range users {
		u := &users[i]
		if u.RemoteIP == ip || u.VPNIP == ip {
			return u
		}
	}
	return nil
}

// table returns the cached user list, refreshing it when the TTL expired.
func (p *ocservCtl) table(ctx context.Context) []ocservUser {
	p.mu.Lock()
	if p.users != nil && time.Since(p.fetchedAt) < time.Duration(p.args.CacheTTL)*time.Second {
		users := p.users
		p.mu.Unlock()
		return users
	}
	p.mu.Unlock()

	fresh, err := p.fetch(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		// Keep serving the previous snapshot: a transient occtl failure
		// should not turn every query into "unknown user".
		p.L().Warn("failed to query ocserv users",
			zap.String("endpoint", p.args.endpoint()), zap.Error(err))
		return p.users
	}
	p.users = fresh
	p.fetchedAt = time.Now()
	p.L().Debug("ocserv user list refreshed", zap.Int("users", len(fresh)))
	return p.users
}

func (p *ocservCtl) fetch(parent context.Context) ([]ocservUser, error) {
	ctx, cancel := context.WithTimeout(parent, time.Duration(p.args.Timeout)*time.Second)
	defer cancel()

	ep, err := p.endpoint()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, p.args.OcctlPath, "-s", ep, "-j", "show", "users")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("occtl failed: %s", msg)
	}
	return parseUsers(stdout.Bytes())
}

// parseUsers decodes "occtl --json show users". occtl emits human readable
// keys ("Username", "Remote IP", "IPv4"), so keys are normalized before use.
func parseUsers(raw []byte) ([]ocservUser, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var rows []map[string]interface{}
	if err := dec.Decode(&rows); err != nil {
		return nil, fmt.Errorf("decode occtl json: %w", err)
	}

	users := make([]ocservUser, 0, len(rows))
	for _, row := range rows {
		var u ocservUser
		for k, v := range row {
			switch normalizeKey(k) {
			case "username", "user":
				u.Username = valueString(v)
			case "id":
				u.ID = valueString(v)
			case "remoteip", "clientip":
				u.RemoteIP = cleanIP(valueString(v))
			case "ipv4", "vpnip":
				u.VPNIP = cleanIP(valueString(v))
			}
		}
		if u.Username == "" {
			continue
		}
		users = append(users, u)
	}
	return users, nil
}

func normalizeKey(s string) string {
	s = strings.ToLower(s)
	s = strings.NewReplacer(" ", "", "-", "", "_", "", ".", "").Replace(s)
	return s
}

func valueString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatInt(int64(t), 10)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

// cleanIP strips a zone, a /prefix length or a port, so "10.8.0.2/32" and
// "[fd00::2]:443" compare equal to the bare address.
func cleanIP(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return s
}
