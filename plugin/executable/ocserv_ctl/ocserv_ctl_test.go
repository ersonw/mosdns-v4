package ocserv_ctl

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const sampleUsers = `[
 {"ID": 62409, "Username": "alice", "Remote IP": "203.0.113.9", "IPv4": "10.8.0.2", "State": "connected"},
 {"ID": 62410, "Username": "bob", "Remote IP": "203.0.113.10", "IPv4": "10.8.0.3", "State": "connected"}
]`

// fakeOcctl writes an executable stub that records its argv and prints body.
// It also creates the socket file the plugin checks for, because occtl itself
// is never really executed by the stub.
func fakeOcctl(t *testing.T, body string) (path, argvLog, socketPath string) {
	t.Helper()
	dir := t.TempDir()
	argvLog = filepath.Join(dir, "argv.log")
	path = filepath.Join(dir, "occtl")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> " + argvLog + "\ncat <<'JSON'\n" + body + "\nJSON\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake occtl: %v", err)
	}
	socketPath = filepath.Join(dir, "occtl.socket")
	if err := os.WriteFile(socketPath, nil, 0o600); err != nil {
		t.Fatalf("write fake socket: %v", err)
	}
	return path, argvLog, socketPath
}

func newTestPlugin(t *testing.T, args *Args) *ocservCtl {
	t.Helper()
	bp := coremain.NewBP("test_ocserv", PluginType, zap.NewNop(), nil)
	p, err := newOcservCtl(bp, args)
	if err != nil {
		t.Fatalf("newOcservCtl: %v", err)
	}
	return p.(*ocservCtl)
}

func runQuery(t *testing.T, p *ocservCtl, client string) *query_context.Context {
	t.Helper()
	qCtx := query_context.NewContext(new(dns.Msg), &query_context.RequestMeta{ClientAddr: netip.MustParseAddr(client)})
	if err := p.Exec(context.Background(), qCtx, nil); err != nil {
		t.Fatalf("Exec: %v", err)
	}
	return qCtx
}

func TestMarksQueryForRemoteIP(t *testing.T) {
	occtl, argvLog, socket := fakeOcctl(t, sampleUsers)
	p := newTestPlugin(t, &Args{OcctlPath: occtl, Socket: socket, Mark: 7})

	qCtx := runQuery(t, p, "203.0.113.10")
	if !qCtx.HasMark(7) {
		t.Fatalf("query from a connected client was not marked")
	}

	// The socket and the json flag must both reach occtl, in this order.
	raw, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatalf("read argv log: %v", err)
	}
	want := "-s\n" + socket + "\n-j\nshow\nusers\n"
	if got := string(raw); got != want {
		t.Fatalf("occtl argv = %q, want %q", got, want)
	}
}

func TestMarksQueryForVPNAddress(t *testing.T) {
	occtl, _, socket := fakeOcctl(t, sampleUsers)
	p := newTestPlugin(t, &Args{OcctlPath: occtl, Socket: socket, Mark: 7})

	qCtx := runQuery(t, p, "10.8.0.2")
	if !qCtx.HasMark(7) {
		t.Fatalf("query from the tunnel address was not marked")
	}
}

func TestUnknownClientIsNotMarked(t *testing.T) {
	occtl, _, socket := fakeOcctl(t, sampleUsers)
	p := newTestPlugin(t, &Args{OcctlPath: occtl, Socket: socket, Mark: 7})

	qCtx := runQuery(t, p, "198.51.100.1")
	if qCtx.HasMark(7) {
		t.Fatalf("unknown client must not be marked")
	}
}

func TestUserListIsCached(t *testing.T) {
	occtl, argvLog, socket := fakeOcctl(t, sampleUsers)
	p := newTestPlugin(t, &Args{OcctlPath: occtl, Socket: socket, Mark: 7})

	runQuery(t, p, "203.0.113.10")
	runQuery(t, p, "203.0.113.9")

	raw, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatalf("read argv log: %v", err)
	}
	// One occtl call records five argument lines; a second call would double it.
	if lines := strings.Count(string(raw), "\n"); lines != 5 {
		t.Fatalf("occtl called %d times, want 1 (argv log %q)", lines/5, string(raw))
	}
}

func TestOcctlFailureIsNotFatal(t *testing.T) {
	dir := t.TempDir()
	occtl := filepath.Join(dir, "occtl")
	script := "#!/bin/sh\necho 'failed to connect to socket' >&2\nexit 1\n"
	if err := os.WriteFile(occtl, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake occtl: %v", err)
	}
	socket := filepath.Join(dir, "occtl.socket")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatalf("write fake socket: %v", err)
	}
	p := newTestPlugin(t, &Args{OcctlPath: occtl, Socket: socket, Mark: 7})

	qCtx := runQuery(t, p, "203.0.113.10")
	if qCtx.HasMark(7) {
		t.Fatalf("a failed occtl call must not mark the query")
	}
}

// Without a configured endpoint the plugin must be a silent pass-through:
// no occtl call, no mark, even when an occtl binary is reachable.
func TestDisabledWithoutEndpoint(t *testing.T) {
	occtl, argvLog, _ := fakeOcctl(t, sampleUsers)
	p := newTestPlugin(t, &Args{OcctlPath: occtl, Mark: 7})

	qCtx := runQuery(t, p, "203.0.113.10")
	if qCtx.HasMark(7) {
		t.Fatalf("disabled plugin must not mark the query")
	}
	if _, err := os.Stat(argvLog); err == nil {
		t.Fatalf("disabled plugin must not call occtl; argv log was written")
	}
}

// A configured socket that does not exist yet is skipped instead of retried
// on every query.
func TestMissingSocketFileSkipsCall(t *testing.T) {
	occtl, argvLog, _ := fakeOcctl(t, sampleUsers)
	p := newTestPlugin(t, &Args{OcctlPath: occtl, Socket: filepath.Join(t.TempDir(), "absent.socket"), Mark: 7})

	qCtx := runQuery(t, p, "203.0.113.10")
	if qCtx.HasMark(7) {
		t.Fatalf("missing socket must not mark the query")
	}
	if _, err := os.Stat(argvLog); err == nil {
		t.Fatalf("missing socket must not call occtl; argv log was written")
	}
}

func TestParseUsersNormalizesKeys(t *testing.T) {
	raw := []byte(`[
 {"Username":"alice","Remote_IP":"203.0.113.9/32","IPv4":"10.8.0.2"},
 {"Username":"bob","remote ip":"[fd00::1]:443","vpn ip":"10.8.0.3"}
]`)
	users, err := parseUsers(raw)
	if err != nil {
		t.Fatalf("parseUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("parsed %d users, want 2", len(users))
	}
	if users[0].RemoteIP != "203.0.113.9" || users[0].VPNIP != "10.8.0.2" {
		t.Fatalf("alice = %+v", users[0])
	}
	if users[1].RemoteIP != "fd00::1" || users[1].VPNIP != "10.8.0.3" {
		t.Fatalf("bob = %+v", users[1])
	}
}

func TestArgsDefaultsAndExclusivity(t *testing.T) {
	// No endpoint is valid: the plugin simply stays disabled.
	a := &Args{}
	if err := a.initDefault(); err != nil {
		t.Fatalf("empty args rejected: %v", err)
	}
	if a.enabled() {
		t.Fatalf("empty args must be disabled")
	}
	if a.OcctlPath != "occtl" || a.Timeout != 3 || a.CacheTTL != 15 {
		t.Fatalf("defaults not applied: %+v", a)
	}

	if err := (&Args{Socket: "/run/x.sock", Addr: "1.2.3.4:4433"}).initDefault(); err == nil {
		t.Fatalf("socket and addr together must be rejected")
	}

	tcp := &Args{Addr: "1.2.3.4:4433"}
	if err := tcp.initDefault(); err != nil {
		t.Fatalf("addr-only args rejected: %v", err)
	}
	if !tcp.enabled() || tcp.endpoint() != "1.2.3.4:4433" {
		t.Fatalf("addr endpoint not applied: %+v", tcp)
	}
}

func withCandidates(t *testing.T, list []string) {
	t.Helper()
	old := autoSocketCandidates
	autoSocketCandidates = list
	t.Cleanup(func() { autoSocketCandidates = old })
}

func TestAutoSocketDiscoversFirstExisting(t *testing.T) {
	occtl, argvLog, _ := fakeOcctl(t, sampleUsers)
	dir := t.TempDir()
	sock := filepath.Join(dir, "occtl.socket")
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatalf("write socket: %v", err)
	}
	withCandidates(t, []string{filepath.Join(dir, "absent.socket"), sock})

	p := newTestPlugin(t, &Args{OcctlPath: occtl, Socket: autoSocket, Mark: 7})
	if !p.available() {
		t.Fatalf("auto socket that exists must be usable")
	}
	runQuery(t, p, "203.0.113.10")

	raw, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatalf("read argv log: %v", err)
	}
	if want := "-s\n" + sock + "\n-j\nshow\nusers\n"; string(raw) != want {
		t.Fatalf("occtl argv = %q, want %q", raw, want)
	}
}

func TestAutoSocketMissingSkipsCall(t *testing.T) {
	occtl, argvLog, _ := fakeOcctl(t, sampleUsers)
	withCandidates(t, []string{filepath.Join(t.TempDir(), "absent.socket")})

	p := newTestPlugin(t, &Args{OcctlPath: occtl, Socket: autoSocket})
	if p.available() {
		t.Fatalf("no candidate exists, availability must be false")
	}
	runQuery(t, p, "203.0.113.10")
	if raw, err := os.ReadFile(argvLog); err == nil && len(raw) > 0 {
		t.Fatalf("occtl must not be called without a socket, argv = %q", raw)
	}
}
