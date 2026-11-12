package ocserv_ctl

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shortSocketDir keeps the unix path under the 104 byte limit that macOS
// still enforces; t.TempDir can be too long.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ocev")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func sendEvent(t *testing.T, conn net.Conn, raw string) eventReply {
	t.Helper()
	if _, err := conn.Write([]byte(raw + "\n")); err != nil {
		t.Fatalf("send event: %v", err)
	}
	sc := bufio.NewScanner(conn)
	if !sc.Scan() {
		t.Fatalf("no reply: %v", sc.Err())
	}
	var r eventReply
	if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
		t.Fatalf("decode reply %q: %v", sc.Text(), err)
	}
	return r
}

func TestEventSocketRecordsConnectAndDisconnect(t *testing.T) {
	dir := shortSocketDir(t)
	sock := filepath.Join(dir, "events.sock")
	eventLog := filepath.Join(dir, "events.jsonl")

	p := newTestPlugin(t, &Args{EventSocket: sock, EventLog: eventLog, EventBuffer: 10})
	t.Cleanup(func() { _ = p.Close() })

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial event socket: %v", err)
	}

	if r := sendEvent(t, conn, `{"event":"connect","user":"alice","real_ip":"203.0.113.9","vpn_ip":"10.8.0.2","geo":"CN / Guangxi","rx_bytes":0,"time":"2026-11-12 23:00:00"}`); !r.OK {
		t.Fatalf("connect rejected: %+v", r)
	}
	if r := sendEvent(t, conn, `{"event":"disconnect","user":"alice","real_ip":"203.0.113.9","vpn_ip":"10.8.0.2","rx_bytes":1048576,"tx_bytes":524288}`); !r.OK {
		t.Fatalf("disconnect rejected: %+v", r)
	}
	_ = conn.Close()

	out, err := p.AdminEvents(10, "")
	if err != nil {
		t.Fatalf("AdminEvents: %v", err)
	}
	for _, want := range []string{"user=alice", "event=disconnect", "rx_bytes=1048576", "event=connect"} {
		if !strings.Contains(out, want) {
			t.Fatalf("events output missing %q:\n%s", want, out)
		}
	}

	raw, err := os.ReadFile(eventLog)
	if err != nil {
		t.Fatalf("read event log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("event log lines = %d, want 2:\n%s", len(lines), raw)
	}
	var stored updownEvent
	if err := json.Unmarshal([]byte(lines[1]), &stored); err != nil {
		t.Fatalf("decode stored event: %v", err)
	}
	if stored.Event != "disconnect" || stored.User != "alice" || stored.RXBytes != 1048576 {
		t.Fatalf("stored event = %+v", stored)
	}
	if stored.Time == "" {
		t.Fatalf("timestamp was not filled in: %+v", stored)
	}
}

func TestEventSocketRejectsInvalidEvents(t *testing.T) {
	dir := shortSocketDir(t)
	sock := filepath.Join(dir, "events.sock")
	p := newTestPlugin(t, &Args{EventSocket: sock, EventBuffer: 10})
	t.Cleanup(func() { _ = p.Close() })

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial event socket: %v", err)
	}
	defer conn.Close()

	if r := sendEvent(t, conn, `not json`); r.OK || !strings.Contains(r.Error, "invalid json") {
		t.Fatalf("invalid json reply = %+v", r)
	}
	if r := sendEvent(t, conn, `{"event":"connect","user":"../etc","real_ip":"1.2.3.4"}`); r.OK {
		t.Fatalf("path traversal user accepted: %+v", r)
	}
	if r := sendEvent(t, conn, `{"event":"reconnect","user":"alice"}`); r.OK {
		t.Fatalf("unknown event accepted: %+v", r)
	}

	out, err := p.AdminEvents(10, "")
	if err != nil {
		t.Fatalf("AdminEvents: %v", err)
	}
	if out != "no events recorded yet" {
		t.Fatalf("invalid events must not be stored, got %q", out)
	}
}

func TestEventSocketFilterAndLimit(t *testing.T) {
	dir := shortSocketDir(t)
	sock := filepath.Join(dir, "events.sock")
	p := newTestPlugin(t, &Args{EventSocket: sock, EventBuffer: 3})
	t.Cleanup(func() { _ = p.Close() })

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial event socket: %v", err)
	}
	defer conn.Close()

	for _, user := range []string{"alice", "bob", "alice"} {
		if r := sendEvent(t, conn, `{"event":"connect","user":"`+user+`","real_ip":"203.0.113.9"}`); !r.OK {
			t.Fatalf("event %s rejected: %+v", user, r)
		}
	}

	out, err := p.AdminEvents(2, "alice")
	if err != nil {
		t.Fatalf("AdminEvents: %v", err)
	}
	if strings.Count(out, "user=alice") != 2 {
		t.Fatalf("expected the two newest alice events, got:\n%s", out)
	}
	if strings.Contains(out, "user=bob") {
		t.Fatalf("filter leaked bob:\n%s", out)
	}

	// The ring keeps only the newest three entries: adding carol drops the
	// oldest alice event.
	if r := sendEvent(t, conn, `{"event":"connect","user":"carol","real_ip":"203.0.113.9"}`); !r.OK {
		t.Fatalf("carol rejected: %+v", r)
	}
	all, err := p.AdminEvents(10, "")
	if err != nil {
		t.Fatalf("AdminEvents: %v", err)
	}
	if strings.Contains(all, "user=alice") && strings.Count(all, "user=alice") > 1 {
		t.Fatalf("ring did not drop the oldest event:\n%s", all)
	}
}

func TestEventSocketDisabled(t *testing.T) {
	p := newTestPlugin(t, &Args{})
	t.Cleanup(func() { _ = p.Close() })
	if _, err := p.AdminEvents(10, ""); err == nil || !strings.Contains(err.Error(), "event_socket") {
		t.Fatalf("disabled socket error = %v", err)
	}
}

func TestCloseRemovesEventSocket(t *testing.T) {
	dir := shortSocketDir(t)
	sock := filepath.Join(dir, "events.sock")
	p := newTestPlugin(t, &Args{EventSocket: sock})
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket file still present: %v", err)
	}
}
