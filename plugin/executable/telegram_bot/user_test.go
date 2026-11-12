package telegram_bot

import (
	"context"
	"strings"
	"testing"

	"github.com/ersonw/mosdns-v4/plugin/executable/radius"
)

// stubRadius records the calls the /user command makes.
type stubRadius struct {
	users    []radius.User
	sessions []radius.Session
	added    [][3]string
	deleted  []string
	pass     [][2]string
	enabled  [][2]bool
	groups   [][2]string
	ips      [][2]string
}

func (s *stubRadius) Users() ([]radius.User, error) { return s.users, nil }

func (s *stubRadius) AddUser(name, password, group string) error {
	s.added = append(s.added, [3]string{name, password, group})
	return nil
}

func (s *stubRadius) DeleteUser(name string) (bool, error) {
	s.deleted = append(s.deleted, name)
	for _, u := range s.users {
		if u.Name == name {
			return true, nil
		}
	}
	return false, nil
}

func (s *stubRadius) SetPassword(name, password string) (bool, error) {
	s.pass = append(s.pass, [2]string{name, password})
	return true, nil
}

func (s *stubRadius) SetEnabled(name string, enabled bool) (bool, error) {
	s.enabled = append(s.enabled, [2]bool{true, enabled})
	return true, nil
}

func (s *stubRadius) SetGroup(name, group string) (bool, error) {
	s.groups = append(s.groups, [2]string{name, group})
	return true, nil
}

func (s *stubRadius) SetIP(name, ip string) (bool, error) {
	s.ips = append(s.ips, [2]string{name, ip})
	return true, nil
}

func (s *stubRadius) Sessions(activeOnly bool, limit int) ([]radius.Session, error) {
	if activeOnly {
		var out []radius.Session
		for _, r := range s.sessions {
			if r.Active {
				out = append(out, r)
			}
		}
		return out, nil
	}
	return s.sessions, nil
}

func newRadiusBot() (*telegramBot, *stubRadius) {
	p := newStubPlugin()
	adm := &stubRadius{
		users: []radius.User{
			{Name: "alice", Group: "staff", IP: "10.8.0.20", Enabled: true, UpdatedAt: 1700000000},
			{Name: "bob", Enabled: false, UpdatedAt: 1700000100},
		},
		sessions: []radius.Session{
			{SessionID: "sess-1", Name: "alice", RemoteIP: "10.9.0.2", StartedAt: 1700000000, UpdatedAt: 1700001000, In: 1024, Out: 2048, Active: true},
			{SessionID: "sess-2", Name: "bob", RemoteIP: "10.9.0.3", StartedAt: 1699990000, EndedAt: 1699995000, Active: false},
		},
	}
	p.radius = adm
	return p, adm
}

func TestUserHelp(t *testing.T) {
	p, _ := newRadiusBot()
	reply, err := p.handleText(context.Background(), 123, "/user")
	if err != nil {
		t.Fatalf("handleText: %v", err)
	}
	if !strings.Contains(reply, "/user add") || !strings.Contains(reply, "/user ip") || !strings.Contains(reply, "/user sessions") {
		t.Fatalf("help text missing commands: %s", reply)
	}
}

func TestUserList(t *testing.T) {
	p, _ := newRadiusBot()
	reply, err := p.handleText(context.Background(), 123, "/user list")
	if err != nil {
		t.Fatalf("handleText: %v", err)
	}
	for _, want := range []string{"users on radius (2)", "alice", "staff", "ip=10.8.0.20", "enabled", "bob", "disabled"} {
		if !strings.Contains(reply, want) {
			t.Fatalf("list output missing %q: %s", want, reply)
		}
	}
}

func TestUserAddRequiresArguments(t *testing.T) {
	p, adm := newRadiusBot()
	reply, _ := p.handleText(context.Background(), 123, "/user add alice")
	if !strings.Contains(reply, "usage: /user add") {
		t.Fatalf("missing usage reply: %s", reply)
	}
	if len(adm.added) != 0 {
		t.Fatalf("AddUser was called without a password: %v", adm.added)
	}
}

func TestUserAddWithGroup(t *testing.T) {
	p, adm := newRadiusBot()
	reply, _ := p.handleText(context.Background(), 123, "/user add carol secret123 ops")
	if !strings.Contains(reply, "added carol") || !strings.Contains(reply, "ops") {
		t.Fatalf("unexpected reply: %s", reply)
	}
	if len(adm.added) != 1 || adm.added[0] != [3]string{"carol", "secret123", "ops"} {
		t.Fatalf("AddUser call = %v", adm.added)
	}
}

func TestUserDeleteUnknown(t *testing.T) {
	p, _ := newRadiusBot()
	reply, _ := p.handleText(context.Background(), 123, "/user del dave")
	if !strings.Contains(reply, "no such user") {
		t.Fatalf("unexpected reply: %s", reply)
	}
}

func TestUserPasswordAndToggle(t *testing.T) {
	p, adm := newRadiusBot()
	reply, _ := p.handleText(context.Background(), 123, "/user pass alice newsecret")
	if !strings.Contains(reply, "password changed") {
		t.Fatalf("unexpected reply: %s", reply)
	}
	if len(adm.pass) != 1 || adm.pass[0] != [2]string{"alice", "newsecret"} {
		t.Fatalf("SetPassword call = %v", adm.pass)
	}

	reply, _ = p.handleText(context.Background(), 123, "/user disable alice")
	if !strings.Contains(reply, "alice: disabled") {
		t.Fatalf("unexpected reply: %s", reply)
	}
	if len(adm.enabled) != 1 || adm.enabled[0][1] != false {
		t.Fatalf("SetEnabled calls = %v", adm.enabled)
	}
}

func TestUserGroup(t *testing.T) {
	p, adm := newRadiusBot()
	reply, _ := p.handleText(context.Background(), 123, "/user group alice ops")
	if !strings.Contains(reply, "group ops") {
		t.Fatalf("unexpected reply: %s", reply)
	}
	if len(adm.groups) != 1 || adm.groups[0] != [2]string{"alice", "ops"} {
		t.Fatalf("SetGroup calls = %v", adm.groups)
	}
}

func TestUserFixedIP(t *testing.T) {
	p, adm := newRadiusBot()
	reply, _ := p.handleText(context.Background(), 123, "/user ip alice 10.8.0.30")
	if !strings.Contains(reply, "fixed ip 10.8.0.30") {
		t.Fatalf("unexpected reply: %s", reply)
	}
	if len(adm.ips) != 1 || adm.ips[0] != [2]string{"alice", "10.8.0.30"} {
		t.Fatalf("SetIP calls = %v", adm.ips)
	}

	reply, _ = p.handleText(context.Background(), 123, "/user ip alice -")
	if !strings.Contains(reply, "fixed ip cleared") {
		t.Fatalf("unexpected clear reply: %s", reply)
	}
	if len(adm.ips) != 2 || adm.ips[1] != [2]string{"alice", "-"} {
		t.Fatalf("SetIP calls after clear = %v", adm.ips)
	}

	reply, _ = p.handleText(context.Background(), 123, "/user ip alice")
	if !strings.Contains(reply, "usage: /user ip") {
		t.Fatalf("missing usage reply: %s", reply)
	}
}

func TestUserSessionsActiveOnly(t *testing.T) {
	p, _ := newRadiusBot()
	reply, _ := p.handleText(context.Background(), 123, "/user sessions active")
	if !strings.Contains(reply, "sess-1") {
		t.Fatalf("active session missing: %s", reply)
	}
	if strings.Contains(reply, "sess-2") {
		t.Fatalf("closed session leaked into the active list: %s", reply)
	}
}

func TestUserCommandNeedsRadiusPermission(t *testing.T) {
	p, _ := newRadiusBot()
	// Role without the radius permission: the command must be refused, not
	// answered by the injected stub.
	p.args.Roles = map[string]Role{
		"vpnonly": {Allow: []string{PermStatus, PermOcserv}},
	}
	p.args.DefaultRole = "vpnonly"
	if acc, err := buildAccess(p.args); err == nil {
		p.access = acc
	}
	reply, _ := p.handleText(context.Background(), 123, "/user list")
	if !strings.Contains(reply, "permission denied") {
		t.Fatalf("expected a permission error, got: %s", reply)
	}
}
