package telegram_bot

import (
	"context"
	"strings"
	"testing"
)

func TestHelpListsOnlyPermittedCommands(t *testing.T) {
	args := &Args{
		ChatIDs: []int64{111}, // default_role admin
		Admins: []AdminUser{
			{ChatID: 222, Role: RoleSuperAdmin},
			{ChatID: 333, Role: "auditor"},
		},
		Roles: map[string]Role{
			"auditor": {Allow: []string{PermAccess}},
		},
		FakeIPTags: []string{"fakeip"},
	}
	args.initDefault()
	access, err := buildAccess(args)
	if err != nil {
		t.Fatalf("buildAccess: %v", err)
	}

	p := newStubPlugin()
	p.args = args
	p.args.AuditLog = ""
	p.access = access

	adminHelp := p.helpFor(111)
	for _, want := range []string{"role: admin", "/user list", "/access <user>", "/vpn users", "/status", "/provider"} {
		if !strings.Contains(adminHelp, want) {
			t.Errorf("admin help lacks %q:\n%s", want, adminHelp)
		}
	}
	for _, forbidden := range []string{"/config", "/exec", "/reload", "/fip", "fakeip mappings"} {
		if strings.Contains(adminHelp, forbidden) {
			t.Errorf("admin help must not show %q:\n%s", forbidden, adminHelp)
		}
	}

	superHelp := p.helpFor(222)
	for _, want := range []string{"/config", "/exec", "/reload", "/fip", "/access", "/user"} {
		if !strings.Contains(superHelp, want) {
			t.Errorf("superadmin help lacks %q:\n%s", want, superHelp)
		}
	}

	// A role that only holds "access" sees just that group, plus the
	// unconditional /perm and /help lines.
	auditorHelp := p.helpFor(333)
	if !strings.Contains(auditorHelp, "/access <ip>") {
		t.Errorf("auditor help lacks /access:\n%s", auditorHelp)
	}
	for _, forbidden := range []string{"/status", "/vpn", "/fip", "/config"} {
		if strings.Contains(auditorHelp, forbidden) {
			t.Errorf("auditor help must not show %q:\n%s", forbidden, auditorHelp)
		}
	}
	if !strings.Contains(auditorHelp, "/help") || !strings.Contains(auditorHelp, "/perm") {
		t.Errorf("auditor help lacks the always-available entries:\n%s", auditorHelp)
	}
}

func TestHelpIsNotGatedByAPermission(t *testing.T) {
	args := &Args{
		Admins: []AdminUser{{ChatID: 444, Role: "auditor"}},
		Roles:  map[string]Role{"auditor": {Allow: []string{PermAccess}}},
	}
	args.initDefault()
	access, err := buildAccess(args)
	if err != nil {
		t.Fatalf("buildAccess: %v", err)
	}

	p := newStubPlugin()
	p.args = args
	p.args.AuditLog = ""
	p.access = access

	reply, _ := p.handleText(context.Background(), 444, "/help")
	if strings.Contains(reply, "permission denied") {
		t.Fatalf("/help must work for any administrator, got %q", reply)
	}
	if !strings.Contains(reply, "/access") {
		t.Fatalf("/help reply lacks the only command the role may run: %q", reply)
	}

	// /start is the same entry point.
	reply, _ = p.handleText(context.Background(), 444, "/start")
	if strings.Contains(reply, "permission denied") {
		t.Fatalf("/start must work for any administrator, got %q", reply)
	}
}
