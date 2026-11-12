package telegram_bot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	tgbot "github.com/go-telegram/bot"

	"github.com/ersonw/mosdns-v4/coremain"
	fakeipnat "github.com/ersonw/mosdns-v4/plugin/executable/fakeip_nat"
	"go.uber.org/zap"
)

type stubAdmin struct {
	entries []fakeipnat.MappingEntry
	stats   fakeipnat.MappingStats
	deleted []string
	put     [][2]string
	clearN  int64
}

func (s *stubAdmin) AdminPutMapping(_ context.Context, domain, fakeIP string) error {
	s.put = append(s.put, [2]string{domain, fakeIP})
	return nil
}

// stubOcserv records the argv handed to occtl.
type stubOcserv struct {
	argv []string
	out  string
}

func (s *stubOcserv) AdminExec(_ context.Context, argv []string) (string, error) {
	s.argv = argv
	return s.out, nil
}

func (s *stubAdmin) AdminListMappings(context.Context, int) ([]fakeipnat.MappingEntry, error) {
	return s.entries, nil
}

func (s *stubAdmin) AdminLookupDomain(_ context.Context, domain string) (*fakeipnat.MappingEntry, bool, error) {
	for i := range s.entries {
		if s.entries[i].Domain == domain {
			return &s.entries[i], true, nil
		}
	}
	return nil, false, nil
}

func (s *stubAdmin) AdminLookupFakeIP(_ context.Context, fakeIP string) (*fakeipnat.MappingEntry, bool, error) {
	for i := range s.entries {
		if s.entries[i].FakeIP == fakeIP {
			return &s.entries[i], true, nil
		}
	}
	return nil, false, nil
}

func (s *stubAdmin) AdminDeleteDomain(_ context.Context, domain string) (bool, error) {
	s.deleted = append(s.deleted, domain)
	return true, nil
}

func (s *stubAdmin) AdminClearMappings(context.Context) (int64, error) {
	return s.clearN, nil
}

func (s *stubAdmin) AdminStats(context.Context) (fakeipnat.MappingStats, error) {
	return s.stats, nil
}

func newStubPlugin() *telegramBot {
	bp := coremain.NewBP("test_bot", PluginType, zap.NewNop(), nil)
	p := &telegramBot{BP: bp, args: &Args{ChatIDs: []int64{123}, FakeIPTag: "fakeip"}}
	p.args.initDefault()
	// Administration actions are audited; a test keeps them off the real file
	// so the working tree stays clean. A test that checks the log sets its own.
	p.args.AuditLog = os.DevNull
	if acc, err := buildAccess(p.args); err == nil {
		p.access = acc
	}
	p.admin = &stubAdmin{
		entries: []fakeipnat.MappingEntry{
			{Domain: "a.example.com", FakeIP: "198.18.0.2", CreatedAt: 1700000000},
			{Domain: "b.example.com", FakeIP: "198.18.0.3", CreatedAt: 1700000001},
		},
		stats:  fakeipnat.MappingStats{Mappings: 2, Runtime: 2},
		clearN: 2,
	}
	return p
}

func TestHandleHelp(t *testing.T) {
	p := newStubPlugin()
	reply, err := p.handleText(context.Background(), 123, "/help")
	if err != nil {
		t.Fatalf("handleText: %v", err)
	}
	if !strings.Contains(reply, "/fip") || !strings.Contains(reply, "/config set") {
		t.Fatalf("help text incomplete: %q", reply)
	}
}

func TestHandleStatsAndList(t *testing.T) {
	p := newStubPlugin()

	reply, err := p.handleText(context.Background(), 123, "/stats")
	if err != nil {
		t.Fatalf("handleText: %v", err)
	}
	if !strings.Contains(reply, "mappings: 2") {
		t.Fatalf("stats reply = %q", reply)
	}

	reply, err = p.handleText(context.Background(), 123, "/list 2")
	if err != nil {
		t.Fatalf("handleText: %v", err)
	}
	if !strings.Contains(reply, "a.example.com -> 198.18.0.2") {
		t.Fatalf("list reply = %q", reply)
	}
}

func TestHandleLookupAndReverse(t *testing.T) {
	p := newStubPlugin()

	reply, _ := p.handleText(context.Background(), 123, "/lookup a.example.com")
	if !strings.Contains(reply, "198.18.0.2") {
		t.Fatalf("lookup reply = %q", reply)
	}

	reply, _ = p.handleText(context.Background(), 123, "/rev 198.18.0.3")
	if !strings.Contains(reply, "b.example.com") {
		t.Fatalf("rev reply = %q", reply)
	}

	reply, _ = p.handleText(context.Background(), 123, "/lookup missing.example.com")
	if !strings.Contains(reply, "no mapping") {
		t.Fatalf("missing lookup reply = %q", reply)
	}
}

func TestHandleDeleteRequiresConfirmationToClear(t *testing.T) {
	p := newStubPlugin()

	reply, _ := p.handleText(context.Background(), 123, "/del a.example.com")
	if !strings.Contains(reply, "deleted") {
		t.Fatalf("del reply = %q", reply)
	}
	if got := p.admin.(*stubAdmin).deleted; len(got) != 1 || got[0] != "a.example.com" {
		t.Fatalf("deleted = %v", got)
	}

	reply, _ = p.handleText(context.Background(), 123, "/clear")
	if !strings.Contains(reply, "/fip clear confirm") {
		t.Fatalf("bare clear must ask for confirmation, got %q", reply)
	}

	reply, _ = p.handleText(context.Background(), 123, "/clear confirm")
	if !strings.Contains(reply, "deleted 2") {
		t.Fatalf("confirmed clear reply = %q", reply)
	}
}

func TestGroupsCommandSuffixIsStripped(t *testing.T) {
	p := newStubPlugin()
	reply, err := p.handleText(context.Background(), 123, "/stats@my_bot")
	if err != nil || !strings.Contains(reply, "mappings") {
		t.Fatalf("group command reply = %q err=%v", reply, err)
	}
}

func TestFipAddAndGet(t *testing.T) {
	p := newStubPlugin()

	reply, err := p.handleText(context.Background(), 123, "/fip add pinned.example.com 198.18.0.9")
	if err != nil || !strings.Contains(reply, "saved") {
		t.Fatalf("fip add reply = %q err=%v", reply, err)
	}
	if got := p.admin.(*stubAdmin).put; len(got) != 1 || got[0] != [2]string{"pinned.example.com", "198.18.0.9"} {
		t.Fatalf("put = %v", got)
	}

	reply, _ = p.handleText(context.Background(), 123, "/fip add pinned.example.com")
	if !strings.Contains(reply, "usage") {
		t.Fatalf("incomplete add must show usage, got %q", reply)
	}
}

func TestVPNCommandsForwardToOcctl(t *testing.T) {
	p := newStubPlugin()
	oc := &stubOcserv{out: "user\t10.0.0.2\n"}
	p.ocserv = oc

	reply, err := p.handleText(context.Background(), 123, "/vpn users")
	if err != nil || !strings.Contains(reply, "10.0.0.2") {
		t.Fatalf("vpn users reply = %q err=%v", reply, err)
	}
	if strings.Join(oc.argv, " ") != "show users" {
		t.Fatalf("argv = %v", oc.argv)
	}

	reply, err = p.handleText(context.Background(), 123, "/vpn kick alice")
	if err != nil || !strings.Contains(reply, "10.0.0.2") {
		t.Fatalf("vpn kick reply = %q err=%v", reply, err)
	}
	if strings.Join(oc.argv, " ") != "disconnect user alice" {
		t.Fatalf("kick argv = %v", oc.argv)
	}

	oc.argv = nil
	_, err = p.handleText(context.Background(), 123, "/vpn run show iroutes")
	if err != nil {
		t.Fatalf("vpn run err = %v", err)
	}
	if strings.Join(oc.argv, " ") != "show iroutes" {
		t.Fatalf("run argv = %v", oc.argv)
	}

	reply, err = p.handleText(context.Background(), 123, "/vpn kick")
	if err != nil || !strings.Contains(reply, "usage") {
		t.Fatalf("missing argument must report usage, got %q err=%v", reply, err)
	}
}

func TestUnknownCommand(t *testing.T) {
	p := newStubPlugin()
	reply, _ := p.handleText(context.Background(), 123, "/nope")
	if !strings.Contains(reply, "/help") {
		t.Fatalf("unknown command reply = %q", reply)
	}
}

func TestArgsDisabledWithoutTokenOrChat(t *testing.T) {
	for _, a := range []*Args{
		{ChatIDs: []int64{1}},
		{Token: "x"},
		{},
	} {
		a.initDefault()
		if a.enabled() {
			t.Fatalf("args %+v must be disabled", a)
		}
	}

	a := &Args{Token: "x", ChatIDs: []int64{1}}
	a.initDefault()
	if !a.enabled() {
		t.Fatalf("token + chat must enable the bot")
	}
	if a.APIBase != "https://api.telegram.org" || a.PollTimeout != 30 || a.FakeIPTag != "fakeip" {
		t.Fatalf("defaults not applied: %+v", a)
	}
	if len(a.FakeIPTags) != 1 || a.FakeIPTags[0] != "fakeip" {
		t.Fatalf("fakeip_tags default = %v", a.FakeIPTags)
	}
	if len(a.OcservTags) != 1 || a.OcservTags[0] != "ocserv" {
		t.Fatalf("ocserv_tags default = %v", a.OcservTags)
	}
}

// fakeTelegram serves one queued update and records sendMessage calls.
type fakeTelegram struct {
	updateJSON string
	sent       chan string
	served     bool
	mu         sync.Mutex
}

func (f *fakeTelegram) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			f.mu.Lock()
			first := !f.served
			f.served = true
			f.mu.Unlock()
			if first {
				_, _ = w.Write([]byte(`{"ok":true,"result":[` + f.updateJSON + `]}`))
				return
			}
			// Idle: keep the poller from spinning while the test asserts.
			time.Sleep(100 * time.Millisecond)
			_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			// The library posts multipart/form-data.
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Logf("parse sendMessage form: %v", err)
			}
			select {
			case f.sent <- r.FormValue("text"):
			default:
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
		default:
			t.Logf("unexpected telegram path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// startBot wires the real Telegram library against the fake server.
func startBot(t *testing.T, p *telegramBot, serverURL string) (cancel context.CancelFunc, done <-chan struct{}) {
	t.Helper()
	poll := time.Second
	client, err := newHTTPClient("", poll+10*time.Second)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	tb, err := tgbot.New("TESTTOKEN",
		tgbot.WithSkipGetMe(),
		tgbot.WithServerURL(serverURL),
		tgbot.WithHTTPClient(poll, client),
		tgbot.WithDefaultHandler(p.onUpdate),
	)
	if err != nil {
		t.Fatalf("bot.New: %v", err)
	}

	ctx, cancelFn := context.WithCancel(context.Background())
	fin := make(chan struct{})
	go func() {
		defer close(fin)
		tb.Start(ctx)
	}()
	return cancelFn, fin
}

func TestBotRepliesToAllowedChat(t *testing.T) {
	fake := &fakeTelegram{
		updateJSON: `{"update_id":7,"message":{"chat":{"id":123},"text":"/stats"}}`,
		sent:       make(chan string, 4),
	}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	p := newStubPlugin()
	cancel, done := startBot(t, p, srv.URL)
	defer func() {
		cancel()
		<-done
	}()

	select {
	case reply := <-fake.sent:
		if !strings.Contains(reply, "mappings: 2") {
			t.Fatalf("reply = %q", reply)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("bot did not reply to an allowed chat")
	}
}

func TestBotIgnoresUnauthorizedChat(t *testing.T) {
	fake := &fakeTelegram{
		updateJSON: `{"update_id":9,"message":{"chat":{"id":999},"text":"/stats"}}`,
		sent:       make(chan string, 4),
	}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	p := newStubPlugin()
	cancel, done := startBot(t, p, srv.URL)
	time.Sleep(1500 * time.Millisecond)
	cancel()
	<-done

	select {
	case reply := <-fake.sent:
		t.Fatalf("unauthorized chat got a reply: %q", reply)
	default:
	}
}

func TestTagListMergesSingleAndList(t *testing.T) {
	a := &Args{FakeIPTags: []string{"fakeip", "fakeip2"}, FakeIPTag: "fakeip2"}
	a.initDefault()
	if len(a.FakeIPTags) != 2 {
		t.Fatalf("duplicate tag was not collapsed: %v", a.FakeIPTags)
	}
	if got, rest := pickTag(a.FakeIPTags, []string{"fakeip2", "list"}); got != "fakeip2" || len(rest) != 1 || rest[0] != "list" {
		t.Fatalf("pickTag = %q %v", got, rest)
	}
	if got, rest := pickTag(a.FakeIPTags, []string{"stats"}); got != "fakeip" || len(rest) != 1 || rest[0] != "stats" {
		t.Fatalf("default pickTag = %q %v", got, rest)
	}
}

func TestConfigCommandsEditFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := `# top comment
log:
  level: info # keep me

plugins:
  - tag: main
    type: sequence
  - tag: fakeip
    type: fakeip_nat

servers:
  - exec: main
    listeners:
      - protocol: udp
        addr: 127.0.0.1:1053
`
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	p := newStubPlugin()
	p.args.ConfigPath = path
	ctx := context.Background()

	reply, err := p.handleText(ctx, 123, "/config")
	if err != nil {
		t.Fatalf("config summary: %v", err)
	}
	if !strings.Contains(reply, "plugins: 2") || !strings.Contains(reply, "servers: 1") {
		t.Fatalf("summary = %q", reply)
	}

	reply, err = p.handleText(ctx, 123, "/config get plugins[1].tag")
	if err != nil || !strings.Contains(reply, "fakeip") {
		t.Fatalf("indexed get = %q err=%v", reply, err)
	}

	reply, err = p.handleText(ctx, 123, "/config set log.level debug")
	if err != nil || !strings.Contains(reply, "updated") {
		t.Fatalf("set = %q err=%v", reply, err)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read updated config: %v", err)
	}
	if !strings.Contains(string(updated), "debug") || !strings.Contains(string(updated), "# keep me") {
		t.Fatalf("value or comment lost: %s", updated)
	}

	reply, err = p.handleText(ctx, 123, "/config add plugins {tag: extra, type: sequence}")
	if err != nil || !strings.Contains(reply, "appended") {
		t.Fatalf("add = %q err=%v", reply, err)
	}
	if _, err := p.handleText(ctx, 123, "/config add plugins {tag: extra, type: sequence}"); err == nil {
		t.Fatalf("duplicate tag must be rejected")
	}

	reply, err = p.handleText(ctx, 123, "/config del plugins extra")
	if err != nil || !strings.Contains(reply, "removed") {
		t.Fatalf("del = %q err=%v", reply, err)
	}

	reply, err = p.handleText(ctx, 123, "/config validate")
	if err != nil || !strings.Contains(reply, "looks valid") {
		t.Fatalf("validate = %q err=%v", reply, err)
	}

	backups, _ := filepath.Glob(path + ".bak.*")
	if len(backups) == 0 {
		t.Fatalf("no backup was written")
	}
}

func TestRolePermissions(t *testing.T) {
	args := &Args{
		ChatIDs: []int64{123},
		Admins: []AdminUser{
			{ChatID: 1001, Role: "fakeip_admin"},
			{ChatID: 1002, Role: "ops"},
		},
		Roles: map[string]Role{
			"fakeip_admin": {Allow: []string{PermFakeIP}},
			"ops":          {Inherits: []string{"fakeip_admin"}, Allow: []string{PermOcserv, PermExecScript}},
		},
		FakeIPTag: "fakeip",
	}
	args.initDefault()
	access, err := buildAccess(args)
	if err != nil {
		t.Fatalf("buildAccess: %v", err)
	}

	p := newStubPlugin()
	p.args = args
	p.args.AuditLog = os.DevNull
	p.access = access
	ctx := context.Background()

	if err := p.require(1001, PermFakeIP); err != nil {
		t.Fatalf("role A should manage fakeip: %v", err)
	}
	if err := p.require(1001, PermOcserv); err == nil {
		t.Fatalf("role A must not manage ocserv")
	}
	if err := p.require(1001, PermExecScript); err == nil {
		t.Fatalf("role A must not run exec_script")
	}

	// role B inherits role A, so fakeip comes for free and it adds the rest.
	if err := p.require(1002, PermFakeIP); err != nil {
		t.Fatalf("role B should inherit fakeip: %v", err)
	}
	if err := p.require(1002, PermOcserv); err != nil {
		t.Fatalf("role B should manage ocserv: %v", err)
	}
	if err := p.require(1002, PermExecScript); err != nil {
		t.Fatalf("role B should run exec_script: %v", err)
	}
	if err := p.require(1002, PermConfig); err == nil {
		t.Fatalf("role B must not edit the config")
	}

	// chat 123 is only in chat_ids, so it keeps the built-in admin role.
	if !access.allowed(123, PermConfig) || !access.allowed(123, PermReload) {
		t.Fatalf("chat_ids entry lost full access: %s", access.permissionNames(123))
	}
	if err := p.require(999, PermStatus); err == nil {
		t.Fatalf("an unlisted chat must be rejected")
	}

	reply, _ := p.handleText(ctx, 1001, "/vpn users")
	if !strings.Contains(reply, "permission denied") {
		t.Fatalf("role A /vpn reply = %q", reply)
	}
	reply, _ = p.handleText(ctx, 1001, "/fip list")
	if strings.Contains(reply, "permission denied") {
		t.Fatalf("role A /fip must pass: %q", reply)
	}
}

func TestRoleInheritanceCycle(t *testing.T) {
	args := &Args{
		Admins: []AdminUser{{ChatID: 1, Role: "a"}},
		Roles: map[string]Role{
			"a": {Inherits: []string{"b"}},
			"b": {Inherits: []string{"a"}},
		},
	}
	args.initDefault()
	if _, err := buildAccess(args); err == nil {
		t.Fatalf("a cycle between roles must be rejected")
	}
}

func TestRoleUnknownPermission(t *testing.T) {
	args := &Args{
		Admins: []AdminUser{{ChatID: 1, Role: "x"}},
		Roles:  map[string]Role{"x": {Allow: []string{"bogus"}}},
	}
	args.initDefault()
	if _, err := buildAccess(args); err == nil {
		t.Fatalf("an unknown permission must be rejected")
	}
}
