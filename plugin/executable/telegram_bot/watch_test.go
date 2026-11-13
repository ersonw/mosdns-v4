package telegram_bot

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	tgbot "github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	fakeipadmin "github.com/ersonw/mosdns-v4/pkg/fakeip_admin"
)

type fakeWatchSender struct {
	mu    sync.Mutex
	sent  []string
	edits []string
}

func (s *fakeWatchSender) SendMessage(_ context.Context, params *tgbot.SendMessageParams) (*models.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, params.Text)
	return &models.Message{ID: 1}, nil
}

func (s *fakeWatchSender) EditMessageText(_ context.Context, params *tgbot.EditMessageTextParams) (*models.Message, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.edits = append(s.edits, params.Text)
	return &models.Message{ID: params.MessageID}, nil
}

func (s *fakeWatchSender) editCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.edits)
}

type fakeWatchAdmin struct {
	mu      sync.Mutex
	starts  int
	stops   int
	events  []fakeipadmin.TrafficEvent
	version uint64
}

func (a *fakeWatchAdmin) AdminWatchStart(context.Context, string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.starts++
	return nil
}

func (a *fakeWatchAdmin) AdminWatchSnapshot(context.Context, string, int) ([]fakeipadmin.TrafficEvent, uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]fakeipadmin.TrafficEvent(nil), a.events...), a.version, nil
}

func (a *fakeWatchAdmin) AdminWatchStop(context.Context, string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stops++
	return nil
}

func newWatchTestBot(t *testing.T) (*telegramBot, *fakeWatchAdmin, *fakeWatchSender) {
	t.Helper()
	admin := &fakeWatchAdmin{version: 1}
	sender := &fakeWatchSender{}
	p := &telegramBot{
		args:          &Args{FakeIPTags: []string{"fakeip"}},
		ctx:           context.Background(),
		watchTest:     admin,
		watchCache:    make(map[string]watchAdmin),
		watchSessions: make(map[int64]map[*watchSession]struct{}),
		sender:        sender,
		loc:           time.UTC,
	}
	return p, admin, sender
}

func TestFormatWatchTextUsesProtocolAndDomain(t *testing.T) {
	p, _, _ := newWatchTestBot(t)
	events := []fakeipadmin.TrafficEvent{{
		Time:            1_700_000_000,
		ClientIP:        "192.0.2.10",
		ClientPort:      50000,
		DestinationIP:   "203.0.113.9",
		DestinationPort: 443,
		FakeIP:          "198.18.0.5",
		Domain:          "example.com",
		Protocol:        "tcp",
		Packets:         3,
	}}
	en := p.formatWatchText(langEN, "fakeip", "192.0.2.10", events, false)
	zh := p.formatWatchText(langZH, "fakeip", "192.0.2.10", events, false)
	for _, want := range []string{"TCP", "192.0.2.10:50000", "203.0.113.9:443", "example.com", "fake=198.18.0.5", "pkts=3"} {
		if !strings.Contains(en, want) {
			t.Fatalf("english text missing %q: %s", want, en)
		}
	}
	if !strings.Contains(zh, "正在监听") || !strings.Contains(zh, "发送 /stop") {
		t.Fatalf("chinese text not localized: %s", zh)
	}
}

func TestHandleWatchThenGlobalStop(t *testing.T) {
	p, admin, sender := newWatchTestBot(t)
	admin.events = []fakeipadmin.TrafficEvent{{
		Time: 1_700_000_000, ClientIP: "192.0.2.10", ClientPort: 50000,
		DestinationIP: "203.0.113.9", DestinationPort: 443, Protocol: "tcp",
	}}
	reply, err := p.handleWatch(context.Background(), 42, []string{"192.0.2.10"}, langEN)
	if err != nil || reply != "" {
		t.Fatalf("handleWatch reply=%q err=%v", reply, err)
	}
	if _, err := p.handleWatch(context.Background(), 42, []string{"192.0.2.11"}, langEN); err != nil {
		t.Fatalf("second handleWatch: %v", err)
	}
	if admin.starts != 2 || len(sender.sent) != 2 {
		t.Fatalf("starts=%d sent=%d", admin.starts, len(sender.sent))
	}

	stopReply, err := p.handleStop(context.Background(), 42, langEN)
	if err != nil {
		t.Fatalf("handleStop: %v", err)
	}
	if !strings.Contains(stopReply, "stopped 2") {
		t.Fatalf("stop reply = %q", stopReply)
	}
	if admin.stops != 2 {
		t.Fatalf("stops = %d, want 2", admin.stops)
	}
	if sender.editCount() != 2 {
		t.Fatalf("edits = %d, want two stopped messages", sender.editCount())
	}
	p.wg.Wait()
}

func TestStopWithoutSessions(t *testing.T) {
	p, _, _ := newWatchTestBot(t)
	reply, err := p.handleStop(context.Background(), 42, langEN)
	if err != nil || !strings.Contains(reply, "no active") {
		t.Fatalf("reply=%q err=%v", reply, err)
	}
}
