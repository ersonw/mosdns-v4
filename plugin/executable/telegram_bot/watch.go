package telegram_bot

// This file implements /watch and the global /stop. One watch owns one Telegram
// message and keeps editing it in place: the data plane exposes the newest
// flows, the bot re-renders them only when the source's version changes, and
// /stop cancels every session belonging to the calling administrator.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	tgbot "github.com/go-telegram/bot"

	fakeipadmin "github.com/ersonw/mosdns-v4/pkg/fakeip_admin"
	"github.com/ersonw/mosdns-v4/pkg/timeutil"
	"go.uber.org/zap"
)

const (
	watchMessageLimit  = 20
	watchRefreshPeriod = 2 * time.Second
	watchMessageMaxLen = 4000
)

type watchSession struct {
	chatID    int64
	tag       string
	sourceIP  string
	messageID int
	admin     watchAdmin
	l         lang
	cancel    context.CancelFunc
	done      chan struct{}

	lastVersion uint64
}

func watchHelpText(l lang) string {
	return l.t(`traffic watch:
/watch [tag] <source_ip>   stream the newest 20 flows of one source
                           tag defaults to the first fakeip_tags entry
/stop                      stop every watch of this chat`,
		`流量监听：
/watch [tag] <source_ip>   监听一个源 IP 的最新 20 条流量
                           tag 默认使用 fakeip_tags 的第一项
/stop                      停止本聊天的全部监听`)
}

func (p *telegramBot) handleWatch(ctx context.Context, chatID int64, args []string, langs ...lang) (string, error) {
	l := replyLang(langs)
	if len(p.args.FakeIPTags) == 0 {
		return l.t("fakeip_tags is empty; traffic watch has no data plane to read",
			"fakeip_tags 为空，流量监听没有可读取的数据面"), nil
	}
	if len(args) == 0 || strings.EqualFold(args[0], "help") {
		return watchHelpText(l), nil
	}

	tag, rest := pickTag(p.args.FakeIPTags, args)
	if len(rest) == 0 {
		return l.t("usage: /watch [tag] <source_ip>", "用法：/watch [tag] <source_ip>"), nil
	}
	source, err := normalizeWatchIP(rest[0])
	if err != nil {
		return "", err
	}

	admin, err := p.resolveWatchFor(tag, l)
	if err != nil {
		return "", err
	}

	p.watchMu.Lock()
	for s := range p.watchSessions[chatID] {
		if s.tag == tag && s.sourceIP == source {
			p.watchMu.Unlock()
			return fmt.Sprintf(l.t("already watching %s on %s", "已在监听 %s（数据面 %s）"), source, tag), nil
		}
	}
	p.watchMu.Unlock()

	if err := admin.AdminWatchStart(ctx, source); err != nil {
		return "", err
	}
	events, version, err := admin.AdminWatchSnapshot(ctx, source, watchMessageLimit)
	if err != nil {
		_ = admin.AdminWatchStop(context.Background(), source)
		return "", err
	}

	text := p.formatWatchText(l, tag, source, events, false)
	if p.sender == nil {
		_ = admin.AdminWatchStop(context.Background(), source)
		return "", fmt.Errorf("telegram sender is not initialized")
	}
	msg, err := p.sender.SendMessage(ctx, &tgbot.SendMessageParams{ChatID: chatID, Text: text})
	if err != nil {
		_ = admin.AdminWatchStop(context.Background(), source)
		return "", fmt.Errorf("send watch message: %w", err)
	}
	if msg == nil {
		_ = admin.AdminWatchStop(context.Background(), source)
		return "", fmt.Errorf("send watch message: empty response")
	}

	parent := p.ctx
	if parent == nil {
		parent = context.Background()
	}
	runCtx, cancel := context.WithCancel(parent)
	s := &watchSession{
		chatID:      chatID,
		tag:         tag,
		sourceIP:    source,
		messageID:   msg.ID,
		admin:       admin,
		l:           l,
		cancel:      cancel,
		done:        make(chan struct{}),
		lastVersion: version,
	}

	p.watchMu.Lock()
	if p.watchSessions[chatID] == nil {
		p.watchSessions[chatID] = make(map[*watchSession]struct{})
	}
	p.watchSessions[chatID][s] = struct{}{}
	p.watchMu.Unlock()

	p.wg.Add(1)
	go p.runWatch(runCtx, s)
	return "", nil
}

func normalizeWatchIP(raw string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid source ip %q: %w", raw, err)
	}
	if !addr.Is4() {
		return "", fmt.Errorf("source ip %q is not IPv4; the fakeip data plane is IPv4 only", raw)
	}
	return addr.String(), nil
}

func (p *telegramBot) runWatch(ctx context.Context, s *watchSession) {
	defer p.wg.Done()
	defer close(s.done)

	ticker := time.NewTicker(watchRefreshPeriod)
	defer ticker.Stop()
	var editFailures int
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			events, version, err := s.admin.AdminWatchSnapshot(ctx, s.sourceIP, watchMessageLimit)
			if err != nil {
				p.L().Debug("traffic watch snapshot failed",
					zap.String("source_ip", s.sourceIP), zap.Error(err))
				continue
			}
			if version == s.lastVersion {
				continue
			}
			text := p.formatWatchText(s.l, s.tag, s.sourceIP, events, false)
			if p.sender == nil {
				continue
			}
			if _, err := p.sender.EditMessageText(ctx, &tgbot.EditMessageTextParams{
				ChatID:    s.chatID,
				MessageID: s.messageID,
				Text:      text,
			}); err != nil {
				p.L().Warn("traffic watch edit failed",
					zap.String("source_ip", s.sourceIP), zap.Error(err))
				editFailures++
				if editFailures >= 3 {
					// A deleted or no-longer-editable message is not worth
					// retrying forever; leave the capture for /stop or Close.
					return
				}
				continue
			}
			// Only a successful edit advances the version, so a transient API
			// failure retries the same snapshot on the next tick.
			s.lastVersion = version
			editFailures = 0
		}
	}
}

func (p *telegramBot) handleStop(ctx context.Context, chatID int64, langs ...lang) (string, error) {
	l := replyLang(langs)
	p.watchMu.Lock()
	sessions := make([]*watchSession, 0, len(p.watchSessions[chatID]))
	for s := range p.watchSessions[chatID] {
		sessions = append(sessions, s)
	}
	delete(p.watchSessions, chatID)
	p.watchMu.Unlock()

	if len(sessions) == 0 {
		return l.t("no active traffic watch for this chat", "本聊天没有进行中的流量监听"), nil
	}
	for _, s := range sessions {
		if s.cancel != nil {
			s.cancel()
		}
	}
	waitWatchSessions(sessions, 3*time.Second)
	for _, s := range sessions {
		if s.admin != nil {
			_ = s.admin.AdminWatchStop(context.Background(), s.sourceIP)
		}
		p.editWatchStopped(ctx, s, l)
	}
	return fmt.Sprintf(l.t("stopped %d traffic watch(es)", "已停止 %d 个流量监听"), len(sessions)), nil
}

func (p *telegramBot) editWatchStopped(ctx context.Context, s *watchSession, l lang) {
	if p.sender == nil {
		return
	}
	text := p.formatWatchText(l, s.tag, s.sourceIP, nil, true)
	if _, err := p.sender.EditMessageText(ctx, &tgbot.EditMessageTextParams{
		ChatID:    s.chatID,
		MessageID: s.messageID,
		Text:      text,
	}); err != nil {
		p.L().Warn("traffic watch stop edit failed",
			zap.String("source_ip", s.sourceIP), zap.Error(err))
	}
}

// closeWatches releases every capture without editing messages: the bot is
// shutting down and may not have a working API connection any more.
func (p *telegramBot) closeWatches() {
	p.watchMu.Lock()
	var sessions []*watchSession
	for _, set := range p.watchSessions {
		for s := range set {
			sessions = append(sessions, s)
		}
	}
	p.watchSessions = make(map[int64]map[*watchSession]struct{})
	p.watchMu.Unlock()

	for _, s := range sessions {
		if s.cancel != nil {
			s.cancel()
		}
	}
	waitWatchSessions(sessions, 3*time.Second)
	for _, s := range sessions {
		if s.admin != nil {
			_ = s.admin.AdminWatchStop(context.Background(), s.sourceIP)
		}
	}
}

// waitWatchSessions gives every cancelled loop one shared deadline instead of
// three seconds each, so /stop stays responsive when many sessions exist.
func waitWatchSessions(sessions []*watchSession, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for _, s := range sessions {
		select {
		case <-s.done:
		case <-timer.C:
			return
		}
	}
}

func (p *telegramBot) formatWatchText(l lang, tag, source string, events []fakeipadmin.TrafficEvent, stopped bool) string {
	loc := p.loc
	if loc == nil {
		loc = time.Local
	}
	var b strings.Builder
	if stopped {
		fmt.Fprintf(&b, l.t("watch stopped for %s", "已停止监听 %s"), source)
	} else {
		fmt.Fprintf(&b, l.t("watching %s via %s (latest %d flows)",
			"正在监听 %s，数据面 %s（最新 %d 条流量）"), source, tag, watchMessageLimit)
		if len(events) == 0 {
			b.WriteString("\n" + l.t("no traffic yet", "暂无流量"))
		}
	}
	for _, e := range events {
		client := e.ClientIP
		if e.ClientPort > 0 {
			client = net.JoinHostPort(client, strconv.Itoa(int(e.ClientPort)))
		}
		destination := e.DestinationIP
		if destination == "" {
			destination = e.FakeIP
		}
		if e.DestinationPort > 0 {
			destination = net.JoinHostPort(destination, strconv.Itoa(int(e.DestinationPort)))
		}
		proto := strings.ToUpper(e.Protocol)
		fmt.Fprintf(&b, "\n%s %s %s -> %s", timeutil.FormatUnix(e.Time, "15:04:05", loc), proto, client, destination)
		if e.Domain != "" {
			b.WriteString(" " + e.Domain)
		}
		if e.FakeIP != "" && e.FakeIP != e.DestinationIP {
			b.WriteString(" fake=" + e.FakeIP)
		}
		if e.Packets > 0 {
			fmt.Fprintf(&b, " pkts=%d", e.Packets)
		}
	}
	if !stopped {
		b.WriteString("\n" + l.t("send /stop to stop every watch of this chat",
			"发送 /stop 停止本聊天的全部监听"))
	}
	text := b.String()
	if len(text) > watchMessageMaxLen {
		text = text[:watchMessageMaxLen] + l.t("\n...(truncated)", "\n...(已截断)")
	}
	return text
}

func (p *telegramBot) resolveWatchFor(tag string, langs ...lang) (watchAdmin, error) {
	l := replyLang(langs)
	p.watchMu.Lock()
	if p.watchTest != nil {
		p.watchMu.Unlock()
		return p.watchTest, nil
	}
	if a, ok := p.watchCache[tag]; ok {
		p.watchMu.Unlock()
		return a, nil
	}
	p.watchMu.Unlock()

	e, ok := p.M().GetExecutables()[tag]
	if !ok {
		return nil, fmt.Errorf(l.t("plugin %q is not loaded", "插件 %q 未加载"), tag)
	}
	a, ok := e.(watchAdmin)
	if !ok {
		return nil, fmt.Errorf(l.t("plugin %q does not implement the traffic watch interface",
			"插件 %q 未实现流量监听接口"), tag)
	}
	p.watchMu.Lock()
	p.watchCache[tag] = a
	p.watchMu.Unlock()
	return a, nil
}
