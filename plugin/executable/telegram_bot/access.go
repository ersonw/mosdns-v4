package telegram_bot

// /access: turn the per-client visit log kept by fakeip_nat into a spreadsheet
// for one RADIUS user. The chain is: user name -> accounting sessions -> the
// addresses that user used -> the rows fakeip recorded for those addresses ->
// one xlsx sent back to the administrator who asked.
//
// The export deliberately goes through the data plane's Admin interface, so the
// bot never reads the SQLite file itself: whatever the plugin recorded is what
// the administrator gets.

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ersonw/mosdns-v4/plugin/executable/radius"
	tgbot "github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"go.uber.org/zap"
)

const accessHelp = `usage:
/access <user> [days]   export that RADIUS user's visit records (default 7 days, max 365)
/access <ip> [days]     export the records of one client address directly
The result is sent to this chat as an .xlsx file.`

// accessRecordRow is one exported line, already resolved to text so the sheet
// writer only deals with values.
type accessRecordRow struct {
	clientIP string
	domain   string
	realIP   string
	fakeIP   string
	hits     int
	first    int64
	last     int64
}

func (p *telegramBot) handleAccess(ctx context.Context, chatID int64, args []string) (string, error) {
	tag, rest := pickTag(p.args.RadiusTags, args)
	if len(rest) == 0 || rest[0] == "help" {
		return accessHelp, nil
	}
	target := rest[0]
	days := 7
	if len(rest) > 1 {
		if n, err := strconv.Atoi(rest[1]); err == nil && n > 0 {
			days = n
		}
	}
	if days > 365 {
		days = 365
	}

	// A bare address is accepted so an administrator can look up a machine that
	// never authenticated through RADIUS (a router, a phone, a test host).
	var addresses []string
	if addr, err := netip.ParseAddr(target); err == nil {
		addresses = []string{addr.Unmap().String()}
	} else {
		rad, err := p.resolveRadiusFor(tag)
		if err != nil {
			return "", err
		}
		users, err := rad.Users()
		if err != nil {
			return "", fmt.Errorf("read radius users: %w", err)
		}
		fixed := fixedIPOfUser(users, target)
		sessions, err := rad.Sessions(false, 5000)
		if err != nil {
			return "", fmt.Errorf("read radius sessions: %w", err)
		}
		addresses = addressesOfUser(sessions, fixed, target)
		if len(addresses) == 0 {
			return fmt.Sprintf("no fixed IP or accounting session with an address for user %q; use /access <ip> if the address is known", target), nil
		}
	}

	since := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	rows, tags, err := p.collectAccessRows(ctx, addresses, since)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return fmt.Sprintf("no visit records for %s in the last %d days", strings.Join(addresses, ", "), days), nil
	}

	cells := [][]interface{}{
		{"client_ip", "domain", "real_ip", "fake_ip", "hits", "first_seen", "last_seen"},
	}
	for _, r := range rows {
		cells = append(cells, []interface{}{
			r.clientIP, r.domain, r.realIP, r.fakeIP, r.hits,
			formatUnix(r.first), formatUnix(r.last),
		})
	}

	data, err := writeXLSX("access", cells)
	if err != nil {
		return "", fmt.Errorf("build xlsx: %w", err)
	}

	filename := fmt.Sprintf("access-%s-%s.xlsx", safeFilePart(target), time.Now().Format("20060102"))
	caption := fmt.Sprintf("access records: %s\naddresses: %s\nrows: %d\ntags: %s\nwindow: last %d days",
		target, strings.Join(addresses, ", "), len(rows), strings.Join(tags, ", "), days)

	if p.tb == nil {
		return "", fmt.Errorf("telegram client is not running")
	}
	if _, err := p.tb.SendDocument(ctx, &tgbot.SendDocumentParams{
		ChatID:   chatID,
		Document: &models.InputFileUpload{Filename: filename, Data: bytes.NewReader(data)},
		Caption:  caption,
	}); err != nil {
		return "", fmt.Errorf("send document: %w", err)
	}
	p.L().Info("telegram access export sent",
		zap.Int64("chat_id", chatID), zap.String("target", target),
		zap.Int("rows", len(rows)), zap.Strings("addresses", addresses))

	// The document already carries the summary; an empty reply stops the
	// handler from sending a second message.
	return "", nil
}

// fixedIPOfUser returns the fixed tunnel address radius assigned to one
// account, or "" when the account has none.
func fixedIPOfUser(users []radius.User, user string) string {
	for _, u := range users {
		if strings.EqualFold(strings.TrimSpace(u.Name), user) {
			return strings.TrimSpace(u.IP)
		}
	}
	return ""
}

// addressesOfUser collects the distinct addresses that may appear as the
// source of a DNS query for one account: the fixed VPN IP first, then the
// public addresses RADIUS saw in accounting sessions.
func addressesOfUser(sessions []radius.Session, fixed string, user string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(ip string) {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			return
		}
		if _, ok := seen[ip]; ok {
			return
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	add(fixed)
	for _, s := range sessions {
		if !strings.EqualFold(strings.TrimSpace(s.Name), user) {
			continue
		}
		add(s.RemoteIP)
	}
	return out
}

// collectAccessRows asks every configured fakeip plugin for its rows of these
// addresses, then merges them newest first.
func (p *telegramBot) collectAccessRows(ctx context.Context, addresses []string, since int64) ([]accessRecordRow, []string, error) {
	var rows []accessRecordRow
	var tags []string

	for _, tag := range p.args.FakeIPTags {
		admin, err := p.resolveAdminFor(tag)
		if err != nil {
			p.L().Warn("access export: fakeip tag unavailable",
				zap.String("tag", tag), zap.Error(err))
			continue
		}
		records, err := admin.AdminAccessRecords(ctx, addresses, since, 2000)
		if err != nil {
			return nil, tags, fmt.Errorf("%s: %w", tag, err)
		}
		if len(records) == 0 {
			continue
		}
		tags = append(tags, tag)
		for _, r := range records {
			rows = append(rows, accessRecordRow{
				clientIP: r.ClientIP, domain: r.Domain, realIP: r.RealIP,
				fakeIP: r.FakeIP, hits: r.Hits, first: r.FirstSeen, last: r.LastSeen,
			})
		}
	}

	sort.SliceStable(rows, func(i, j int) bool { return rows[i].last > rows[j].last })
	return rows, tags, nil
}

func formatUnix(ts int64) string {
	if ts <= 0 {
		return ""
	}
	return time.Unix(ts, 0).Format("2006-01-02 15:04:05")
}

// safeFilePart keeps a user name or address from breaking the file name.
func safeFilePart(s string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_", " ", "_")
	return r.Replace(s)
}
