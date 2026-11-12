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

// Package telegram_bot exposes fakeip_nat's mapping table and ocserv's control
// socket through a Telegram bot. It is an operator convenience, not a DNS
// step: it runs a long-polling loop in the background and only answers chats
// listed in chat_ids.
package telegram_bot

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	tgbot "github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/executable_seq"
	fakeipadmin "github.com/ersonw/mosdns-v4/pkg/fakeip_admin"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/ersonw/mosdns-v4/plugin/executable/radius"
	"go.uber.org/zap"
)

const PluginType = "telegram_bot"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*telegramBot)(nil)

// Args configures the Telegram bot and the plugins it manages.
type Args struct {
	// Token is the bot token from @BotFather. Required; without it the
	// plugin stays disabled.
	Token string `yaml:"token"`
	// ChatIDs is the allowlist of chats (administrators) the bot answers.
	// Empty disables the plugin: a message from any other chat is ignored.
	ChatIDs []int64 `yaml:"chat_ids"`
	// Admins binds each chat to a role. A chat listed here uses that role's
	// permissions; a chat listed only in chat_ids uses DefaultRole. Both lists
	// are merged, so an old config keeps working.
	Admins []AdminUser `yaml:"admins"`
	// Roles defines the named permission sets. See permissions.go for the
	// permission names; a role may inherit other roles.
	Roles map[string]Role `yaml:"roles"`
	// DefaultRole is the role of a chat listed only in ChatIDs. Default
	// "admin", the observe-and-manage role; "superadmin" holds every
	// permission.
	DefaultRole string `yaml:"default_role"`
	// FakeIPTags are the fakeip_nat plugin tags this bot may manage. The
	// first tag is the default target of /fip; another one is selected with
	// "/fip <tag> <sub>". Default ["fakeip"].
	FakeIPTags []string `yaml:"fakeip_tags"`
	// OcservTags are the ocserv_ctl plugin tags used by /vpn. The first tag
	// is the default target. Default ["ocserv"].
	OcservTags []string `yaml:"ocserv_tags"`
	// RadiusTags are the radius plugin tags used by /user. The first tag is
	// the default target. Default ["radius"].
	RadiusTags []string `yaml:"radius_tags"`
	// ConfigPath is the mosdns config file /config edits. Empty means:
	// take -c from the process arguments, else "etc/mosdns/config.yaml".
	ConfigPath string `yaml:"config_path"`
	// AuditLog is where administration actions are appended, one JSON object per
	// line. Empty means "<config dir>/telegram_bot_audit.log".
	AuditLog string `yaml:"audit_log"`
	// Proxy is an optional HTTP(S) or SOCKS5 proxy for api.telegram.org,
	// e.g. "socks5://127.0.0.1:1080".
	Proxy string `yaml:"proxy"`
	// APIBase overrides the Telegram API root, for a mirror or tests.
	// Default: https://api.telegram.org.
	APIBase string `yaml:"api_base"`
	// PollTimeout is the long-polling timeout in seconds. Default 30.
	PollTimeout int `yaml:"poll_timeout"`
}

func (a *Args) initDefault() {
	a.Token = strings.TrimSpace(a.Token)
	a.FakeIPTags = tagList(a.FakeIPTags, "fakeip")
	a.OcservTags = tagList(a.OcservTags, "ocserv")
	a.RadiusTags = tagList(a.RadiusTags, "radius")
	a.DefaultRole = strings.TrimSpace(a.DefaultRole)
	if a.DefaultRole == "" {
		// Default to the plain administrator. A config that wants the write
		// paths has to say so (default_role: superadmin or a chat role).
		a.DefaultRole = RoleAdmin
	}
	for i := range a.Admins {
		a.Admins[i].Role = strings.TrimSpace(a.Admins[i].Role)
	}
	a.ConfigPath = strings.TrimSpace(a.ConfigPath)
	a.APIBase = strings.TrimSpace(a.APIBase)
	if a.APIBase == "" {
		a.APIBase = "https://api.telegram.org"
	}
	if a.PollTimeout <= 0 {
		a.PollTimeout = 30
	}
}

func (a *Args) enabled() bool {
	return a.Token != "" && (len(a.ChatIDs) > 0 || len(a.Admins) > 0)
}

// tagList trims a configured tag list, drops duplicates, and falls back to one
// default tag so a command always has a target.
func tagList(list []string, def string) []string {
	seen := make(map[string]struct{}, len(list)+1)
	var out []string
	add := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" {
			return
		}
		if _, ok := seen[t]; ok {
			return
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	for _, t := range list {
		add(t)
	}
	if len(out) == 0 {
		add(def)
	}
	return out
}

// pickTag lets the first argument select a configured tag, otherwise falls
// back to the default (first) tag.
func pickTag(tags []string, args []string) (string, []string) {
	if len(tags) == 0 {
		return "", args
	}
	if len(args) > 0 {
		for _, t := range tags {
			if args[0] == t {
				return t, args[1:]
			}
		}
	}
	return tags[0], args
}

// mappingAdmin is the fakeip contract, resolved by tag at runtime. The bot
// never imports the fakeip plugin: any plugin implementing the interface is
// manageable.
type mappingAdmin = fakeipadmin.Admin

// ocservAdmin is the slice of ocserv_ctl this bot is allowed to use.
type ocservAdmin interface {
	AdminExec(ctx context.Context, argv []string) (string, error)
}

// ocservServiceAdmin is the systemd slice of ocserv_ctl: reload keeps sessions,
// restart drops them. Optional, so a plugin without a systemd_unit still works
// for the read-only /vpn commands.
type ocservServiceAdmin interface {
	AdminReload(ctx context.Context) (string, error)
	AdminRestart(ctx context.Context) (string, error)
}

// ocservPoolAdmin is the address-pool slice of ocserv_ctl: it reads the pool
// from ocserv.conf and pins explicit-ipv4 values in config-per-user.
type ocservPoolAdmin interface {
	AdminPool(ctx context.Context) (string, error)
	AdminAllocIP(ctx context.Context, user, ip string) (string, error)
	AdminReleaseIP(ctx context.Context, user string) (string, error)
}

// ocservEventAdmin is the up/down event ring kept by ocserv_ctl. The hook
// writes to its unix socket instead of paging an administrator.
type ocservEventAdmin interface {
	AdminEvents(limit int, user string) (string, error)
}

// execScriptAdmin is the slice of exec_script this bot is allowed to use: it
// runs the script already configured in mosdns, never an arbitrary command.
type execScriptAdmin interface {
	AdminRun(ctx context.Context, ip, domain string) (string, error)
}

type telegramBot struct {
	*coremain.BP
	args *Args
	tb   *tgbot.Bot

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	startedAt time.Time

	adminMu    sync.Mutex
	admin      mappingAdmin
	adminCache map[string]mappingAdmin
	plane      planeAdmin // set by tests; production resolves by tag

	ocservMu    sync.Mutex
	ocserv      ocservAdmin
	ocservCache map[string]ocservAdmin

	radiusMu    sync.Mutex
	radius      radius.Admin
	radiusCache map[string]radius.Admin

	access *accessTable
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	return newTelegramBot(bp, args.(*Args))
}

func newTelegramBot(bp *coremain.BP, args *Args) (coremain.Plugin, error) {
	args.initDefault()
	p := &telegramBot{
		BP:          bp,
		args:        args,
		startedAt:   time.Now(),
		adminCache:  make(map[string]mappingAdmin),
		ocservCache: make(map[string]ocservAdmin),
		radiusCache: make(map[string]radius.Admin),
	}
	if !args.enabled() {
		bp.L().Info("telegram bot disabled, token or chat_ids is empty")
		return p, nil
	}

	access, aerr := buildAccess(args)
	if aerr != nil {
		return nil, fmt.Errorf("telegram bot roles: %w", aerr)
	}
	p.access = access

	pollTimeout := time.Duration(args.PollTimeout) * time.Second
	client, err := newHTTPClient(args.Proxy, pollTimeout+10*time.Second)
	if err != nil {
		return nil, err
	}

	tb, err := tgbot.New(args.Token,
		// No getMe round trip at startup: a temporarily unreachable API must
		// not block mosdns from starting, and the poller reports it anyway.
		tgbot.WithSkipGetMe(),
		tgbot.WithServerURL(args.APIBase),
		tgbot.WithHTTPClient(pollTimeout, client),
		tgbot.WithDefaultHandler(p.onUpdate),
		tgbot.WithErrorsHandler(func(err error) {
			p.L().Warn("telegram bot error", zap.Error(err))
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("init telegram bot: %w", err)
	}
	p.tb = tb
	p.ctx, p.cancel = context.WithCancel(context.Background())

	bp.L().Info("telegram bot started",
		zap.String("api_base", args.APIBase),
		zap.Int("chats", len(access.perms)),
		zap.Int("roles", len(args.Roles)),
		zap.Strings("fakeip_tags", args.FakeIPTags),
		zap.Strings("ocserv_tags", args.OcservTags),
		zap.Int("poll_timeout", args.PollTimeout))

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.tb.Start(p.ctx)
	}()
	return p, nil
}

// Exec is a no-op: the bot is not a DNS processing step, but an executable
// plugin so it can sit anywhere in a sequence without breaking the chain.
func (p *telegramBot) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (p *telegramBot) Close() error {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
	return nil
}

func (p *telegramBot) allowed(chatID int64) bool {
	for _, id := range p.args.ChatIDs {
		if id == chatID {
			return true
		}
	}
	return false
}

// onUpdate is the library's default handler: every message lands here.
func (p *telegramBot) onUpdate(ctx context.Context, b *tgbot.Bot, update *models.Update) {
	if update == nil || update.Message == nil {
		return
	}
	chatID := update.Message.Chat.ID
	text := strings.TrimSpace(update.Message.Text)
	if text == "" {
		return
	}
	if !p.allowed(chatID) {
		p.L().Debug("telegram message ignored, chat not allowed", zap.Int64("chat_id", chatID))
		return
	}
	p.L().Debug("telegram command received", zap.Int64("chat_id", chatID), zap.String("text", text))

	reply, err := p.handleText(ctx, chatID, text)
	if err != nil {
		reply = "error: " + err.Error()
	}
	if reply == "" {
		return
	}
	// Telegram caps a message at 4096 characters.
	if len(reply) > 4000 {
		reply = reply[:4000] + "\n...(truncated)"
	}
	if _, err := b.SendMessage(ctx, &tgbot.SendMessageParams{ChatID: chatID, Text: reply}); err != nil {
		p.L().Warn("telegram sendMessage failed", zap.Error(err))
	}
}

// handleText parses one command and returns the reply text.
func (p *telegramBot) handleText(ctx context.Context, chatID int64, text string) (reply string, err error) {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return "", nil
	}
	cmd := strings.ToLower(fields[0])
	if i := strings.IndexByte(cmd, '@'); i > 0 {
		cmd = cmd[:i] // "/cmd@botname" in groups
	}

	if err := p.require(chatID, requiredPermission(cmd)); err != nil {
		return err.Error(), nil
	}

	// Every command that changes the system or the config file leaves one line
	// in the audit log, whether it succeeded or not. The detail is sanitised
	// before it is written, so no credential ends up in the file.
	if isAuditedCommand(cmd) {
		defer func() {
			detail := auditDetail(cmd, fields[1:])
			if err != nil {
				detail = strings.TrimSpace(detail + " failed: " + err.Error())
			}
			p.recordAudit(chatID, cmd, detail)
		}()
	}

	switch cmd {
	case "/start", "/help":
		return p.helpFor(chatID), nil
	case "/fip":
		return p.handleFip(ctx, fields[1:])
	case "/vpn":
		return p.handleVPN(ctx, fields[1:])
	case "/user":
		return p.handleUser(fields[1:]), nil
	case "/access":
		return p.handleAccess(ctx, chatID, fields[1:])
	case "/status":
		return p.handleStatus(ctx)
	case "/plugins":
		return p.handlePlugins(), nil
	case "/plugin":
		if len(fields) < 2 {
			return "usage: /plugin <tag>", nil
		}
		return p.handlePlugin(fields[1])
	case "/config":
		return p.handleConfig(fields[1:])
	case "/reload":
		return p.handleReload(fields[1:])
	case "/exec":
		return p.handleExec(ctx, fields[1:])
	case "/net":
		return p.handleNet(ctx, fields[1:])
	case "/ledger":
		return p.handleLedger(ctx, fields[1:])
	case "/sweep":
		return p.handleSweep(ctx, fields[1:])
	case "/diag":
		return p.handleDiag(ctx, fields[1:])
	case "/proxy":
		return p.handleProxy(ctx, fields[1:])
	case "/audit":
		return p.handleAudit(fields[1:])
	case "/perm", "/whoami":
		return p.handlePerm(chatID), nil
	// Short forms kept for muscle memory; they are aliases of /fip <sub>.
	case "/list", "/stats", "/lookup", "/rev", "/del", "/clear":
		sub := strings.TrimPrefix(cmd, "/")
		if sub == "lookup" || sub == "rev" {
			sub = "get"
		}
		return p.handleFip(ctx, append([]string{sub}, fields[1:]...))
	}

	return "unknown command, send /help", nil
}

// handleExec runs the script already bound to one exec_script plugin. The bot
// never passes an arbitrary shell command, only ip and domain arguments.
func (p *telegramBot) handleExec(ctx context.Context, args []string) (string, error) {
	if len(args) < 3 {
		return "usage: /exec <tag> <ip> <domain>", nil
	}
	tag := args[0]
	e, ok := p.M().GetExecutables()[tag]
	if !ok {
		return fmt.Sprintf("%s: not loaded", tag), nil
	}
	runner, ok := e.(execScriptAdmin)
	if !ok {
		return fmt.Sprintf("%s: not an exec_script plugin", tag), nil
	}

	out, err := runner.AdminRun(ctx, args[1], args[2])
	if err != nil {
		return "", fmt.Errorf("%s %s %s: %w", tag, args[1], args[2], err)
	}
	reply := fmt.Sprintf("exec %s %s %s", tag, args[1], args[2])
	if strings.TrimSpace(out) != "" {
		reply += "\n" + strings.TrimSpace(out)
	}
	return reply, nil
}

func (p *telegramBot) handleFip(ctx context.Context, args []string) (string, error) {
	tag, args := pickTag(p.args.FakeIPTags, args)
	if len(args) == 0 {
		return fipHelp, nil
	}

	switch strings.ToLower(args[0]) {
	case "tags":
		return p.tagSummary("fakeip", p.args.FakeIPTags), nil
	case "help":
		return fipHelp, nil
	}

	admin, err := p.resolveAdminFor(tag)
	if err != nil {
		return "", err
	}

	switch strings.ToLower(args[0]) {
	case "stats":
		s, err := admin.AdminStats(ctx)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("mappings: %d\npending: %d\nreal_ips: %d\nruntime: %d",
			s.Mappings, s.Pending, s.RealIPs, s.Runtime), nil

	case "list":
		limit := 20
		if len(args) > 1 {
			if n, err := strconv.Atoi(args[1]); err == nil && n > 0 {
				limit = n
			}
		}
		entries, err := admin.AdminListMappings(ctx, limit)
		if err != nil {
			return "", err
		}
		if len(entries) == 0 {
			return "no mappings yet", nil
		}
		var b strings.Builder
		fmt.Fprintf(&b, "recent %d mapping(s):", len(entries))
		for _, e := range entries {
			fmt.Fprintf(&b, "\n%s -> %s (%s)", e.Domain, e.FakeIP, formatTime(e.CreatedAt))
		}
		return b.String(), nil

	case "get":
		if len(args) < 2 {
			return "usage: /fip get <domain|fake_ip>", nil
		}
		key := args[1]
		e, ok, err := admin.AdminLookupDomain(ctx, key)
		if err != nil {
			return "", err
		}
		if !ok {
			e, ok, err = admin.AdminLookupFakeIP(ctx, key)
			if err != nil {
				return "", err
			}
		}
		if !ok {
			return fmt.Sprintf("%s: no mapping", key), nil
		}
		return fmt.Sprintf("%s -> %s (%s)", e.Domain, e.FakeIP, formatTime(e.CreatedAt)), nil

	case "add", "set":
		if len(args) < 3 {
			return "usage: /fip add <domain> <fake_ip>", nil
		}
		if err := admin.AdminPutMapping(ctx, args[1], args[2]); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s -> %s saved", args[1], args[2]), nil

	case "del":
		if len(args) < 2 {
			return "usage: /fip del <domain>", nil
		}
		ok, err := admin.AdminDeleteDomain(ctx, args[1])
		if err != nil {
			return "", err
		}
		if !ok {
			return fmt.Sprintf("%s: no mapping", args[1]), nil
		}
		return fmt.Sprintf("deleted %s, the next query allocates a new fake ip", args[1]), nil

	case "clear":
		if len(args) < 2 || strings.ToLower(args[1]) != "confirm" {
			return "send /fip clear confirm to drop every mapping", nil
		}
		n, err := admin.AdminClearMappings(ctx)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("deleted %d mapping(s)", n), nil
	}

	return "unknown subcommand, send /fip help", nil
}

// handleStatus summarises the process and the managed plugins.
func (p *telegramBot) handleStatus(ctx context.Context) (string, error) {
	ex := p.M().GetExecutables()
	var fakeipCount, ocservCount int
	for _, e := range ex {
		if _, ok := e.(mappingAdmin); ok {
			fakeipCount++
		}
		if _, ok := e.(ocservAdmin); ok {
			ocservCount++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "uptime: %s", time.Since(p.startedAt).Round(time.Second))
	fmt.Fprintf(&b, "\nloaded plugins: %d", len(ex))
	fmt.Fprintf(&b, "\nfakeip-capable: %d", fakeipCount)
	fmt.Fprintf(&b, "\nocserv-capable: %d", ocservCount)
	fmt.Fprintf(&b, "\nfakeip_tags: %s", strings.Join(p.args.FakeIPTags, ", "))
	fmt.Fprintf(&b, "\nocserv_tags: %s", strings.Join(p.args.OcservTags, ", "))
	return b.String(), nil
}

// handlePlugins lists every loaded plugin and the capabilities the bot sees
// on it, which is how a tag is chosen for the commands above.
func (p *telegramBot) handlePlugins() string {
	ex := p.M().GetExecutables()
	tags := make([]string, 0, len(ex))
	for tag := range ex {
		tags = append(tags, tag)
	}
	sort.Strings(tags)

	var b strings.Builder
	fmt.Fprintf(&b, "loaded plugins: %d", len(tags))
	for _, tag := range tags {
		var caps string
		if _, ok := ex[tag].(mappingAdmin); ok {
			caps += " fakeip"
		}
		if _, ok := ex[tag].(ocservAdmin); ok {
			caps += " ocserv"
		}
		fmt.Fprintf(&b, "\n%s %T%s", tag, ex[tag], caps)
	}
	return b.String()
}

func (p *telegramBot) handleVPN(ctx context.Context, args []string) (string, error) {
	tag, args := pickTag(p.args.OcservTags, args)
	if len(args) == 0 {
		return vpnHelp, nil
	}
	switch strings.ToLower(args[0]) {
	case "tags":
		return p.tagSummary("ocserv", p.args.OcservTags), nil
	case "help":
		return vpnHelp, nil
	}

	admin, err := p.resolveOcservFor(tag)
	if err != nil {
		return "", err
	}

	switch strings.ToLower(args[0]) {
	case "reload":
		svc, ok := admin.(ocservServiceAdmin)
		if !ok {
			return "", fmt.Errorf("ocserv_ctl tag %q does not expose systemd control", tag)
		}
		return svc.AdminReload(ctx)
	case "restart":
		svc, ok := admin.(ocservServiceAdmin)
		if !ok {
			return "", fmt.Errorf("ocserv_ctl tag %q does not expose systemd control", tag)
		}
		return svc.AdminRestart(ctx)
	case "pool":
		pool, ok := admin.(ocservPoolAdmin)
		if !ok {
			return "", fmt.Errorf("ocserv_ctl tag %q does not expose address allocation", tag)
		}
		return pool.AdminPool(ctx)
	case "alloc":
		if len(args) < 2 {
			return "usage: /vpn alloc <user> [ip]", nil
		}
		pool, ok := admin.(ocservPoolAdmin)
		if !ok {
			return "", fmt.Errorf("ocserv_ctl tag %q does not expose address allocation", tag)
		}
		ip := ""
		if len(args) > 2 {
			ip = args[2]
		}
		return pool.AdminAllocIP(ctx, args[1], ip)
	case "events":
		ev, ok := admin.(ocservEventAdmin)
		if !ok {
			return "", fmt.Errorf("ocserv_ctl tag %q does not expose updown events", tag)
		}
		limit, user := 0, ""
		if len(args) > 1 {
			if n, err := strconv.Atoi(args[1]); err == nil {
				limit = n
			} else {
				user = args[1]
			}
		}
		if len(args) > 2 && user == "" {
			user = args[2]
		}
		return ev.AdminEvents(limit, user)
	case "free":
		if len(args) < 2 {
			return "usage: /vpn free <user>", nil
		}
		pool, ok := admin.(ocservPoolAdmin)
		if !ok {
			return "", fmt.Errorf("ocserv_ctl tag %q does not expose address allocation", tag)
		}
		return pool.AdminReleaseIP(ctx, args[1])
	}

	var argv []string
	switch strings.ToLower(args[0]) {
	case "users":
		argv = []string{"show", "users"}
	case "status":
		argv = []string{"show", "status"}
	case "sessions":
		argv = []string{"show", "sessions", "valid"}
	case "kick":
		if len(args) < 2 {
			return "usage: /vpn kick <user>", nil
		}
		argv = []string{"disconnect", "user", args[1]}
	case "term":
		if len(args) < 2 {
			return "usage: /vpn term <user>", nil
		}
		argv = []string{"terminate", "user", args[1]}
	case "run":
		// Full escape hatch for the remaining occtl commands.
		if len(args) < 2 {
			return "usage: /vpn run <occtl args...>", nil
		}
		argv = args[1:]
	default:
		return "unknown subcommand, send /vpn help", nil
	}

	out, err := admin.AdminExec(ctx, argv)
	out = strings.TrimSpace(out)
	if err != nil {
		if out != "" {
			return "occtl failed: " + err.Error() + "\n" + out, nil
		}
		return "", err
	}
	if out == "" {
		out = "ok, no output"
	}
	return out, nil
}

// resolveAdminFor finds a fakeip plugin by tag. Lookup is lazy because plugins
// are initialised in configuration order, and cached per tag.
func (p *telegramBot) resolveAdminFor(tag string) (mappingAdmin, error) {
	p.adminMu.Lock()
	defer p.adminMu.Unlock()
	if p.admin != nil {
		return p.admin, nil // injected by a test
	}
	if a, ok := p.adminCache[tag]; ok {
		return a, nil
	}

	e, ok := p.M().GetExecutables()[tag]
	if !ok {
		return nil, fmt.Errorf("plugin %q is not loaded", tag)
	}
	a, ok := e.(mappingAdmin)
	if !ok {
		return nil, fmt.Errorf("plugin %q does not implement the fakeip admin interface", tag)
	}
	p.adminCache[tag] = a
	return a, nil
}

// resolveOcservFor finds the ocserv_ctl plugin that owns the occtl call.
func (p *telegramBot) resolveOcservFor(tag string) (ocservAdmin, error) {
	p.ocservMu.Lock()
	defer p.ocservMu.Unlock()
	if p.ocserv != nil {
		return p.ocserv, nil // injected by a test
	}
	if a, ok := p.ocservCache[tag]; ok {
		return a, nil
	}

	e, ok := p.M().GetExecutables()[tag]
	if !ok {
		return nil, fmt.Errorf("plugin %q is not loaded", tag)
	}
	a, ok := e.(ocservAdmin)
	if !ok {
		return nil, fmt.Errorf("plugin %q does not implement the ocserv admin interface", tag)
	}
	p.ocservCache[tag] = a
	return a, nil
}

// tagSummary says which configured tags are actually loaded.
func (p *telegramBot) tagSummary(kind string, tags []string) string {
	ex := p.M().GetExecutables()
	var b strings.Builder
	fmt.Fprintf(&b, "%s targets:", kind)
	for _, t := range tags {
		state := "loaded"
		if _, ok := ex[t]; !ok {
			state = "missing"
		}
		fmt.Fprintf(&b, "\n%s (%s)", t, state)
	}
	return b.String()
}

func formatTime(unix int64) string {
	if unix <= 0 {
		return "-"
	}
	return time.Unix(unix, 0).Format("2006-01-02 15:04")
}

// helpGroup / helpItem describe /help in a form that can be filtered per
// chat: a command only makes sense to print when the caller may actually run
// it, otherwise the reply is a list of things that answer "permission denied".
type helpItem struct {
	line string
	perm string
}

type helpGroup struct {
	title string
	items []helpItem
}

var helpGroups = []helpGroup{
	{title: "fakeip mappings", items: []helpItem{
		{"/fip [tag] list [n]          recent mappings (default 20)", PermFakeIP},
		{"/fip get <domain|fake_ip>    look up one mapping", PermFakeIP},
		{"/fip add <domain> <fake_ip>  create or replace a mapping", PermFakeIP},
		{"/fip del <domain>            drop a mapping", PermFakeIP},
		{"/fip stats                   mapping counters", PermFakeIP},
		{"/fip clear confirm           drop every mapping", PermFakeIP},
	}},
	{title: "ocserv", items: []helpItem{
		{"/vpn users                   connected ocserv users", PermOcserv},
		{"/vpn status                  ocserv status", PermOcserv},
		{"/vpn sessions                valid sessions", PermOcserv},
		{"/vpn kick <user>             disconnect one user", PermOcserv},
		{"/vpn term <user>             terminate one user", PermOcserv},
		{"/vpn run <occtl args...>     any other occtl command", PermOcserv},
	}},
	{title: "radius accounts", items: []helpItem{
		{"/user list                   radius accounts with group and state", PermRadius},
		{"/user add <name> <pass> [g]  create a radius account", PermRadius},
		{"/user del <name>             delete a radius account", PermRadius},
		{"/user pass <name> <pass>     replace a password", PermRadius},
		{"/user enable|disable <name>  toggle authentication", PermRadius},
		{"/user sessions [active] [n]  accounting sessions", PermRadius},
	}},
	{title: "access records", items: []helpItem{
		{"/access <user> [days]        export that user's visit records as xlsx (default 7 days)", PermAccess},
		{"/access <ip> [days]          export one client address directly", PermAccess},
	}},
	{title: "data plane", items: []helpItem{
		{"/net [tag]                   data plane: device, proxy, mark, rules, routes", PermStatus},
		{"/ledger [tag]                recorded objects a later run would clean", PermStatus},
		{"/diag <domain> [tag]         mapping, real ips and outlet for one domain", PermFakeIP},
		{"/sweep [tag] confirm         drop recorded objects this config does not own", PermConfig},
	}},
	{title: "process", items: []helpItem{
		{"/status                      process and plugin summary", PermStatus},
		{"/plugins                     loaded plugins and their capabilities", PermStatus},
		{"/plugin <tag>                one plugin: type, capabilities, config args", PermStatus},
		{"/audit [n]                   last administration actions", PermStatus},
	}},
	{title: "config", items: []helpItem{
		{"/config                      config file summary", PermConfig},
		{"/config show <section>       dump log/data_providers/plugins/servers", PermConfig},
		{"/config get <key.path>       read a value, e.g. plugins[1].tag", PermConfig},
		{"/config set <key.path> <v>   write a value (backup taken)", PermConfig},
		{"/config add <section> <yaml> append a block; flow yaml, e.g.", PermConfig},
		{"                             /config add plugins {tag: x, type: sequence}", PermConfig},
		{"/config del <section> <k>    drop by tag, index or log key", PermConfig},
		{"/config validate             check required fields before reload", PermConfig},
		{"/proxy [tag]                 proxy state of the fakeip plugin", PermConfig},
		{"/proxy on <url>|off          write the proxy, then /reload confirm", PermConfig},
		{"/exec <tag> <ip> <domain>    run one configured exec_script plugin", PermExecScript},
		{"/reload confirm              validate config and stop, so a supervisor restarts", PermReload},
	}},
}

// helpFor builds the reply for one chat: only the commands that chat may run,
// with an empty group omitted entirely.
func (p *telegramBot) helpFor(chatID int64) string {
	var b strings.Builder
	b.WriteString("mosdns admin bot")
	if p.access != nil {
		if role, ok := p.access.roles[chatID]; ok {
			b.WriteString(" (role: " + role + ")")
		}
	}
	b.WriteString("\n")
	for _, group := range helpGroups {
		var visible []string
		for _, item := range group.items {
			if p.mayRun(chatID, item.perm) {
				visible = append(visible, item.line)
			}
		}
		if len(visible) == 0 {
			continue
		}
		b.WriteString("\n" + group.title + "\n")
		for _, line := range visible {
			b.WriteString(line + "\n")
		}
	}
	b.WriteString("\n/perm                        your role and permissions\n/help                        this message")
	return b.String()
}

// mayRun reports whether the chat holds a permission. An unconfigured
// permission table means the bot is disabled, and the help is not filtered.
func (p *telegramBot) mayRun(chatID int64, perm string) bool {
	if p.access == nil || perm == "" {
		return true
	}
	return p.access.allowed(chatID, perm)
}

const fipHelp = `fakeip commands (optional tag first, e.g. /fip fakeip2 list)
/fip tags                    configured targets
/fip list [n]                recent mappings
/fip get <domain|fake_ip>    look up one mapping
/fip add <domain> <fake_ip>  create or replace a mapping
/fip del <domain>            drop a mapping
/fip stats                   mapping counters
/fip clear confirm           drop every mapping`

const vpnHelp = `ocserv commands (occtl; optional tag first, e.g. /vpn ocserv2 users)
/vpn tags                    configured targets
/vpn users                   connected users
/vpn status                  server status
/vpn sessions                valid sessions
/vpn kick <user>             disconnect one user
/vpn term <user>             terminate one user
/vpn run <occtl args...>     any other occtl command, e.g.
                             /vpn run show iroutes
                             /vpn run unban ip 10.0.0.5
/vpn pool                    lease range parsed from ocserv.conf
/vpn alloc <user> [ip]       pin a fixed IP in config-per-user
/vpn free <user>             drop that fixed IP
/vpn reload                  systemctl reload ocserv (keeps sessions)
/vpn restart                 systemctl restart ocserv (drops sessions)
/vpn events [n] [user]       recent connect/disconnect events from the updown hook`
