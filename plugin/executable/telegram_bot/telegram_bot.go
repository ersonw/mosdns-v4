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
	"path/filepath"
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
	"github.com/ersonw/mosdns-v4/pkg/helperscript"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"github.com/ersonw/mosdns-v4/pkg/timeutil"
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
	// DomainManageScript edits a plain-text domain provider. It must accept
	// "add|del [file_path] domain..." (and "clear" is not used here).
	// Default: <config dir>/scripts/domain_manage.py; a missing script is
	// downloaded there from the project's raw GitHub mirror.
	DomainManageScript string `yaml:"domain_manage_script"`
	// Txt2DatScript regenerates a v2dat geosite file. It must accept
	// "<input_txt> <output_dat> <category> [--overwrite]".
	// Default: <config dir>/scripts/txt2dat.py; a missing script is downloaded.
	Txt2DatScript string `yaml:"txt2dat_script"`
	// DomainPython runs *.py domain scripts. Default "python3". A non-.py
	// script is executed directly, so a custom helper can use its own shebang.
	DomainPython string `yaml:"domain_python"`
	// DomainTimeout is the maximum run time of one domain script, in seconds.
	// Default 30.
	DomainTimeout int `yaml:"domain_timeout"`
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
	// Timezone overrides how stored Unix timestamps are rendered. Empty uses
	// the data source plugin's timezone, then Asia/Shanghai.
	Timezone string `yaml:"timezone"`

	timezoneSet bool
	loc         *time.Location
}

func (a *Args) initDefault() error {
	a.Token = strings.TrimSpace(a.Token)
	a.timezoneSet = strings.TrimSpace(a.Timezone) != ""
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
	a.DomainManageScript = strings.TrimSpace(a.DomainManageScript)
	a.Txt2DatScript = strings.TrimSpace(a.Txt2DatScript)
	a.DomainPython = strings.TrimSpace(a.DomainPython)
	if a.DomainPython == "" {
		a.DomainPython = "python3"
	}
	if a.DomainTimeout <= 0 {
		a.DomainTimeout = 30
	}
	a.APIBase = strings.TrimSpace(a.APIBase)
	if a.APIBase == "" {
		a.APIBase = "https://api.telegram.org"
	}
	if a.PollTimeout <= 0 {
		a.PollTimeout = 30
	}
	loc, err := timeutil.Load(a.Timezone)
	if err != nil {
		return err
	}
	a.loc = loc
	return nil
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

// watchAdmin is the optional live traffic capability of a fakeip plugin.
type watchAdmin = fakeipadmin.WatchAdmin

// telegramSender is the small part of the Telegram client the watch uses. A
// test can substitute it without a live bot token.
type telegramSender interface {
	SendMessage(ctx context.Context, params *tgbot.SendMessageParams) (*models.Message, error)
	EditMessageText(ctx context.Context, params *tgbot.EditMessageTextParams) (*models.Message, error)
}

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
	args   *Args
	tb     *tgbot.Bot
	sender telegramSender

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	startedAt time.Time

	adminMu    sync.Mutex
	admin      mappingAdmin
	adminCache map[string]mappingAdmin
	plane      planeAdmin // set by tests; production resolves by tag

	watchMu       sync.Mutex
	watchTest     watchAdmin // set by tests; production resolves by tag
	watchCache    map[string]watchAdmin
	watchSessions map[int64]map[*watchSession]struct{}

	ocservMu    sync.Mutex
	ocserv      ocservAdmin
	ocservCache map[string]ocservAdmin

	radiusMu    sync.Mutex
	radius      radius.Admin
	radiusCache map[string]radius.Admin

	domainMu     sync.Mutex
	domainRunner func(ctx context.Context, script string, args ...string) (string, error)

	access *accessTable
	loc    *time.Location
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	return newTelegramBot(bp, args.(*Args))
}

func newTelegramBot(bp *coremain.BP, args *Args) (coremain.Plugin, error) {
	if err := args.initDefault(); err != nil {
		return nil, err
	}
	p := &telegramBot{
		BP:            bp,
		args:          args,
		startedAt:     time.Now(),
		adminCache:    make(map[string]mappingAdmin),
		ocservCache:   make(map[string]ocservAdmin),
		radiusCache:   make(map[string]radius.Admin),
		watchCache:    make(map[string]watchAdmin),
		watchSessions: make(map[int64]map[*watchSession]struct{}),
		loc:           args.loc,
	}
	if !args.enabled() {
		bp.L().Info("telegram bot disabled, token or chat_ids is empty")
		return p, nil
	}

	configDir := filepath.Dir(p.configPath())
	scriptCtx, scriptCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer scriptCancel()
	resolve := func(name, configured string) string {
		path := helperscript.ConfiguredPath(configDir, configured, name)
		resolved, downloaded, err := helperscript.Resolve(scriptCtx, configDir, configured, name)
		if err != nil {
			p.L().Warn("telegram bot: resolving helper script failed",
				zap.String("script", name), zap.String("path", path), zap.Error(err))
			return path
		}
		if downloaded {
			p.L().Info("telegram bot: downloaded helper script",
				zap.String("script", name), zap.String("path", resolved))
		}
		return resolved
	}
	args.DomainManageScript = resolve("domain_manage.py", args.DomainManageScript)
	args.Txt2DatScript = resolve("txt2dat.py", args.Txt2DatScript)

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
	p.sender = tb
	p.ctx, p.cancel = context.WithCancel(context.Background())

	bp.L().Info("telegram bot started",
		zap.String("api_base", args.APIBase),
		zap.Int("chats", len(access.perms)),
		zap.Int("roles", len(args.Roles)),
		zap.Strings("fakeip_tags", args.FakeIPTags),
		zap.Strings("ocserv_tags", args.OcservTags),
		zap.Int("poll_timeout", args.PollTimeout),
		zap.String("timezone", args.loc.String()))

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
	p.closeWatches()
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

	code := ""
	if update.Message.From != nil {
		code = update.Message.From.LanguageCode
	}
	l := detectLang(code, text)

	reply, err := p.handleText(ctx, chatID, text, l)
	if err != nil {
		reply = l.t("error: ", "错误：") + err.Error()
	}
	if reply == "" {
		return
	}
	// Telegram caps a message at 4096 characters.
	if len(reply) > 4000 {
		reply = reply[:4000] + l.t("\n...(truncated)", "\n...(已截断)")
	}
	if _, err := b.SendMessage(ctx, &tgbot.SendMessageParams{ChatID: chatID, Text: reply}); err != nil {
		p.L().Warn("telegram sendMessage failed", zap.Error(err))
	}
}

// handleText parses one command and returns the reply text.
func (p *telegramBot) handleText(ctx context.Context, chatID int64, text string, langs ...lang) (reply string, err error) {
	l := replyLang(langs)
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return "", nil
	}
	cmd := strings.ToLower(fields[0])
	if i := strings.IndexByte(cmd, '@'); i > 0 {
		cmd = cmd[:i] // "/cmd@botname" in groups
	}

	if err := p.require(chatID, requiredPermission(cmd), l); err != nil {
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
		return p.helpFor(chatID, l), nil
	case "/fip":
		return p.handleFip(ctx, fields[1:], l)
	case "/vpn":
		return p.handleVPN(ctx, fields[1:], l)
	case "/user":
		return p.handleUser(fields[1:], l), nil
	case "/access":
		return p.handleAccess(ctx, chatID, fields[1:], l)
	case "/status":
		return p.handleStatus(ctx, l)
	case "/plugins":
		return p.handlePlugins(l), nil
	case "/plugin":
		if len(fields) < 2 {
			return l.t("usage: /plugin <tag>", "用法：/plugin <tag>"), nil
		}
		return p.handlePlugin(fields[1], l)
	case "/config":
		return p.handleConfig(fields[1:], l)
	case "/provider":
		return p.handleProvider(ctx, fields[1:], l)
	case "/watch":
		return p.handleWatch(ctx, chatID, fields[1:], l)
	case "/stop":
		return p.handleStop(ctx, chatID, l)
	case "/reload":
		return p.handleReload(fields[1:], l)
	case "/exec":
		return p.handleExec(ctx, fields[1:], l)
	case "/net":
		return p.handleNet(ctx, fields[1:], l)
	case "/ledger":
		return p.handleLedger(ctx, fields[1:], l)
	case "/sweep":
		return p.handleSweep(ctx, fields[1:], l)
	case "/diag":
		return p.handleDiag(ctx, fields[1:], l)
	case "/proxy":
		return p.handleProxy(ctx, fields[1:], l)
	case "/audit":
		return p.handleAudit(fields[1:], l)
	case "/perm", "/whoami":
		return p.handlePerm(chatID, l), nil
	// Short forms kept for muscle memory; they are aliases of /fip <sub>.
	case "/list", "/stats", "/lookup", "/rev", "/del", "/clear":
		sub := strings.TrimPrefix(cmd, "/")
		if sub == "lookup" || sub == "rev" {
			sub = "get"
		}
		return p.handleFip(ctx, append([]string{sub}, fields[1:]...), l)
	}

	return l.t("unknown command, send /help", "未知命令，请发送 /help"), nil
}

// handleExec runs the script already bound to one exec_script plugin. The bot
// never passes an arbitrary shell command, only ip and domain arguments.
func (p *telegramBot) handleExec(ctx context.Context, args []string, langs ...lang) (string, error) {
	l := replyLang(langs)
	if len(args) < 3 {
		return l.t("usage: /exec <tag> <ip> <domain>", "用法：/exec <tag> <ip> <domain>"), nil
	}
	tag := args[0]
	e, ok := p.M().GetExecutables()[tag]
	if !ok {
		return l.t(fmt.Sprintf("%s: not loaded", tag), fmt.Sprintf("%s：未加载", tag)), nil
	}
	runner, ok := e.(execScriptAdmin)
	if !ok {
		return l.t(fmt.Sprintf("%s: not an exec_script plugin", tag), fmt.Sprintf("%s：不是 exec_script 插件", tag)), nil
	}

	out, err := runner.AdminRun(ctx, args[1], args[2])
	if err != nil {
		return "", fmt.Errorf("%s %s %s: %w", tag, args[1], args[2], err)
	}
	reply := l.t(fmt.Sprintf("exec %s %s %s", tag, args[1], args[2]),
		fmt.Sprintf("执行 %s %s %s", tag, args[1], args[2]))
	if strings.TrimSpace(out) != "" {
		reply += "\n" + strings.TrimSpace(out)
	}
	return reply, nil
}

func (p *telegramBot) handleFip(ctx context.Context, args []string, langs ...lang) (string, error) {
	l := replyLang(langs)
	tag, args := pickTag(p.args.FakeIPTags, args)
	if len(args) == 0 {
		return fipHelpText(l), nil
	}

	switch strings.ToLower(args[0]) {
	case "tags":
		return p.tagSummary("fakeip", p.args.FakeIPTags, l), nil
	case "help":
		return fipHelpText(l), nil
	}

	admin, err := p.resolveAdminFor(tag, l)
	if err != nil {
		return "", err
	}
	loc := p.locationFor(admin)

	switch strings.ToLower(args[0]) {
	case "stats":
		s, err := admin.AdminStats(ctx)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf(l.t("mappings: %d\npending: %d\nreal_ips: %d\nruntime: %d",
			"映射：%d\n待处理：%d\n真实 IP：%d\n运行时：%d"),
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
			return l.t("no mappings yet", "暂无映射"), nil
		}
		var b strings.Builder
		fmt.Fprintf(&b, l.t("recent %d mapping(s):", "最近 %d 条映射："), len(entries))
		for _, e := range entries {
			fmt.Fprintf(&b, "\n%s -> %s (%s)", e.Domain, e.FakeIP, formatTime(e.CreatedAt, loc))
		}
		return b.String(), nil

	case "get":
		if len(args) < 2 {
			return l.t("usage: /fip get <domain|fake_ip>", "用法：/fip get <domain|fake_ip>"), nil
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
			return l.t(fmt.Sprintf("%s: no mapping", key), fmt.Sprintf("%s：无映射", key)), nil
		}
		return fmt.Sprintf("%s -> %s (%s)", e.Domain, e.FakeIP, formatTime(e.CreatedAt, loc)), nil

	case "add", "set":
		if len(args) < 3 {
			return l.t("usage: /fip add <domain> <fake_ip>", "用法：/fip add <domain> <fake_ip>"), nil
		}
		if err := admin.AdminPutMapping(ctx, args[1], args[2]); err != nil {
			return "", err
		}
		return l.t(fmt.Sprintf("%s -> %s saved", args[1], args[2]),
			fmt.Sprintf("%s -> %s 已保存", args[1], args[2])), nil

	case "del":
		if len(args) < 2 {
			return l.t("usage: /fip del <domain>", "用法：/fip del <domain>"), nil
		}
		ok, err := admin.AdminDeleteDomain(ctx, args[1])
		if err != nil {
			return "", err
		}
		if !ok {
			return l.t(fmt.Sprintf("%s: no mapping", args[1]), fmt.Sprintf("%s：无映射", args[1])), nil
		}
		return l.t(fmt.Sprintf("deleted %s, the next query allocates a new fake ip", args[1]),
			fmt.Sprintf("已删除 %s，下次查询会分配新的 fake IP", args[1])), nil

	case "clear":
		if len(args) < 2 || strings.ToLower(args[1]) != "confirm" {
			return l.t("send /fip clear confirm to drop every mapping",
				"发送 /fip clear confirm 以删除全部映射"), nil
		}
		n, err := admin.AdminClearMappings(ctx)
		if err != nil {
			return "", err
		}
		return l.t(fmt.Sprintf("deleted %d mapping(s)", n),
			fmt.Sprintf("已删除 %d 条映射", n)), nil
	}

	return l.t("unknown subcommand, send /fip help", "未知子命令，请发送 /fip help"), nil
}

// handleStatus summarises the process and the managed plugins.
func (p *telegramBot) handleStatus(ctx context.Context, langs ...lang) (string, error) {
	l := replyLang(langs)
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
	fmt.Fprintf(&b, l.t("uptime: %s", "运行时长：%s"), time.Since(p.startedAt).Round(time.Second))
	fmt.Fprintf(&b, l.t("\nloaded plugins: %d", "\n已加载插件：%d"), len(ex))
	fmt.Fprintf(&b, l.t("\nfakeip-capable: %d", "\n支持 fakeip：%d"), fakeipCount)
	fmt.Fprintf(&b, l.t("\nocserv-capable: %d", "\n支持 ocserv：%d"), ocservCount)
	fmt.Fprintf(&b, l.t("\nfakeip_tags: %s", "\nfakeip 标签：%s"), strings.Join(p.args.FakeIPTags, ", "))
	fmt.Fprintf(&b, l.t("\nocserv_tags: %s", "\nocserv 标签：%s"), strings.Join(p.args.OcservTags, ", "))
	return b.String(), nil
}

// handlePlugins lists every loaded plugin and the capabilities the bot sees
// on it, which is how a tag is chosen for the commands above.
func (p *telegramBot) handlePlugins(langs ...lang) string {
	l := replyLang(langs)
	ex := p.M().GetExecutables()
	tags := make([]string, 0, len(ex))
	for tag := range ex {
		tags = append(tags, tag)
	}
	sort.Strings(tags)

	var b strings.Builder
	fmt.Fprintf(&b, l.t("loaded plugins: %d", "已加载插件：%d"), len(tags))
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

func (p *telegramBot) handleVPN(ctx context.Context, args []string, langs ...lang) (string, error) {
	l := replyLang(langs)
	tag, args := pickTag(p.args.OcservTags, args)
	if len(args) == 0 {
		return vpnHelpText(l), nil
	}
	switch strings.ToLower(args[0]) {
	case "tags":
		return p.tagSummary("ocserv", p.args.OcservTags, l), nil
	case "help":
		return vpnHelpText(l), nil
	}

	admin, err := p.resolveOcservFor(tag, l)
	if err != nil {
		return "", err
	}

	switch strings.ToLower(args[0]) {
	case "reload":
		svc, ok := admin.(ocservServiceAdmin)
		if !ok {
			return "", fmt.Errorf("%s", l.t(fmt.Sprintf("ocserv_ctl tag %q does not expose systemd control", tag),
				fmt.Sprintf("ocserv_ctl 标签 %q 未提供 systemd 控制", tag)))
		}
		return svc.AdminReload(ctx)
	case "restart":
		svc, ok := admin.(ocservServiceAdmin)
		if !ok {
			return "", fmt.Errorf("%s", l.t(fmt.Sprintf("ocserv_ctl tag %q does not expose systemd control", tag),
				fmt.Sprintf("ocserv_ctl 标签 %q 未提供 systemd 控制", tag)))
		}
		return svc.AdminRestart(ctx)
	case "pool":
		pool, ok := admin.(ocservPoolAdmin)
		if !ok {
			return "", fmt.Errorf("%s", l.t(fmt.Sprintf("ocserv_ctl tag %q does not expose address allocation", tag),
				fmt.Sprintf("ocserv_ctl 标签 %q 未提供地址分配", tag)))
		}
		return pool.AdminPool(ctx)
	case "alloc":
		if len(args) < 2 {
			return l.t("usage: /vpn alloc <user> [ip]", "用法：/vpn alloc <user> [ip]"), nil
		}
		pool, ok := admin.(ocservPoolAdmin)
		if !ok {
			return "", fmt.Errorf("%s", l.t(fmt.Sprintf("ocserv_ctl tag %q does not expose address allocation", tag),
				fmt.Sprintf("ocserv_ctl 标签 %q 未提供地址分配", tag)))
		}
		ip := ""
		if len(args) > 2 {
			ip = args[2]
		}
		return pool.AdminAllocIP(ctx, args[1], ip)
	case "events":
		ev, ok := admin.(ocservEventAdmin)
		if !ok {
			return "", fmt.Errorf("%s", l.t(fmt.Sprintf("ocserv_ctl tag %q does not expose updown events", tag),
				fmt.Sprintf("ocserv_ctl 标签 %q 未提供上下线事件", tag)))
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
			return l.t("usage: /vpn free <user>", "用法：/vpn free <user>"), nil
		}
		pool, ok := admin.(ocservPoolAdmin)
		if !ok {
			return "", fmt.Errorf("%s", l.t(fmt.Sprintf("ocserv_ctl tag %q does not expose address allocation", tag),
				fmt.Sprintf("ocserv_ctl 标签 %q 未提供地址分配", tag)))
		}
		return pool.AdminReleaseIP(ctx, args[1])
	}

	var argv []string
	switch strings.ToLower(args[0]) {
	case "user":
		if len(args) < 2 {
			return l.t("usage: /vpn user <name>", "用法：/vpn user <name>"), nil
		}
		argv = []string{"show", "user", args[1]}
	case "users":
		argv = []string{"show", "users"}
	case "status":
		argv = []string{"show", "status"}
	case "sessions":
		argv = []string{"show", "sessions", "valid"}
	case "kick":
		if len(args) < 2 {
			return l.t("usage: /vpn kick <user>", "用法：/vpn kick <user>"), nil
		}
		argv = []string{"disconnect", "user", args[1]}
	case "term":
		if len(args) < 2 {
			return l.t("usage: /vpn term <user>", "用法：/vpn term <user>"), nil
		}
		argv = []string{"terminate", "user", args[1]}
	case "run":
		// Full escape hatch for the remaining occtl commands.
		if len(args) < 2 {
			return l.t("usage: /vpn run <occtl args...>", "用法：/vpn run <occtl args...>"), nil
		}
		argv = args[1:]
	default:
		return l.t("unknown subcommand, send /vpn help", "未知子命令，请发送 /vpn help"), nil
	}

	out, err := admin.AdminExec(ctx, argv)
	out = strings.TrimSpace(out)
	if err != nil {
		if out != "" {
			return l.t("occtl failed: ", "occtl 失败：") + err.Error() + "\n" + out, nil
		}
		return "", err
	}
	if out == "" {
		out = l.t("ok, no output", "成功，无输出")
	}
	return out, nil
}

// resolveAdminFor finds a fakeip plugin by tag. Lookup is lazy because plugins
// are initialised in configuration order, and cached per tag.
func (p *telegramBot) resolveAdminFor(tag string, langs ...lang) (mappingAdmin, error) {
	l := replyLang(langs)
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
		return nil, fmt.Errorf(l.t("plugin %q is not loaded", "插件 %q 未加载"), tag)
	}
	a, ok := e.(mappingAdmin)
	if !ok {
		return nil, fmt.Errorf(l.t("plugin %q does not implement the fakeip admin interface",
			"插件 %q 未实现 fakeip 管理接口"), tag)
	}
	p.adminCache[tag] = a
	return a, nil
}

// resolveOcservFor finds the ocserv_ctl plugin that owns the occtl call.
func (p *telegramBot) resolveOcservFor(tag string, langs ...lang) (ocservAdmin, error) {
	l := replyLang(langs)
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
		return nil, fmt.Errorf(l.t("plugin %q is not loaded", "插件 %q 未加载"), tag)
	}
	a, ok := e.(ocservAdmin)
	if !ok {
		return nil, fmt.Errorf(l.t("plugin %q does not implement the ocserv admin interface",
			"插件 %q 未实现 ocserv 管理接口"), tag)
	}
	p.ocservCache[tag] = a
	return a, nil
}

// tagSummary says which configured tags are actually loaded.
func (p *telegramBot) tagSummary(kind string, tags []string, langs ...lang) string {
	l := replyLang(langs)
	ex := p.M().GetExecutables()
	var b strings.Builder
	fmt.Fprintf(&b, l.t("%s targets:", "%s 目标："), kind)
	for _, t := range tags {
		state := l.t("loaded", "已加载")
		if _, ok := ex[t]; !ok {
			state = l.t("missing", "未加载")
		}
		fmt.Fprintf(&b, "\n%s (%s)", t, state)
	}
	return b.String()
}

// locationFor picks the timezone used to render a data source's timestamps:
// an explicit bot timezone wins, then the plugin's own setting, then the
// default Asia/Shanghai.
func (p *telegramBot) locationFor(src interface{}) *time.Location {
	if p.args.timezoneSet && p.loc != nil {
		return p.loc
	}
	if lp, ok := src.(interface{ Location() *time.Location }); ok {
		if loc := lp.Location(); loc != nil {
			return loc
		}
	}
	if p.loc != nil {
		return p.loc
	}
	return timeutil.MustDefault()
}

// formatTime renders stored Unix seconds in loc.
func formatTime(unix int64, loc *time.Location) string {
	if unix <= 0 {
		return "-"
	}
	return timeutil.FormatUnix(unix, "2006-01-02 15:04", loc)
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
		{"/fip tags                    configured targets", PermFakeIP},
		{"/fip [tag] list [n]          recent mappings (default 20)", PermFakeIP},
		{"/fip get <domain|fake_ip>    look up one mapping", PermFakeIP},
		{"/fip add <domain> <fake_ip>  create or replace a mapping", PermFakeIP},
		{"/fip del <domain>            drop a mapping", PermFakeIP},
		{"/fip stats                   mapping counters", PermFakeIP},
		{"/fip clear confirm           drop every mapping", PermFakeIP},
	}},
	{title: "ocserv", items: []helpItem{
		{"/vpn tags                    configured targets", PermOcserv},
		{"/vpn users                   connected ocserv users", PermOcserv},
		{"/vpn user <name>             state of one ocserv user", PermOcserv},
		{"/vpn events [n] [user]       connect/disconnect history", PermOcserv},
		{"/vpn status                  ocserv status", PermOcserv},
		{"/vpn sessions                valid sessions", PermOcserv},
		{"/vpn kick <user>             disconnect one user", PermOcserv},
		{"/vpn term <user>             terminate one user", PermOcserv},
		{"/vpn run <occtl args...>     any other occtl command", PermOcserv},
	}},
	{title: "radius accounts", items: []helpItem{
		{"/user tags                   configured targets", PermRadius},
		{"/user list                   radius accounts with group and state", PermRadius},
		{"/user add <name> <pass> [g]  create a radius account", PermRadius},
		{"/user del <name>             delete a radius account", PermRadius},
		{"/user pass <name> <pass>     replace a password", PermRadius},
		{"/user enable|disable <name>  toggle authentication", PermRadius},
		{"/user limit <name> <max> [p] set traffic quota / reset period", PermRadius},
		{"/user usage <name>           used up/down, limit and next reset", PermRadius},
		{"/user reset <name>           clear usage, start a new period", PermRadius},
		{"/user sessions [active] [n]  accounting sessions", PermRadius},
	}},
	{title: "access records", items: []helpItem{
		{"/access <user> [days]        export that user's visit records as xlsx (default 7 days)", PermAccess},
		{"/access <ip> [days]          export one client address directly", PermAccess},
	}},
	{title: "traffic watch", items: []helpItem{
		{"/watch [tag] <source_ip>     live newest 20 flows of one source", PermWatch},
		{"/stop                        stop every watch of this chat", PermWatch},
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
	{title: "data providers", items: []helpItem{
		{"/provider                    configured data providers and examples", PermProvider},
		{"/provider <tag>              one provider and its add/mod/del/clear examples", PermProvider},
		{"/provider <tag> add <d>      add a domain to a text provider", PermProvider},
		{"/provider <tag> list [p] [n]  list a .txt provider, page and size together", PermProvider},
		{"/provider <tag> mod <old> <new>  replace a domain", PermProvider},
		{"/provider <tag> del <d>      delete a domain", PermProvider},
		{"/provider <tag> clear        empty a text provider or one v2dat category", PermProvider},
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
func (p *telegramBot) helpFor(chatID int64, langs ...lang) string {
	l := replyLang(langs)
	groups := helpGroups
	if l == langZH {
		groups = helpGroupsZH
	}
	var b strings.Builder
	b.WriteString(l.t("mosdns admin bot", "mosdns 管理机器人"))
	if p.access != nil {
		if role, ok := p.access.roles[chatID]; ok {
			b.WriteString(l.t(" (role: "+role+")", "（角色："+role+"）"))
		}
	}
	b.WriteString("\n")
	for _, group := range groups {
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
	b.WriteString(l.t("\n/perm                        your role and permissions\n/help                        this message",
		"\n/perm                        查看你的角色和权限\n/help                        显示本帮助"))
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
/vpn user <name>             state of one user (online, IP, traffic)
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
/vpn events [n] [user]       recent connect/disconnect events from the updown hook

traffic quota belongs to the radius account table, not occtl:
/user limit <name> <max|0|-> [period|0|-]   set total quota and reset period
/user usage <name>                            used up/down, limit and next reset
/user reset <name>                            clear usage, start a new period`

const fipHelpZH = `fakeip 命令（可选 tag 放在最前，例如 /fip fakeip2 list）
/fip tags                    已配置的目标
/fip list [n]                最近的映射
/fip get <domain|fake_ip>    查询一条映射
/fip add <domain> <fake_ip>  新增或替换映射
/fip del <domain>            删除一条映射
/fip stats                   映射计数
/fip clear confirm           删除全部映射`

const vpnHelpZH = `ocserv 命令（occtl；可选 tag 放在最前，例如 /vpn ocserv2 users）
/vpn tags                    已配置的目标
/vpn users                   当前在线用户
/vpn user <name>             单个用户状态（在线、IP、流量）
/vpn status                  服务端状态
/vpn sessions                有效会话
/vpn kick <user>             断开一个用户
/vpn term <user>             终止一个用户
/vpn run <occtl args...>     其他任意 occtl 命令，例如
                             /vpn run show iroutes
                             /vpn run unban ip 10.0.0.5
/vpn pool                    从 ocserv.conf 解析的地址池
/vpn alloc <user> [ip]       在 config-per-user 中固定 IP
/vpn free <user>             释放该固定 IP
/vpn reload                  重载 ocserv（保留会话）
/vpn restart                 重启 ocserv（丢弃会话）
/vpn events [n] [user]       最近的上下线事件

流量配额属于 radius 账号表，不属于 occtl：
/user limit <name> <max|0|-> [period|0|-]   设置总配额和重置周期
/user usage <name>                           查看上下行、上限和下次重置
/user reset <name>                           清空用量并开始新周期`

// helpGroupsZH mirrors helpGroups in the same order. Command tokens stay in
// English deliberately; only the descriptions are translated.
var helpGroupsZH = []helpGroup{
	{title: "fakeip 映射", items: []helpItem{
		{"/fip tags                    已配置的目标", PermFakeIP},
		{"/fip [tag] list [n]          最近映射（默认 20 条）", PermFakeIP},
		{"/fip get <domain|fake_ip>    查询一条映射", PermFakeIP},
		{"/fip add <domain> <fake_ip>  新增或替换映射", PermFakeIP},
		{"/fip del <domain>             删除一条映射", PermFakeIP},
		{"/fip stats                    映射计数", PermFakeIP},
		{"/fip clear confirm            删除全部映射", PermFakeIP},
	}},
	{title: "ocserv", items: []helpItem{
		{"/vpn tags                    已配置的目标", PermOcserv},
		{"/vpn users                   当前在线用户", PermOcserv},
		{"/vpn user <name>             单个用户状态", PermOcserv},
		{"/vpn events [n] [user]       上下线历史", PermOcserv},
		{"/vpn status                  服务端状态", PermOcserv},
		{"/vpn sessions                有效会话", PermOcserv},
		{"/vpn kick <user>             断开一个用户", PermOcserv},
		{"/vpn term <user>             终止一个用户", PermOcserv},
		{"/vpn run <occtl args...>     其他 occtl 命令", PermOcserv},
	}},
	{title: "radius 账号", items: []helpItem{
		{"/user tags                   已配置的目标", PermRadius},
		{"/user list                   radius 账号、组和状态", PermRadius},
		{"/user add <name> <pass> [g]  创建 radius 账号", PermRadius},
		{"/user del <name>             删除 radius 账号", PermRadius},
		{"/user pass <name> <pass>     替换密码", PermRadius},
		{"/user enable|disable <name>  启用或禁用认证", PermRadius},
		{"/user limit <name> <max> [p] 设置流量配额和重置周期", PermRadius},
		{"/user usage <name>           查看上下行、上限和下次重置", PermRadius},
		{"/user reset <name>           清空用量并开始新周期", PermRadius},
		{"/user sessions [active] [n]  记账会话", PermRadius},
	}},
	{title: "访问记录", items: []helpItem{
		{"/access <user> [days]        导出该用户的访问记录为 xlsx（默认 7 天）", PermAccess},
		{"/access <ip> [days]          直接导出某个客户端地址的记录", PermAccess},
	}},
	{title: "流量监听", items: []helpItem{
		{"/watch [tag] <source_ip>     持续显示单个源 IP 的最新 20 条流量", PermWatch},
		{"/stop                        停止本聊天的全部监听", PermWatch},
	}},
	{title: "数据面", items: []helpItem{
		{"/net [tag]                   数据面：设备、代理、标记、规则、路由", PermStatus},
		{"/ledger [tag]                后续运行会清理的已记录对象", PermStatus},
		{"/diag <domain> [tag]         单个域名的映射、真实 IP 和出口", PermFakeIP},
		{"/sweep [tag] confirm         清理当前配置不拥有的已记录对象", PermConfig},
	}},
	{title: "进程", items: []helpItem{
		{"/status                      进程和插件摘要", PermStatus},
		{"/plugins                     已加载插件及其能力", PermStatus},
		{"/plugin <tag>                单个插件的类型、能力和配置参数", PermStatus},
		{"/audit [n]                   最近的管理操作", PermStatus},
	}},
	{title: "数据源", items: []helpItem{
		{"/provider                    查看数据源和示例", PermProvider},
		{"/provider <tag>              单个数据源及其 add/mod/del/clear 示例", PermProvider},
		{"/provider <tag> add <d>      向文本数据源增加域名", PermProvider},
		{"/provider <tag> list [p] [n] 列出 .txt 数据源，页码和分页大小须同时提供", PermProvider},
		{"/provider <tag> mod <old> <new>  替换域名", PermProvider},
		{"/provider <tag> del <d>      删除域名", PermProvider},
		{"/provider <tag> clear        清空文本数据源或一个 v2dat 分类", PermProvider},
	}},
	{title: "配置", items: []helpItem{
		{"/config                      配置文件摘要", PermConfig},
		{"/config show <section>       查看 log/data_providers/plugins/servers", PermConfig},
		{"/config get <key.path>       读取一个值，例如 plugins[1].tag", PermConfig},
		{"/config set <key.path> <v>   写入一个值（会先备份）", PermConfig},
		{"/config add <section> <yaml> 追加一个块；flow yaml，例如", PermConfig},
		{"                             /config add plugins {tag: x, type: sequence}", PermConfig},
		{"/config del <section> <k>    按 tag、索引或日志键删除", PermConfig},
		{"/config validate             重载前检查必填字段", PermConfig},
		{"/proxy [tag]                 fakeip 插件的代理状态", PermConfig},
		{"/proxy on <url>|off          写入代理，然后 /reload confirm", PermConfig},
		{"/exec <tag> <ip> <domain>    运行一个已配置的 exec_script 插件", PermExecScript},
		{"/reload confirm              校验配置并停止，由 supervisor 拉起", PermReload},
	}},
}

func fipHelpText(l lang) string {
	return l.t(fipHelp, fipHelpZH)
}

func vpnHelpText(l lang) string {
	return l.t(vpnHelp, vpnHelpZH)
}
