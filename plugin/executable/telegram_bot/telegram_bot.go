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
	// "admin", which holds every permission.
	DefaultRole string `yaml:"default_role"`
	// FakeIPTags are the fakeip_nat plugin tags this bot may manage. The
	// first tag is the default target of /fip; another one is selected with
	// "/fip <tag> <sub>". Default ["fakeip"].
	FakeIPTags []string `yaml:"fakeip_tags"`
	// FakeIPTag is the single-value form of FakeIPTags, kept for configs
	// written before the list existed.
	FakeIPTag string `yaml:"fakeip_tag"`
	// OcservTags are the ocserv_ctl plugin tags used by /vpn. The first tag
	// is the default target. Default ["ocserv"].
	OcservTags []string `yaml:"ocserv_tags"`
	// OcservTag is the single-value form of OcservTags.
	OcservTag string `yaml:"ocserv_tag"`
	// ConfigPath is the mosdns config file /config edits. Empty means:
	// take -c from the process arguments, else "etc/mosdns/config.yaml".
	ConfigPath string `yaml:"config_path"`
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
	a.FakeIPTags = mergeTagList(a.FakeIPTags, a.FakeIPTag, "fakeip")
	a.OcservTags = mergeTagList(a.OcservTags, a.OcservTag, "ocserv")
	a.FakeIPTag = a.FakeIPTags[0]
	a.OcservTag = a.OcservTags[0]
	a.DefaultRole = strings.TrimSpace(a.DefaultRole)
	if a.DefaultRole == "" {
		a.DefaultRole = PermAll
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

// mergeTagList combines the list form and the legacy single-value form, drops
// duplicates, and falls back to one default tag.
func mergeTagList(list []string, single, def string) []string {
	seen := make(map[string]struct{}, len(list)+2)
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
	add(single)
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

	ocservMu    sync.Mutex
	ocserv      ocservAdmin
	ocservCache map[string]ocservAdmin

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
func (p *telegramBot) handleText(ctx context.Context, chatID int64, text string) (string, error) {
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

	switch cmd {
	case "/start", "/help":
		return helpText, nil
	case "/fip":
		return p.handleFip(ctx, fields[1:])
	case "/vpn":
		return p.handleVPN(ctx, fields[1:])
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

const helpText = `mosdns admin bot
/fip [tag] list [n]          recent mappings (default 20)
/fip get <domain|fake_ip>    look up one mapping
/fip add <domain> <fake_ip>  create or replace a mapping
/fip del <domain>            drop a mapping
/fip stats                   mapping counters
/fip clear confirm           drop every mapping
/vpn users                   connected ocserv users
/vpn status                  ocserv status
/vpn sessions                valid sessions
/vpn kick <user>             disconnect one user
/vpn term <user>             terminate one user
/vpn run <occtl args...>     any other occtl command
/status                      process and plugin summary
/plugins                     loaded plugins and their capabilities
/plugin <tag>                one plugin: type, capabilities, config args
/config                      config file summary
/config show <section>       dump log/data_providers/plugins/servers
/config get <key.path>       read a value, e.g. plugins[1].tag
/config set <key.path> <v>   write a value (backup taken)
/config add <section> <yaml> append a block; flow yaml, e.g.
                             /config add plugins {tag: x, type: sequence}
/config del <section> <k>    drop by tag, index or log key
/config validate             check required fields before reload
/exec <tag> <ip> <domain>    run one configured exec_script plugin
/perm                        your role and permissions
/reload confirm              validate config and stop, so a supervisor restarts
/help                        this message`

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
                             /vpn run unban ip 10.0.0.5`
