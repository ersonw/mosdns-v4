package telegram_bot

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	fakeipadmin "github.com/ersonw/mosdns-v4/pkg/fakeip_admin"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// planeAdmin is the data-plane contract of a fakeip plugin, resolved by tag.
type planeAdmin = fakeipadmin.PlaneAdmin

func (p *telegramBot) resolvePlaneAdmin(tag string, langs ...lang) (planeAdmin, error) {
	l := replyLang(langs)
	if p.plane != nil {
		return p.plane, nil // test seam: one stub for every tag
	}
	e, ok := p.M().GetExecutables()[tag]
	if !ok {
		return nil, fmt.Errorf(l.t("%s: not loaded", "%s：未加载"), tag)
	}
	admin, ok := e.(planeAdmin)
	if !ok {
		return nil, fmt.Errorf(l.t("%s: not a fakeip data plane", "%s：不是 fakeip 数据面插件"), tag)
	}
	return admin, nil
}

// handleNet renders what the data plane has installed: the fields a shell
// session would otherwise need three commands to read.
func (p *telegramBot) handleNet(ctx context.Context, args []string, langs ...lang) (string, error) {
	l := replyLang(langs)
	tag, args := pickTag(p.args.FakeIPTags, args)
	if len(args) > 0 && strings.ToLower(args[0]) == "tags" {
		return p.tagSummary("fakeip", p.args.FakeIPTags, l), nil
	}
	admin, err := p.resolvePlaneAdmin(tag, l)
	if err != nil {
		return "", err
	}
	plane, err := admin.AdminPlane(ctx)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, l.t("%s plane: %s", "%s 数据面：%s"), tag, plane.DataPlane)
	if plane.Device != "" {
		fmt.Fprintf(&b, " (%s)", plane.Device)
	}
	fmt.Fprintf(&b, l.t("\nrange: %s", "\n地址范围：%s"), plane.Range)
	fmt.Fprintf(&b, l.t("\nproxy: %s", "\n代理：%s"), l.yesNo(plane.ProxyActive))
	fmt.Fprintf(&b, l.t("\nmark: %s", "\n标记：%s"), l.yesNo(plane.MarkEnabled))
	if plane.RouteMark != 0 {
		fmt.Fprintf(&b, l.t(" (0x%x -> table %s)", " (0x%x -> 路由表 %s)"), plane.RouteMark, plane.RouteTable)
	}
	if plane.OutletTable != "" {
		fmt.Fprintf(&b, l.t("\noutlet table: %s", "\n出口路由表：%s"), plane.OutletTable)
	}
	fmt.Fprintf(&b, l.t("\nmark set: %d address(es)", "\n标记地址：%d 个"), plane.RealIPs)
	if len(plane.Rules) > 0 {
		fmt.Fprintf(&b, l.t("\nrules:", "\n规则："))
		for _, line := range plane.Rules {
			fmt.Fprintf(&b, "\n  %s", line)
		}
	} else {
		fmt.Fprintf(&b, l.t("\nrules: none of ours", "\n规则：没有本插件的规则"))
	}
	if len(plane.Routes) > 0 {
		fmt.Fprintf(&b, l.t("\nroutes:", "\n路由："))
		for _, line := range plane.Routes {
			fmt.Fprintf(&b, "\n  %s", line)
		}
	}
	return b.String(), nil
}

// handleLedger shows the state a later run would clean with, next to what is
// installed now: a recorded object with no live counterpart is a leftover.
func (p *telegramBot) handleLedger(ctx context.Context, args []string, langs ...lang) (string, error) {
	l := replyLang(langs)
	tag, args := pickTag(p.args.FakeIPTags, args)
	if len(args) > 0 && strings.ToLower(args[0]) == "tags" {
		return p.tagSummary("fakeip", p.args.FakeIPTags, l), nil
	}
	admin, err := p.resolvePlaneAdmin(tag, l)
	if err != nil {
		return "", err
	}
	plane, err := admin.AdminPlane(ctx)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, l.t("%s recorded objects:", "%s 已记录对象："), tag)
	if len(plane.Recorded) == 0 {
		fmt.Fprintf(&b, l.t("\n  none", "\n  无"))
		return b.String(), nil
	}
	keys := make([]string, 0, len(plane.Recorded))
	for k := range plane.Recorded {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "\n  %s = %s", k, plane.Recorded[k])
	}
	fmt.Fprintf(&b, l.t("\nlive: rules=%d routes=%d mark set=%d",
		"\n当前：规则=%d 路由=%d 标记地址=%d"),
		len(plane.Rules), len(plane.Routes), plane.RealIPs)
	return b.String(), nil
}

// handleSweep runs the record-driven cleanup by hand. It removes only what the
// running configuration does not own, so it is safe while the plugin is up.
func (p *telegramBot) handleSweep(ctx context.Context, args []string, langs ...lang) (string, error) {
	l := replyLang(langs)
	tag, args := pickTag(p.args.FakeIPTags, args)
	if len(args) == 0 {
		return l.t("sweep removes recorded objects the current configuration does not own.\nrun /sweep confirm",
			"清理会删除当前配置不拥有的已记录对象。\n请运行 /sweep confirm"), nil
	}
	if strings.ToLower(args[0]) != "confirm" {
		return l.t("usage: /sweep [tag] confirm", "用法：/sweep [tag] confirm"), nil
	}
	admin, err := p.resolvePlaneAdmin(tag, l)
	if err != nil {
		return "", err
	}
	removed, err := admin.AdminSweep(ctx)
	if err != nil {
		return "", err
	}
	if len(removed) == 0 {
		return l.t("nothing to sweep: no recorded object differs from the running configuration",
			"没有需要清理的对象：已记录对象与当前运行配置一致"), nil
	}
	return l.t("removed:\n  ", "已删除：\n  ") + strings.Join(removed, "\n  "), nil
}

// handleDiag answers what happens to one domain: the mapping handed out, the
// real addresses learned for it, and the way the stack would dial them.
func (p *telegramBot) handleDiag(ctx context.Context, args []string, langs ...lang) (string, error) {
	l := replyLang(langs)
	if len(args) == 0 {
		return l.t("usage: /diag <domain> [tag]", "用法：/diag <domain> [tag]"), nil
	}
	domain := strings.ToLower(strings.TrimSpace(args[0]))
	tag, _ := pickTag(p.args.FakeIPTags, args[1:])
	admin, err := p.resolvePlaneAdmin(tag, l)
	if err != nil {
		return "", err
	}
	d, err := admin.AdminDiagnose(ctx, domain)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s", d.Domain)
	if d.FakeIP == "" {
		fmt.Fprintf(&b, l.t("\nno mapping: this domain has never been answered",
			"\n无映射：该域名从未被应答过"))
	} else {
		fmt.Fprintf(&b, l.t("\nfake ip: %s", "\nfake IP：%s"), d.FakeIP)
		if d.CreatedAt > 0 {
			fmt.Fprintf(&b, " (%s)", formatTime(d.CreatedAt, p.locationFor(nil)))
		}
	}
	if d.RealIPKnown {
		fmt.Fprintf(&b, l.t("\nreal ips: %s", "\n真实 IP：%s"), strings.Join(d.RealIPs, ", "))
	} else {
		fmt.Fprintf(&b, l.t("\nreal ips: none recorded yet", "\n真实 IP：尚未记录"))
	}
	fmt.Fprintf(&b, l.t("\noutlet: %s", "\n出口：%s"), d.Outlet)
	fmt.Fprintf(&b, l.t("\nproxy: %s  mark: %s", "\n代理：%s  标记：%s"),
		l.yesNo(d.ProxyActive), l.yesNo(d.Marked))
	return b.String(), nil
}

// handleProxy reads or writes the proxy of the fakeip plugin. Writing the URL
// is the "on" switch, an empty value is "off"; the change is written to the
// config file with a backup, and a reload is needed to take effect.
func (p *telegramBot) handleProxy(ctx context.Context, args []string, langs ...lang) (string, error) {
	l := replyLang(langs)
	tag, args := pickTag(p.args.FakeIPTags, args)
	if len(args) == 0 {
		return p.proxySummary(tag, l)
	}
	switch strings.ToLower(args[0]) {
	case "off":
		backup, err := p.setPluginValue(tag, "proxy", "")
		if err != nil {
			return "", err
		}
		return l.t(fmt.Sprintf("%s proxy cleared (backup %s)\nrun /reload confirm to apply", tag, backup),
			fmt.Sprintf("%s 代理已清除（备份 %s）\n运行 /reload confirm 以生效", tag, backup)), nil
	case "on":
		if len(args) < 2 {
			return l.t("usage: /proxy on <socks5://user:pass@host:port>",
				"用法：/proxy on <socks5://user:pass@host:port>"), nil
		}
		backup, err := p.setPluginValue(tag, "proxy", args[1])
		if err != nil {
			return "", err
		}
		return l.t(fmt.Sprintf("%s proxy set (backup %s)\nrun /reload confirm to apply", tag, backup),
			fmt.Sprintf("%s 代理已设置（备份 %s）\n运行 /reload confirm 以生效", tag, backup)), nil
	}
	return l.t("usage: /proxy [tag]\n/proxy on <url>\n/proxy off",
		"用法：/proxy [tag]\n/proxy on <url>\n/proxy off"), nil
}

func (p *telegramBot) proxySummary(tag string, langs ...lang) (string, error) {
	l := replyLang(langs)
	doc, err := loadConfigDocument(p.configPath())
	if err != nil {
		return "", err
	}
	block := pluginBlock(doc, tag)
	if block == nil {
		return "", fmt.Errorf("%s", l.t(fmt.Sprintf("%s: not in the config file", tag),
			fmt.Sprintf("%s：不在配置文件中", tag)))
	}
	args := mappingGet(block, "args")
	proxy := ""
	if args != nil {
		if v := mappingGet(args, "proxy"); v != nil {
			proxy = strings.TrimSpace(nodeText(v))
		}
	}
	if proxy == "" {
		return l.t(fmt.Sprintf("%s proxy: off (answers go out over the direct outlet)", tag),
			fmt.Sprintf("%s 代理：关（应答走直连出口）", tag)), nil
	}
	return l.t(fmt.Sprintf("%s proxy: on %s", tag, maskURL(proxy)),
		fmt.Sprintf("%s 代理：开 %s", tag, maskURL(proxy))), nil
}

// setPluginValue writes one key of a plugin's args and returns the backup path.
func (p *telegramBot) setPluginValue(tag, key, value string) (string, error) {
	path := p.configPath()
	doc, err := loadConfigDocument(path)
	if err != nil {
		return "", err
	}
	block := pluginBlock(doc, tag)
	if block == nil {
		return "", fmt.Errorf("%s: not in the config file", tag)
	}
	args := mappingGet(block, "args")
	if args == nil {
		args = &yaml.Node{
			Kind: yaml.MappingNode,
			Tag:  "!!map",
			Content: []*yaml.Node{
				scalarNode(key), scalarNode(value),
			},
		}
		block.Content = append(block.Content, scalarNode("args"), args)
	} else if idx := mappingIndex(args, key); idx >= 0 {
		setValueNode(args.Content[idx+1], scalarNode(value))
	} else {
		args.Content = append(args.Content, scalarNode(key), scalarNode(value))
	}
	backup, err := writeConfigDocument(path, doc)
	if err != nil {
		return "", err
	}
	return backup, nil
}

// maskURL hides the credentials of a proxy URL before it is shown in a chat.
func maskURL(url string) string {
	at := strings.LastIndex(url, "@")
	if at < 0 {
		return url
	}
	scheme := ""
	if i := strings.Index(url, "://"); i >= 0 {
		scheme = url[:i+3]
	}
	return scheme + "***" + url[at:]
}

// ---- audit -----------------------------------------------------------------

// auditEntry is one recorded administration action. The config file keeps
// credentials, so the detail is always the sanitised form, never the raw text.
type auditEntry struct {
	At     string `json:"at"`
	ChatID int64  `json:"chat_id"`
	Action string `json:"action"`
	Detail string `json:"detail"`
}

func (p *telegramBot) auditPath() string {
	if p.args.AuditLog != "" {
		return p.args.AuditLog
	}
	return filepath.Join(filepath.Dir(p.configPath()), "telegram_bot_audit.log")
}

func (p *telegramBot) recordAudit(chatID int64, action, detail string) {
	path := p.auditPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		p.L().Debug("telegram audit: cannot create the directory", zap.Error(err))
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		p.L().Debug("telegram audit: cannot open the log", zap.Error(err))
		return
	}
	defer f.Close()
	entry := auditEntry{
		At:     time.Now().Format(time.RFC3339),
		ChatID: chatID,
		Action: action,
		Detail: detail,
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		p.L().Debug("telegram audit: cannot write the log", zap.Error(err))
	}
}

func (p *telegramBot) readAudit(limit int) ([]auditEntry, error) {
	if limit <= 0 {
		limit = 20
	}
	f, err := os.Open(p.auditPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []auditEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var e auditEntry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	return entries, nil
}

func (p *telegramBot) handleAudit(args []string, langs ...lang) (string, error) {
	l := replyLang(langs)
	limit := 20
	if len(args) > 0 {
		if n, err := strconv.Atoi(args[0]); err == nil && n > 0 {
			limit = n
		}
	}
	entries, err := p.readAudit(limit)
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return l.t("no administration action recorded yet\nlog: ", "暂无管理操作记录\n日志：") + p.auditPath(), nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, l.t("last %d action(s), log %s", "最近 %d 条操作，日志 %s"), len(entries), p.auditPath())
	for _, e := range entries {
		fmt.Fprintf(&b, l.t("\n%s chat %d %s", "\n%s 会话 %d %s"), e.At, e.ChatID, e.Action)
		if e.Detail != "" {
			fmt.Fprintf(&b, " %s", e.Detail)
		}
	}
	return b.String(), nil
}

// scalarNode turns a plain string into a yaml scalar, tagged as a string so a
// value that looks like a number or a bool is not turned into one by the
// encoder.
func scalarNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

func yesNo(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

// isAuditedCommand reports whether one command changes the config file, the
// system objects, or runs a script. Read-only commands are not recorded.
func isAuditedCommand(cmd string) bool {
	switch cmd {
	case "/config", "/proxy", "/sweep", "/provider", "/reload", "/exec", "/fip":
		return true
	}
	return false
}

// auditDetail turns the arguments into the form that is safe to keep on disk.
// A config write keeps the key path but drops the value, and a proxy change
// keeps the verb but never the URL, because both may carry a credential.
func auditDetail(cmd string, args []string) string {
	switch cmd {
	case "/config":
		if len(args) >= 2 {
			return args[0] + " " + args[1]
		}
		if len(args) == 1 {
			return args[0]
		}
		return ""
	case "/proxy":
		if len(args) == 0 {
			return "show"
		}
		return args[0] // "on" or "off"; the url is never recorded
	}
	joined := strings.Join(args, " ")
	if len(joined) > 160 {
		joined = joined[:160] + "..."
	}
	return joined
}
