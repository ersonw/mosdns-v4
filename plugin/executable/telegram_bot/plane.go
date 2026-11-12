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

func (p *telegramBot) resolvePlaneAdmin(tag string) (planeAdmin, error) {
	if p.plane != nil {
		return p.plane, nil // test seam: one stub for every tag
	}
	e, ok := p.M().GetExecutables()[tag]
	if !ok {
		return nil, fmt.Errorf("%s: not loaded", tag)
	}
	admin, ok := e.(planeAdmin)
	if !ok {
		return nil, fmt.Errorf("%s: not a fakeip data plane", tag)
	}
	return admin, nil
}

// handleNet renders what the data plane has installed: the fields a shell
// session would otherwise need three commands to read.
func (p *telegramBot) handleNet(ctx context.Context, args []string) (string, error) {
	tag, args := pickTag(p.args.FakeIPTags, args)
	if len(args) > 0 && strings.ToLower(args[0]) == "tags" {
		return p.tagSummary("fakeip", p.args.FakeIPTags), nil
	}
	admin, err := p.resolvePlaneAdmin(tag)
	if err != nil {
		return "", err
	}
	plane, err := admin.AdminPlane(ctx)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s plane: %s", tag, plane.DataPlane)
	if plane.Device != "" {
		fmt.Fprintf(&b, " (%s)", plane.Device)
	}
	fmt.Fprintf(&b, "\nrange: %s", plane.Range)
	fmt.Fprintf(&b, "\nproxy: %s", yesNo(plane.ProxyActive))
	fmt.Fprintf(&b, "\nmark: %s", yesNo(plane.MarkEnabled))
	if plane.RouteMark != 0 {
		fmt.Fprintf(&b, " (0x%x -> table %s)", plane.RouteMark, plane.RouteTable)
	}
	if plane.OutletTable != "" {
		fmt.Fprintf(&b, "\noutlet table: %s", plane.OutletTable)
	}
	fmt.Fprintf(&b, "\nmark set: %d address(es)", plane.RealIPs)
	if len(plane.Rules) > 0 {
		fmt.Fprintf(&b, "\nrules:")
		for _, line := range plane.Rules {
			fmt.Fprintf(&b, "\n  %s", line)
		}
	} else {
		fmt.Fprintf(&b, "\nrules: none of ours")
	}
	if len(plane.Routes) > 0 {
		fmt.Fprintf(&b, "\nroutes:")
		for _, line := range plane.Routes {
			fmt.Fprintf(&b, "\n  %s", line)
		}
	}
	return b.String(), nil
}

// handleLedger shows the state a later run would clean with, next to what is
// installed now: a recorded object with no live counterpart is a leftover.
func (p *telegramBot) handleLedger(ctx context.Context, args []string) (string, error) {
	tag, args := pickTag(p.args.FakeIPTags, args)
	if len(args) > 0 && strings.ToLower(args[0]) == "tags" {
		return p.tagSummary("fakeip", p.args.FakeIPTags), nil
	}
	admin, err := p.resolvePlaneAdmin(tag)
	if err != nil {
		return "", err
	}
	plane, err := admin.AdminPlane(ctx)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s recorded objects:", tag)
	if len(plane.Recorded) == 0 {
		fmt.Fprintf(&b, "\n  none")
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
	fmt.Fprintf(&b, "\nlive: rules=%d routes=%d mark set=%d",
		len(plane.Rules), len(plane.Routes), plane.RealIPs)
	return b.String(), nil
}

// handleSweep runs the record-driven cleanup by hand. It removes only what the
// running configuration does not own, so it is safe while the plugin is up.
func (p *telegramBot) handleSweep(ctx context.Context, args []string) (string, error) {
	tag, args := pickTag(p.args.FakeIPTags, args)
	if len(args) == 0 {
		return "sweep removes recorded objects the current configuration does not own.\nrun /sweep confirm", nil
	}
	if strings.ToLower(args[0]) != "confirm" {
		return "usage: /sweep [tag] confirm", nil
	}
	admin, err := p.resolvePlaneAdmin(tag)
	if err != nil {
		return "", err
	}
	removed, err := admin.AdminSweep(ctx)
	if err != nil {
		return "", err
	}
	if len(removed) == 0 {
		return "nothing to sweep: no recorded object differs from the running configuration", nil
	}
	return "removed:\n  " + strings.Join(removed, "\n  "), nil
}

// handleDiag answers what happens to one domain: the mapping handed out, the
// real addresses learned for it, and the way the stack would dial them.
func (p *telegramBot) handleDiag(ctx context.Context, args []string) (string, error) {
	if len(args) == 0 {
		return "usage: /diag <domain> [tag]", nil
	}
	domain := strings.ToLower(strings.TrimSpace(args[0]))
	tag, _ := pickTag(p.args.FakeIPTags, args[1:])
	admin, err := p.resolvePlaneAdmin(tag)
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
		fmt.Fprintf(&b, "\nno mapping: this domain has never been answered")
	} else {
		fmt.Fprintf(&b, "\nfake ip: %s", d.FakeIP)
		if d.CreatedAt > 0 {
			fmt.Fprintf(&b, " (%s)", formatTime(d.CreatedAt))
		}
	}
	if d.RealIPKnown {
		fmt.Fprintf(&b, "\nreal ips: %s", strings.Join(d.RealIPs, ", "))
	} else {
		fmt.Fprintf(&b, "\nreal ips: none recorded yet")
	}
	fmt.Fprintf(&b, "\noutlet: %s", d.Outlet)
	fmt.Fprintf(&b, "\nproxy: %s  mark: %s", yesNo(d.ProxyActive), yesNo(d.Marked))
	return b.String(), nil
}

// handleProxy reads or writes the proxy of the fakeip plugin. Writing the URL
// is the "on" switch, an empty value is "off"; the change is written to the
// config file with a backup, and a reload is needed to take effect.
func (p *telegramBot) handleProxy(ctx context.Context, args []string) (string, error) {
	tag, args := pickTag(p.args.FakeIPTags, args)
	if len(args) == 0 {
		return p.proxySummary(tag)
	}
	switch strings.ToLower(args[0]) {
	case "off":
		backup, err := p.setPluginValue(tag, "proxy", "")
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s proxy cleared (backup %s)\nrun /reload confirm to apply", tag, backup), nil
	case "on":
		if len(args) < 2 {
			return "usage: /proxy on <socks5://user:pass@host:port>", nil
		}
		backup, err := p.setPluginValue(tag, "proxy", args[1])
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s proxy set (backup %s)\nrun /reload confirm to apply", tag, backup), nil
	}
	return "usage: /proxy [tag]\n/proxy on <url>\n/proxy off", nil
}

func (p *telegramBot) proxySummary(tag string) (string, error) {
	doc, err := loadConfigDocument(p.configPath())
	if err != nil {
		return "", err
	}
	block := pluginBlock(doc, tag)
	if block == nil {
		return "", fmt.Errorf("%s: not in the config file", tag)
	}
	args := mappingGet(block, "args")
	proxy := ""
	if args != nil {
		if v := mappingGet(args, "proxy"); v != nil {
			proxy = strings.TrimSpace(nodeText(v))
		}
	}
	if proxy == "" {
		return fmt.Sprintf("%s proxy: off (answers go out over the direct outlet)", tag), nil
	}
	return fmt.Sprintf("%s proxy: on %s", tag, maskURL(proxy)), nil
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

func (p *telegramBot) handleAudit(args []string) (string, error) {
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
		return "no administration action recorded yet\nlog: " + p.auditPath(), nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "last %d action(s), log %s", len(entries), p.auditPath())
	for _, e := range entries {
		fmt.Fprintf(&b, "\n%s chat %d %s", e.At, e.ChatID, e.Action)
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
	case "/config", "/proxy", "/sweep", "/reload", "/exec", "/fip":
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
