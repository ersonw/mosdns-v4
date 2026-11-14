package telegram_bot

// This file implements /provider: it lists the data_providers entries from the
// mosdns config and edits the ones that hold domains. Plain-text providers are
// edited through domain_manage.py. A v2dat geosite provider is handled by
// extracting the selected category to a temporary text list, editing it through
// domain_manage.py, then rebuilding the dat through txt2dat.py. Both script
// paths are configurable; a custom script must keep the same argv contract.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/matcher/v2data"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"
)

type domainProvider struct {
	Index      int
	Tag        string
	File       string
	AutoReload bool
	Kind       string // text, geosite, geoip or dat
	Categories []string
}

const (
	providerAdd   = "add"
	providerMod   = "mod"
	providerDel   = "del"
	providerClear = "clear"
	providerList  = "list"
)

func (p *telegramBot) handleProvider(ctx context.Context, args []string, langs ...lang) (string, error) {
	l := replyLang(langs)
	p.domainMu.Lock()
	defer p.domainMu.Unlock()

	doc, err := loadConfigDocument(p.configPath())
	if err != nil {
		return "", fmt.Errorf(l.t("read config %s: %w", "读取配置 %s 失败：%w"), p.configPath(), err)
	}
	providers := domainProviders(doc)
	if len(providers) == 0 {
		return l.t("data_providers is empty; nothing to manage", "data_providers 为空，没有可管理的数据源"), nil
	}

	if len(args) == 0 {
		return p.providerOverview(providers, l), nil
	}
	switch strings.ToLower(args[0]) {
	case "list", "providers", "help":
		if len(args) == 1 {
			return p.providerOverview(providers, l), nil
		}
	}

	prov, err := selectDomainProvider(providers, args[0], l)
	if err != nil {
		return "", err
	}
	if len(args) == 1 {
		return p.providerDetail(prov, l), nil
	}

	action, ok := parseProviderAction(args[1])
	if !ok {
		return p.providerDetail(prov, l), nil
	}
	rest := args[2:]
	if action == providerList {
		return p.providerList(prov, rest, l)
	}
	category, values, err := splitProviderArgs(prov, action, rest, l)
	if err != nil {
		return "", err
	}
	for _, value := range values {
		if err := validateProviderRule(value, prov.Kind == "text", l); err != nil {
			return "", fmt.Errorf(l.t("invalid rule %q: %w", "规则 %q 无效：%w"), value, err)
		}
	}

	if prov.Kind == "text" {
		return p.providerText(ctx, prov, action, values, l)
	}
	return p.providerV2Dat(ctx, prov, action, category, values, l)
}

func parseProviderAction(s string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "add", "a":
		return providerAdd, true
	case "mod", "modify", "update", "set", "replace":
		return providerMod, true
	case "del", "delete", "remove", "rm":
		return providerDel, true
	case "clear", "wipe", "empty":
		return providerClear, true
	case "list", "ls", "show":
		return providerList, true
	}
	return "", false
}

func domainProviders(doc *yaml.Node) []domainProvider {
	list := nodePath(doc, []string{"data_providers"})
	if list == nil || list.Kind != yaml.SequenceNode {
		return nil
	}
	var out []domainProvider
	for i, item := range list.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		tagNode := mappingGet(item, "tag")
		fileNode := mappingGet(item, "file")
		if tagNode == nil || fileNode == nil {
			continue
		}
		tag := strings.TrimSpace(tagNode.Value)
		raw := strings.TrimSpace(fileNode.Value)
		if tag == "" || raw == "" {
			continue
		}
		abs := raw
		if v, err := filepath.Abs(raw); err == nil {
			abs = v
		}
		prov := domainProvider{
			Index: i + 1,
			Tag:   tag,
			File:  abs,
			Kind:  providerKind(raw),
		}
		if r := mappingGet(item, "auto_reload"); r != nil {
			prov.AutoReload = strings.EqualFold(strings.TrimSpace(r.Value), "true")
		}
		prov.Categories = providerCategories(doc, tag)
		out = append(out, prov)
	}
	return out
}

func providerKind(file string) string {
	ext := strings.ToLower(filepath.Ext(file))
	if ext != ".dat" {
		return "text"
	}
	base := strings.ToLower(filepath.Base(file))
	switch {
	case strings.Contains(base, "geoip"):
		return "geoip"
	case strings.Contains(base, "geosite"):
		return "geosite"
	}
	return "dat"
}

// providerCategories collects the "provider:<tag>:<category>" references used
// by plugins, so a geosite provider usually needs no manually typed category.
func providerCategories(doc *yaml.Node, tag string) []string {
	set := make(map[string]struct{})
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		if n.Kind == yaml.ScalarNode {
			prefix := "provider:" + tag + ":"
			if idx := strings.Index(n.Value, prefix); idx >= 0 {
				rest := n.Value[idx+len(prefix):]
				cat := strings.FieldsFunc(rest, func(r rune) bool {
					return r == ' ' || r == '\t' || r == ',' || r == '"' || r == '\'' ||
						r == ']' || r == '}' || r == '\n' || r == '\r'
				})
				if len(cat) > 0 && cat[0] != "" {
					set[strings.ToLower(cat[0])] = struct{}{}
				}
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(doc)
	var out []string
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func selectDomainProvider(providers []domainProvider, selector string, l lang) (domainProvider, error) {
	selector = strings.TrimSpace(selector)
	if n, err := strconv.Atoi(selector); err == nil {
		if n >= 1 && n <= len(providers) {
			return providers[n-1], nil
		}
		return domainProvider{}, fmt.Errorf(l.t("provider number %d is out of range (1-%d)",
			"数据源编号 %d 超出范围（1-%d）"), n, len(providers))
	}
	for _, prov := range providers {
		if strings.EqualFold(prov.Tag, selector) {
			return prov, nil
		}
	}
	return domainProvider{}, fmt.Errorf(l.t("unknown provider %q; send /provider to list them",
		"未知数据源 %q；发送 /provider 查看列表"), selector)
}

// splitProviderArgs separates the optional category from the domain values.
// A v2dat provider with exactly one configured category uses it automatically;
// an explicit category is still accepted before the value list.
func splitProviderArgs(prov domainProvider, action string, rest []string, l lang) (string, []string, error) {
	want := 1
	if action == providerMod {
		want = 2
	}
	if action == providerClear {
		want = 0
	}
	if prov.Kind == "text" {
		if len(rest) != want {
			return "", nil, errors.New(l.t(
				fmt.Sprintf("provider %s needs %d argument(s) for %s", prov.Tag, want, action),
				fmt.Sprintf("数据源 %s 的 %s 需要 %d 个参数", prov.Tag, action, want)))
		}
		return "", rest, nil
	}

	cat := ""
	if len(prov.Categories) == 1 {
		cat = prov.Categories[0]
		switch {
		case len(rest) == want:
			return cat, rest, nil
		case action == providerClear && len(rest) == 1:
			return strings.ToLower(rest[0]), nil, nil
		case len(rest) == want+1 && strings.EqualFold(rest[0], cat):
			return cat, rest[1:], nil
		default:
			return "", nil, errors.New(l.t(
				fmt.Sprintf("provider %s (category %s) needs %d argument(s) for %s", prov.Tag, cat, want, action),
				fmt.Sprintf("数据源 %s（分类 %s）的 %s 需要 %d 个参数", prov.Tag, cat, action, want)))
		}
	}

	if len(rest) == 0 {
		return "", nil, errors.New(l.t(
			fmt.Sprintf("provider %s needs a category (e.g. cn) and %d argument(s) for %s", prov.Tag, want, action),
			fmt.Sprintf("数据源 %s 需要分类（例如 cn）以及 %d 个参数用于 %s", prov.Tag, want, action)))
	}
	cat = strings.ToLower(rest[0])
	values := rest[1:]
	if len(values) != want {
		return "", nil, errors.New(l.t(
			fmt.Sprintf("provider %s needs category and %d argument(s) for %s", prov.Tag, want, action),
			fmt.Sprintf("数据源 %s 需要分类以及 %d 个参数用于 %s", prov.Tag, want, action)))
	}
	return cat, values, nil
}

func (p *telegramBot) providerList(prov domainProvider, args []string, l lang) (string, error) {
	if !strings.EqualFold(filepath.Ext(prov.File), ".txt") {
		return "", fmt.Errorf(l.t("list is only available for a .txt provider", "只有 .txt 数据源支持列出"))
	}
	page, size := 1, 50
	switch len(args) {
	case 0:
		// Default first page.
	case 1:
		return "", fmt.Errorf(l.t("page and page size must be supplied together", "页码和分页大小必须同时提供"))
	case 2:
		var err error
		page, err = strconv.Atoi(args[0])
		if err != nil || page < 1 {
			return "", fmt.Errorf(l.t("invalid page %q", "页码 %q 无效"), args[0])
		}
		size, err = strconv.Atoi(args[1])
		if err != nil || size < 1 || size > 500 {
			return "", fmt.Errorf(l.t("invalid page size %q (1-500)", "分页大小 %q 无效（1-500）"), args[1])
		}
	default:
		return "", fmt.Errorf(l.t("list takes either no argument or page and page size", "列出命令不带参数，或同时传页码和分页大小"))
	}

	set, err := readTextDomains(prov.File)
	if err != nil {
		return "", err
	}
	domains := make([]string, 0, len(set))
	for _, rule := range set {
		domains = append(domains, rule)
	}
	sort.Strings(domains)
	total := len(domains)
	pages := (total + size - 1) / size
	if total == 0 {
		return l.t(fmt.Sprintf("provider %s has no domains: %s", prov.Tag, prov.File),
			fmt.Sprintf("数据源 %s 没有域名：%s", prov.Tag, prov.File)), nil
	}
	if page > pages {
		return "", fmt.Errorf(l.t("page %d is out of range (total %d, %d page(s))",
			"页码 %d 超出范围（共 %d 条，%d 页）"), page, total, pages)
	}
	start := (page - 1) * size
	end := start + size
	if end > total {
		end = total
	}
	var b strings.Builder
	fmt.Fprintf(&b, l.t("provider %s (text)\ntotal: %d  page: %d/%d  page size: %d",
		"数据源 %s（文本）\n总数：%d  页码：%d/%d  分页大小：%d"),
		prov.Tag, total, page, pages, size)
	for i := start; i < end; i++ {
		fmt.Fprintf(&b, "\n%d. %s", i+1, domains[i])
	}
	fmt.Fprintf(&b, "\n%s", prov.File)
	return b.String(), nil
}

func normalizeProviderRule(s string) (key, text string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	lower := strings.ToLower(s)

	switch {
	case strings.HasPrefix(lower, "domain:"):
		value := strings.TrimPrefix(s[len("domain:"):], "*.")
		value = strings.TrimSpace(value)
		d := domainKey(value)
		if !validDomainName(d) {
			return "", "", false
		}
		return "domain:" + d, "domain:" + d, true
	case strings.HasPrefix(lower, "full:"):
		value := strings.TrimSpace(s[len("full:"):])
		d := domainKey(value)
		if !validDomainName(d) {
			return "", "", false
		}
		return "full:" + d, "full:" + d, true
	case strings.HasPrefix(lower, "keyword:"):
		value := strings.TrimSpace(s[len("keyword:"):])
		if value == "" || strings.ContainsAny(value, " \t\r\n") {
			return "", "", false
		}
		value = strings.ToLower(value)
		return "keyword:" + value, "keyword:" + value, true
	case strings.HasPrefix(lower, "regexp:"):
		value := strings.TrimSpace(s[len("regexp:"):])
		if value == "" {
			return "", "", false
		}
		if _, err := regexp.Compile(value); err != nil {
			return "", "", false
		}
		return "regexp:" + value, "regexp:" + value, true
	}

	if ipKey, display, ok := normalizeIPRule(s); ok {
		return "ip:" + ipKey, display, true
	}

	value := strings.TrimPrefix(s, "*.")
	d := domainKey(value)
	if !validDomainName(d) {
		return "", "", false
	}
	return "domain:" + d, d, true
}

func normalizeIPRule(s string) (key, display string, ok bool) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		_, network, err := net.ParseCIDR(s)
		if err != nil {
			return "", "", false
		}
		return network.String(), network.String(), true
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", "", false
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String() + "/32", v4.String(), true
	}
	return ip.String() + "/128", ip.String(), true
}

func validDomainName(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") || net.ParseIP(s) != nil {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func ruleKey(s string) string {
	if key, _, ok := normalizeProviderRule(s); ok {
		return key
	}
	return "raw:" + strings.ToLower(strings.TrimSpace(s))
}

func providerRuleText(s string) string {
	if _, text, ok := normalizeProviderRule(s); ok {
		return text
	}
	return strings.TrimSpace(s)
}

func validateProviderRule(s string, allowIP bool, l lang) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New(l.t("empty rule", "规则为空"))
	}
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "domain:"):
		value := strings.TrimPrefix(s[len("domain:"):], "*.")
		return validateDomainArg(value, l)
	case strings.HasPrefix(lower, "full:"):
		return validateDomainArg(strings.TrimSpace(s[len("full:"):]), l)
	case strings.HasPrefix(lower, "keyword:"):
		value := strings.TrimSpace(s[len("keyword:"):])
		if value == "" {
			return errors.New(l.t("empty keyword", "keyword 为空"))
		}
		if strings.ContainsAny(value, " \t\r\n") {
			return errors.New(l.t("keyword contains whitespace", "keyword 包含空白"))
		}
		return nil
	case strings.HasPrefix(lower, "regexp:"):
		value := strings.TrimSpace(s[len("regexp:"):])
		if value == "" {
			return errors.New(l.t("empty regexp", "regexp 为空"))
		}
		if _, err := regexp.Compile(value); err != nil {
			return fmt.Errorf(l.t("invalid regexp: %w", "regexp 无效：%w"), err)
		}
		return nil
	}

	if allowIP && (strings.Contains(s, "/") || net.ParseIP(s) != nil) {
		if _, _, ok := normalizeIPRule(s); !ok {
			return errors.New(l.t("invalid IP or CIDR", "IP 或 CIDR 无效"))
		}
		return nil
	}
	return validateDomainArg(s, l)
}

func validateDomainArg(s string, l lang) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New(l.t("empty domain", "域名为空"))
	}
	if len(s) > 253 {
		return errors.New(l.t("domain is longer than 253 bytes", "域名长度超过 253 字节"))
	}
	if strings.HasPrefix(s, "-") || strings.ContainsAny(s, " \t\r\n/\\;|&$`'\"") {
		return errors.New(l.t("domain contains a forbidden character", "域名包含不允许的字符"))
	}
	if net.ParseIP(s) != nil {
		return errors.New(l.t("IP address is not a domain", "IP 地址不是域名"))
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if !strings.Contains(s, ".") {
		return errors.New(l.t("domain needs at least one dot", "域名至少需要包含一个点"))
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 {
			return errors.New(l.t("domain label length is invalid", "域名标签长度无效"))
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errors.New(l.t("domain label starts or ends with '-'", "域名标签不能以 - 开头或结尾"))
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return fmt.Errorf(l.t("domain label contains %q", "域名标签包含 %q"), r)
			}
		}
	}
	return nil
}

func (p *telegramBot) providerOverview(providers []domainProvider, l lang) string {
	var b strings.Builder
	b.WriteString(l.t("domain data providers (select by tag or number)", "域名数据源（用 tag 或编号选择）"))
	for _, prov := range providers {
		fmt.Fprintf(&b, "\n%d) %s  [%s]", prov.Index, prov.Tag, providerKindLabel(prov.Kind, l))
		if len(prov.Categories) > 0 {
			fmt.Fprintf(&b, l.t("  categories: %s", "  分类：%s"), strings.Join(prov.Categories, ", "))
		}
		fmt.Fprintf(&b, "\n   %s", prov.File)
		b.WriteString("\n")
		for _, line := range providerExamples(prov) {
			b.WriteString("   " + line + "\n")
		}
		if prov.Kind == "geoip" {
			b.WriteString("   " + l.t("CIDR only; domain add/mod/del/clear are not supported", "仅 CIDR，不支持域名 add/mod/del/clear") + "\n")
		}
	}
	b.WriteString("\n" + providerUsage(l))
	fmt.Fprintf(&b, l.t("\nscripts: text=%s  v2dat=%s", "\n脚本：文本=%s  v2dat=%s"),
		p.args.DomainManageScript, p.args.Txt2DatScript)
	return b.String()
}

func (p *telegramBot) providerDetail(prov domainProvider, l lang) string {
	var b strings.Builder
	fmt.Fprintf(&b, l.t("provider %s (%d)  [%s]", "数据源 %s（%d）  [%s]"),
		prov.Tag, prov.Index, providerKindLabel(prov.Kind, l))
	fmt.Fprintf(&b, "\n%s", prov.File)
	if len(prov.Categories) > 0 {
		fmt.Fprintf(&b, l.t("\ncategories: %s", "\n分类：%s"), strings.Join(prov.Categories, ", "))
	}
	if prov.AutoReload {
		b.WriteString(l.t("\nauto_reload: on", "\nauto_reload：开"))
	} else {
		b.WriteString(l.t("\nauto_reload: off (send /reload confirm after a change)", "\nauto_reload：关（修改后发送 /reload confirm）"))
	}
	b.WriteString("\n" + providerUsage(l))
	b.WriteString("\n")
	for _, line := range providerExamples(prov) {
		b.WriteString(line + "\n")
	}
	if prov.Kind == "geoip" {
		b.WriteString(l.t("CIDR only; domain add/mod/del/clear are not supported", "仅 CIDR，不支持域名 add/mod/del/clear") + "\n")
	}
	return b.String()
}

func providerKindLabel(kind string, l lang) string {
	switch kind {
	case "text":
		return l.t("text", "文本")
	case "geosite":
		return l.t("v2dat/geosite", "v2dat/geosite")
	case "geoip":
		return l.t("v2dat/geoip, CIDR only", "v2dat/geoip，仅 CIDR")
	default:
		return l.t("v2dat, format not recognized from name", "v2dat，文件名无法判断格式")
	}
}

func providerExamples(prov domainProvider) []string {
	if prov.Kind == "geoip" {
		return nil
	}
	cat := ""
	if prov.Kind != "text" {
		if len(prov.Categories) == 1 {
			cat = ""
		} else {
			cat = " <category>"
		}
	}
	base := "/provider " + prov.Tag + " "
	lines := []string{}
	if strings.EqualFold(filepath.Ext(prov.File), ".txt") {
		lines = append(lines,
			base+"list",
			base+"list <page> <page_size>")
	}
	return append(lines,
		base+"add"+cat+" example.com",
		base+"mod"+cat+" old.example.com new.example.com",
		base+"del"+cat+" example.com",
		base+"clear"+cat,
	)
}

func providerUsage(l lang) string {
	return l.t(`usage:
/provider                         list providers and examples
/provider <tag>                   one provider and its examples
/provider <tag> list              list a .txt provider (first 50)
/provider <tag> list <page> <page_size>  list a .txt provider page
/provider <tag> add <rule>        add a rule
/provider <tag> mod <old> <new>    replace a rule
/provider <tag> del <rule>        delete a rule
/provider <tag> clear             empty the list or one v2dat category

Rules: bare domain or domain: (suffix), full: (exact), keyword:, regexp:.
Text providers also accept IPv4/IPv6 addresses and CIDR; geosite providers accept
domain rules only. For a v2dat provider the category is taken from the config when
it is unique; otherwise put it before the rule, e.g.
"/provider geosite add cn example.com".
Page and page size must be supplied together.`,
		`用法：
/provider                         列出数据源和示例
/provider <tag>                   单个数据源及其示例
/provider <tag> list              列出 .txt 数据源（默认前 50 条）
/provider <tag> list <page> <page_size>  按页列出 .txt 数据源
/provider <tag> add <rule>        增加规则
/provider <tag> mod <old> <new>   修改规则
/provider <tag> del <rule>        删除规则
/provider <tag> clear             清空列表或一个 v2dat 分类

规则：裸域名或 domain:（后缀）、full:（精确）、keyword:、regexp:。
文本数据源还支持 IPv4/IPv6 地址和 CIDR；geosite 只支持域名规则。
v2dat 数据源在配置中只有一个分类时会自动使用该分类；
否则把分类放在规则前面，例如 "/provider geosite add cn example.com"。
页码和分页大小必须同时提供。`)
}

func (p *telegramBot) providerText(ctx context.Context, prov domainProvider, action string, values []string, l lang) (string, error) {
	existing, err := readTextDomains(prov.File)
	if err != nil {
		return "", err
	}
	switch action {
	case providerAdd:
		if _, ok := existing[ruleKey(values[0])]; ok {
			return l.t(fmt.Sprintf("%s already present in %s", values[0], prov.Tag),
				fmt.Sprintf("%s 已存在于 %s", values[0], prov.Tag)), nil
		}
	case providerDel:
		if _, ok := existing[ruleKey(values[0])]; !ok {
			return l.t(fmt.Sprintf("%s is not present in %s", values[0], prov.Tag),
				fmt.Sprintf("%s 不在 %s 中", values[0], prov.Tag)), nil
		}
	case providerMod:
		if ruleKey(values[0]) == ruleKey(values[1]) {
			return l.t("old and new domain are identical", "旧域名和新域名相同"), nil
		}
		if _, ok := existing[ruleKey(values[0])]; !ok {
			return "", fmt.Errorf(l.t("%s is not present in %s", "%s 不在 %s 中"), values[0], prov.Tag)
		}
	case providerClear:
		return p.clearTextProvider(prov, l)
	}

	backup, err := backupDomainFile(prov.File)
	if err != nil {
		return "", fmt.Errorf(l.t("backup %s: %w", "备份 %s 失败：%w"), prov.File, err)
	}
	rollback := func(rerr error) (string, error) {
		if backup != "" {
			if err := restoreDomainFile(prov.File, backup); err != nil {
				return "", fmt.Errorf("%v; restore %s: %w", rerr, prov.File, err)
			}
		}
		return "", rerr
	}

	var out []string
	run := func(args ...string) error {
		text, err := p.runDomainScript(ctx, p.args.DomainManageScript, args...)
		if text != "" {
			out = append(out, text)
		}
		return err
	}
	switch action {
	case providerAdd:
		err = run("add", "-a", prov.File, values[0])
	case providerDel:
		err = run("del", "-a", prov.File, values[0])
	case providerMod:
		if err = run("del", "-a", prov.File, values[0]); err == nil {
			err = run("add", "-a", prov.File, values[1])
		}
	}
	if err != nil {
		return rollback(err)
	}

	after, err := readTextDomains(prov.File)
	if err != nil {
		return rollback(err)
	}
	if !verifyTextChange(after, action, values) {
		return rollback(errors.New(l.t(
			fmt.Sprintf("script did not apply the expected %s to %s", action, prov.Tag),
			fmt.Sprintf("脚本没有按预期对 %s 执行 %s", prov.Tag, action))))
	}
	res := providerResult(l, prov, action, "", out, backup)
	// The list entry is the only thing kept: every cached answer and every
	// stored record of the deleted name goes, so the next query follows the new
	// rule set instead of an answer learned under the old one.
	if extra := p.providerPurge(ctx, action, values, l); extra != "" {
		res += "\n" + extra
	}
	return res, nil
}

func (p *telegramBot) clearTextProvider(prov domainProvider, l lang) (string, error) {
	backup, err := backupDomainFile(prov.File)
	if err != nil {
		return "", fmt.Errorf(l.t("backup %s: %w", "备份 %s 失败：%w"), prov.File, err)
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(prov.File); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.WriteFile(prov.File, []byte{}, mode); err != nil {
		if backup != "" {
			_ = restoreDomainFile(prov.File, backup)
		}
		return "", fmt.Errorf(l.t("write %s: %w", "写入 %s 失败：%w"), prov.File, err)
	}
	return providerResult(l, prov, providerClear, "", []string{"empty file"}, backup), nil
}

func (p *telegramBot) providerV2Dat(ctx context.Context, prov domainProvider, action, category string, values []string, l lang) (string, error) {
	if category == "" {
		return "", fmt.Errorf(l.t("provider %s needs a category", "数据源 %s 需要分类"), prov.Tag)
	}
	if err := validateCategory(category); err != nil {
		return "", err
	}

	kind, err := detectDatKind(prov.File, prov.Kind, l)
	if err != nil {
		return "", err
	}
	if kind == "geoip" {
		return "", fmt.Errorf(l.t("provider %s is a geoip (CIDR) file, not a domain list",
			"数据源 %s 是 geoip（CIDR）文件，不是域名列表"), prov.Tag)
	}
	if kind != "geosite" {
		return "", fmt.Errorf(l.t("cannot confirm provider %s is a geosite file; refusing to rewrite it",
			"无法确认数据源 %s 是 geosite 文件，拒绝改写"), prov.Tag)
	}

	if action == providerClear {
		return p.clearV2DatCategory(prov, category, l)
	}

	existing, err := readGeoSiteDomains(prov.File, category, l)
	if err != nil {
		return "", err
	}
	set := make(map[string]string, len(existing))
	for _, d := range existing {
		set[ruleKey(d)] = providerRuleText(d)
	}
	switch action {
	case providerAdd:
		if _, ok := set[ruleKey(values[0])]; ok {
			return l.t(fmt.Sprintf("%s already present in %s/%s", values[0], prov.Tag, category),
				fmt.Sprintf("%s 已存在于 %s/%s", values[0], prov.Tag, category)), nil
		}
	case providerDel:
		if _, ok := set[ruleKey(values[0])]; !ok {
			return l.t(fmt.Sprintf("%s is not present in %s/%s", values[0], prov.Tag, category),
				fmt.Sprintf("%s 不在 %s/%s 中", values[0], prov.Tag, category)), nil
		}
	case providerMod:
		if ruleKey(values[0]) == ruleKey(values[1]) {
			return l.t("old and new domain are identical", "旧域名和新域名相同"), nil
		}
		if _, ok := set[ruleKey(values[0])]; !ok {
			return "", fmt.Errorf(l.t("%s is not present in %s/%s", "%s 不在 %s/%s 中"),
				values[0], prov.Tag, category)
		}
	}

	// Build the expected set first. Deleting the last domain cannot be done by
	// txt2dat.py (it rejects an empty input), so that one case removes the
	// category directly from the dat.
	before := make([]string, 0, len(set))
	for _, rule := range set {
		before = append(before, rule)
	}
	sort.Strings(before)
	switch action {
	case providerAdd:
		set[ruleKey(values[0])] = providerRuleText(values[0])
	case providerDel:
		delete(set, ruleKey(values[0]))
	case providerMod:
		delete(set, ruleKey(values[0]))
		set[ruleKey(values[1])] = providerRuleText(values[1])
	}
	after := make([]string, 0, len(set))
	for _, rule := range set {
		after = append(after, rule)
	}
	sort.Strings(after)
	if len(after) == 0 {
		return p.clearV2DatCategoryWithNote(prov, category, l)
	}

	tmp, err := os.CreateTemp("", "mosdns-provider-*.txt")
	if err != nil {
		return "", fmt.Errorf(l.t("create temporary list: %w", "创建临时列表失败：%w"), err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := writeDomainList(tmp, before); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}

	var out []string
	runText := func(args ...string) error {
		text, err := p.runDomainScript(ctx, p.args.DomainManageScript, args...)
		if text != "" {
			out = append(out, text)
		}
		return err
	}
	switch action {
	case providerAdd:
		err = runText("add", "-a", tmpPath, values[0])
	case providerDel:
		err = runText("del", "-a", tmpPath, values[0])
	case providerMod:
		if err = runText("del", "-a", tmpPath, values[0]); err == nil {
			err = runText("add", "-a", tmpPath, values[1])
		}
	}
	if err != nil {
		return "", err
	}
	edited, err := readTextDomains(tmpPath)
	if err != nil {
		return "", err
	}
	if !verifyTextChange(edited, action, values) {
		return "", errors.New(l.t("text script did not apply the expected change to the temporary list",
			"文本脚本没有对临时列表应用预期的修改"))
	}

	backup, err := backupDomainFile(prov.File)
	if err != nil {
		return "", fmt.Errorf(l.t("backup %s: %w", "备份 %s 失败：%w"), prov.File, err)
	}
	text, err := p.runDomainScript(ctx, p.args.Txt2DatScript, tmpPath, prov.File, category)
	if text != "" {
		out = append(out, text)
	}
	if err != nil {
		if backup != "" {
			if rerr := restoreDomainFile(prov.File, backup); rerr != nil {
				return "", fmt.Errorf("%v; restore %s: %w", err, prov.File, rerr)
			}
		}
		return "", err
	}

	got, err := readGeoSiteDomains(prov.File, category, l)
	if err != nil {
		return "", err
	}
	if !domainsEqual(got, after) {
		if backup != "" {
			if rerr := restoreDomainFile(prov.File, backup); rerr != nil {
				return "", fmt.Errorf("dat verification failed; restore %s: %w", prov.File, rerr)
			}
		}
		return "", errors.New(l.t("dat verification failed: category does not match the edited list",
			"dat 校验失败：分类内容与编辑后的列表不一致"))
	}
	return providerResult(l, prov, action, category, out, backup), nil
}

func (p *telegramBot) clearV2DatCategory(prov domainProvider, category string, l lang) (string, error) {
	return p.clearV2DatCategoryWithNote(prov, category, l)
}

func (p *telegramBot) clearV2DatCategoryWithNote(prov domainProvider, category string, l lang) (string, error) {
	list, err := loadGeoSiteList(prov.File, l)
	if err != nil {
		return "", err
	}
	idx := -1
	for i, site := range list.Entry {
		if strings.EqualFold(site.GetCountryCode(), category) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return l.t(fmt.Sprintf("category %s is already absent from %s", category, prov.Tag),
			fmt.Sprintf("分类 %s 在 %s 中本来就不存在", category, prov.Tag)), nil
	}
	if len(list.Entry) <= 1 {
		return "", fmt.Errorf(l.t("refusing to remove the only category in %s; the dat would be empty and the config reference would fail",
			"拒绝删除 %s 中唯一的分类；dat 会变空，配置中的引用会失效"), prov.Tag)
	}
	backup, err := backupDomainFile(prov.File)
	if err != nil {
		return "", fmt.Errorf(l.t("backup %s: %w", "备份 %s 失败：%w"), prov.File, err)
	}
	list.Entry = append(list.Entry[:idx], list.Entry[idx+1:]...)
	if err := writeGeoSiteList(prov.File, list); err != nil {
		if backup != "" {
			_ = restoreDomainFile(prov.File, backup)
		}
		return "", err
	}
	return providerResult(l, prov, providerClear, category, []string{"category removed"}, backup), nil
}

func providerResult(l lang, prov domainProvider, action, category string, out []string, backup string) string {
	var b strings.Builder
	fmt.Fprintf(&b, l.t("provider: %s", "数据源：%s"), prov.Tag)
	fmt.Fprintf(&b, l.t("\naction: %s", "\n操作：%s"), action)
	if category != "" {
		fmt.Fprintf(&b, l.t("\ncategory: %s", "\n分类：%s"), category)
	}
	fmt.Fprintf(&b, "\n%s", prov.File)
	if backup != "" {
		fmt.Fprintf(&b, l.t("\nbackup: %s", "\n备份：%s"), backup)
	}
	if len(out) > 0 {
		b.WriteString(l.t("\nscript output:", "\n脚本输出："))
		for _, line := range out {
			for _, part := range strings.Split(strings.TrimSpace(line), "\n") {
				if part != "" {
					b.WriteString("\n  " + part)
				}
			}
		}
	}
	if prov.AutoReload {
		b.WriteString(l.t("\nauto_reload is on; the matcher will reload the file", "\nauto_reload 已开启，匹配器会自动重载该文件"))
	} else {
		b.WriteString(l.t("\nauto_reload is off; send /reload confirm to apply", "\nauto_reload 已关闭，发送 /reload confirm 以生效"))
	}
	return b.String()
}

func (p *telegramBot) runDomainScript(ctx context.Context, script string, args ...string) (string, error) {
	if p.domainRunner != nil {
		return p.domainRunner(ctx, script, args...)
	}
	return p.execDomainScript(ctx, script, args...)
}

func (p *telegramBot) execDomainScript(ctx context.Context, script string, args ...string) (string, error) {
	if strings.TrimSpace(script) == "" {
		return "", errors.New("domain script path is empty")
	}
	timeout := time.Duration(p.args.DomainTimeout) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var cmd *exec.Cmd
	if strings.HasSuffix(strings.ToLower(script), ".py") {
		python := strings.TrimSpace(p.args.DomainPython)
		if python == "" {
			python = "python3"
		}
		cmd = exec.CommandContext(cctx, python, append([]string{script}, args...)...)
	} else {
		cmd = exec.CommandContext(cctx, script, args...)
	}
	output := &limitedBuffer{limit: 4096}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	text := strings.TrimSpace(output.String())
	if cctx.Err() == context.DeadlineExceeded {
		return text, fmt.Errorf("script %s timed out after %s", script, timeout)
	}
	if err != nil {
		if text != "" {
			return text, fmt.Errorf("%s: %s", err, text)
		}
		return text, fmt.Errorf("%s: %w", script, err)
	}
	return text, nil
}

type limitedBuffer struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.limit <= 0 {
		b.limit = 4096
	}
	if room := b.limit - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func readTextDomains(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	set := make(map[string]string)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// regexp: may contain '#', so only strip a trailing comment on other
		// rule types. A single space before '#' is the script's convention.
		if !strings.HasPrefix(strings.ToLower(line), "regexp:") {
			if i := strings.Index(line, " #"); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
		}
		key, text, ok := normalizeProviderRule(line)
		if !ok {
			continue
		}
		set[key] = text
	}
	return set, nil
}

func writeDomainList(f *os.File, domains []string) error {
	for _, d := range domains {
		if _, err := f.WriteString(d + "\n"); err != nil {
			return fmt.Errorf("write temporary list: %w", err)
		}
	}
	return nil
}

func verifyTextChange(after map[string]string, action string, values []string) bool {
	switch action {
	case providerAdd:
		_, ok := after[ruleKey(values[0])]
		return ok
	case providerDel:
		_, ok := after[ruleKey(values[0])]
		return !ok
	case providerMod:
		_, oldOK := after[ruleKey(values[0])]
		_, newOK := after[ruleKey(values[1])]
		return !oldOK && newOK
	}
	return false
}

func domainKey(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func domainsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := make([]string, len(a))
	for i, s := range a {
		as[i] = ruleKey(s)
	}
	bs := make([]string, len(b))
	for i, s := range b {
		bs[i] = ruleKey(s)
	}
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

func loadGeoSiteList(path string, l lang) (*v2data.GeoSiteList, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf(l.t("read %s: %w", "读取 %s 失败：%w"), path, err)
	}
	list := new(v2data.GeoSiteList)
	if err := proto.Unmarshal(b, list); err != nil {
		return nil, fmt.Errorf(l.t("parse geosite %s: %w", "解析 geosite %s 失败：%w"), path, err)
	}
	return list, nil
}

func readGeoSiteDomains(path, category string, l lang) ([]string, error) {
	list, err := loadGeoSiteList(path, l)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	for _, site := range list.Entry {
		if !strings.EqualFold(site.GetCountryCode(), category) {
			continue
		}
		var out []string
		for _, d := range site.GetDomain() {
			if len(d.GetAttribute()) > 0 {
				return nil, fmt.Errorf(l.t("category %s contains attributes; refusing to rewrite it with txt2dat.py",
					"分类 %s 包含属性；拒绝用 txt2dat.py 改写"), category)
			}
			var rule string
			switch d.GetType() {
			case v2data.Domain_Domain:
				rule = d.GetValue()
			case v2data.Domain_Plain:
				rule = "keyword:" + d.GetValue()
			case v2data.Domain_Regex:
				rule = "regexp:" + d.GetValue()
			case v2data.Domain_Full:
				rule = "full:" + d.GetValue()
			default:
				return nil, fmt.Errorf(l.t("category %s contains a %s entry; refusing to rewrite it with txt2dat.py",
					"分类 %s 包含 %s 类型条目；拒绝用 txt2dat.py 改写"), category, d.GetType().String())
			}
			out = append(out, rule)
		}
		return out, nil
	}
	return nil, nil
}

func writeGeoSiteList(path string, list *v2data.GeoSiteList) error {
	b, err := proto.Marshal(list)
	if err != nil {
		return fmt.Errorf("encode geosite: %w", err)
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.WriteFile(path, b, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func detectDatKind(path, fallback string, l lang) (string, error) {
	switch fallback {
	case "geosite", "geoip":
		// The file name is the documented way to tell geosite from geoip; do
		// not guess from protobuf content, because both formats share the same
		// top-level repeated-message shape.
		return fallback, nil
	}
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf(l.t("read %s: %w", "读取 %s 失败：%w"), path, err)
	}
	return "", fmt.Errorf(l.t("cannot determine whether %s is geosite or geoip; name it geosite*.dat or geoip*.dat",
		"无法判断 %s 是 geosite 还是 geoip；请命名为 geosite*.dat 或 geoip*.dat"), path)
}

func backupDomainFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	stamp := time.Now().Format("20060102-150405")
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("%s.bak-domain-%s", path, stamp)
		if i > 0 {
			name += fmt.Sprintf("-%d", i)
		}
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			if os.IsExist(err) {
				continue
			}
			return "", err
		}
		_, werr := f.Write(b)
		cerr := f.Close()
		if werr != nil {
			return "", werr
		}
		if cerr != nil {
			return "", cerr
		}
		return name, nil
	}
	return "", fmt.Errorf("could not allocate a backup name for %s", path)
}

func restoreDomainFile(path, backup string) error {
	if backup == "" {
		return nil
	}
	b, err := os.ReadFile(backup)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp := path + ".restore-" + time.Now().Format("20060102-150405.000000000")
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func validateCategory(s string) error {
	if s == "" {
		return errors.New("category is empty")
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return fmt.Errorf("category %q contains %q", s, r)
		}
	}
	return nil
}
