package telegram_bot

// The /alias command manages the served name list of an alias plugin. The
// plugin owns the file, so every mutation goes through it: the list is rebuilt,
// the file is rewritten and the state of a removed name is purged in one step.
// A plain administrator may only touch the list; the suffix form belongs to the
// config permission.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	aliasadmin "github.com/ersonw/mosdns-v4/pkg/alias_admin"
	"github.com/ersonw/mosdns-v4/pkg/matcher/domain"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const aliasListLimit = 200

func (p *telegramBot) aliasTargets() map[string]aliasadmin.Admin {
	out := make(map[string]aliasadmin.Admin)
	if p.M() == nil {
		return out
	}
	for tag, ex := range p.M().GetExecutables() {
		if adm, ok := ex.(aliasadmin.Admin); ok {
			out[tag] = adm
		}
	}
	return out
}

func (p *telegramBot) handleAlias(ctx context.Context, chatID int64, args []string, langs ...lang) (string, error) {
	l := replyLang(langs)
	targets := p.aliasTargets()
	if len(targets) == 0 {
		return l.t("no alias plugin is loaded", "没有加载 alias 插件"), nil
	}

	if len(args) == 0 {
		tags := make([]string, 0, len(targets))
		for tag := range targets {
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		var b strings.Builder
		b.WriteString(l.t("alias tags:", "alias 标签："))
		for _, tag := range tags {
			snap, err := targets[tag].AdminAliasSnapshot(ctx)
			if err != nil {
				fmt.Fprintf(&b, "\n%s: %v", tag, err)
				continue
			}
			fmt.Fprintf(&b, "\n%s  suffix=.%s  range=%s  entries=%d",
				tag, snap.Suffix, snap.IPv4Range, snap.Total)
		}
		b.WriteString(l.t("\nusage: /alias <tag> list|add|del|mod|clear|suffix|range|reload",
			"\n用法：/alias <tag> list|add|del|mod|clear|suffix|range|reload"))
		return b.String(), nil
	}

	tag := args[0]
	adm, ok := targets[tag]
	if !ok {
		tags := make([]string, 0, len(targets))
		for t := range targets {
			tags = append(tags, t)
		}
		sort.Strings(tags)
		return "", fmt.Errorf(l.t("unknown alias tag %q (loaded: %s)", "未知的 alias 标签 %q（已加载：%s）"),
			tag, strings.Join(tags, ", "))
	}

	snap, err := adm.AdminAliasSnapshot(ctx)
	if err != nil {
		return "", fmt.Errorf(l.t("read alias %s: %w", "读取 alias %s 失败：%w"), tag, err)
	}

	if len(args) == 1 {
		return aliasDetail(snap, l), nil
	}

	action := strings.ToLower(args[1])
	rest := args[2:]
	switch action {
	case "list", "ls":
		return aliasList(snap, rest, l), nil
	case "add":
		if len(rest) != 1 {
			return aliasUsage(l), nil
		}
		value := rest[0]
		added, aerr := adm.AdminAliasAdd(ctx, value)
		if aerr != nil {
			return "", fmt.Errorf(l.t("add %s: %w", "添加 %s 失败：%w"), value, aerr)
		}
		if !added {
			return fmt.Sprintf(l.t("%s is already served by %s", "%s 已存在于 %s"), value, tag), nil
		}
		head := fmt.Sprintf("added %s to %s", value, tag)
		if l == langZH {
			head = fmt.Sprintf("已向 %s 添加 %s", tag, value)
		}
		return p.aliasMutationReport(ctx, l, snap, tag, head, value), nil
	case "del", "delete", "rm":
		if len(rest) != 1 {
			return aliasUsage(l), nil
		}
		value := rest[0]
		removed, derr := adm.AdminAliasDelete(ctx, value)
		if derr != nil {
			return "", fmt.Errorf(l.t("delete %s: %w", "删除 %s 失败：%w"), value, derr)
		}
		if !removed {
			return fmt.Sprintf(l.t("%s is not served by %s", "%s 不在 %s 中"), value, tag), nil
		}
		head := fmt.Sprintf("deleted %s from %s", value, tag)
		if l == langZH {
			head = fmt.Sprintf("已从 %s 删除 %s", tag, value)
		}
		return p.aliasMutationReport(ctx, l, snap, tag, head, value), nil
	case "mod", "modify", "set":
		if len(rest) != 2 {
			return aliasUsage(l), nil
		}
		oldValue, newValue := rest[0], rest[1]
		if merr := adm.AdminAliasModify(ctx, oldValue, newValue); merr != nil {
			return "", fmt.Errorf(l.t("modify %s: %w", "修改 %s 失败：%w"), oldValue, merr)
		}
		head := fmt.Sprintf("replaced %s with %s", oldValue, newValue)
		if l == langZH {
			head = fmt.Sprintf("已将 %s 替换为 %s", oldValue, newValue)
		}
		return p.aliasMutationReport(ctx, l, snap, tag, head, oldValue), nil
	case "clear", "wipe":
		before := snap.Entries
		n, cerr := adm.AdminAliasClear(ctx)
		if cerr != nil {
			return "", fmt.Errorf(l.t("clear %s: %w", "清空 %s 失败：%w"), tag, cerr)
		}
		var extra []string
		for _, e := range before {
			res := p.purgeDomainData(ctx, e.Domain)
			if res.removed() {
				extra = append(extra, e.Domain+": "+purgeSummary(res, l))
			}
		}
		out := fmt.Sprintf(l.t("cleared %s: %d entries removed", "已清空 %s：移除 %d 条"), tag, n)
		if len(extra) > 0 {
			out += "\n" + l.t("purged:", "已清理：") + "\n" + strings.Join(extra, "\n")
		}
		return out, nil
	case "suffix":
		if len(rest) != 1 {
			return aliasUsage(l), nil
		}
		if err := p.require(chatID, PermConfig, l); err != nil {
			return "", err
		}
		raw := strings.TrimPrefix(strings.TrimSpace(rest[0]), ".")
		if serr := adm.AdminAliasSetSuffix(ctx, raw); serr != nil {
			return "", fmt.Errorf(l.t("set suffix: %w", "设置后缀失败：%w"), serr)
		}
		out := fmt.Sprintf(l.t("suffix of %s is now .%s", "%s 的后缀现在是 .%s"), tag, raw)
		backup, perr := p.persistAliasArg(tag, "suffix", raw)
		if perr != nil {
			out += "\n" + fmt.Sprintf(l.t("runtime only, config not updated: %v", "仅运行时生效，配置未写入：%v"), perr)
			return out, nil
		}
		out += "\n" + fmt.Sprintf(l.t("config written (backup %s)", "已写入配置（备份 %s）"), backup)
		return out, nil
	case "range", "range4", "ipv4_range":
		if len(rest) != 1 {
			return aliasUsage(l), nil
		}
		if err := p.require(chatID, PermConfig, l); err != nil {
			return "", err
		}
		cidr := strings.TrimSpace(rest[0])
		if cerr := adm.AdminAliasCheckRange(ctx, cidr); cerr != nil {
			return "", fmt.Errorf(l.t("range refused: %w", "网段被拒绝：%w"), cerr)
		}
		backup, berr := p.persistAliasArg(tag, "ipv4_range", cidr)
		if berr != nil {
			return "", fmt.Errorf(l.t("write config: %w", "写入配置失败：%w"), berr)
		}
		p.L().Info("alias range written by bot", zap.String("tag", tag),
			zap.String("from", snap.IPv4Range), zap.String("to", cidr), zap.String("backup", backup))
		return fmt.Sprintf(l.t(
			"range of %s: %s -> %s\nwritten to config (backup %s); send /reload confirm or restart mosdns to apply",
			"%s 的网段：%s -> %s\n已写入配置（备份 %s）；发送 /reload confirm 或重启 mosdns 后生效"),
			tag, snap.IPv4Range, cidr, backup), nil
	case "reload", "refresh":
		if rerr := adm.AdminAliasReload(ctx); rerr != nil {
			return "", fmt.Errorf(l.t("reload %s: %w", "重载 %s 失败：%w"), tag, rerr)
		}
		return fmt.Sprintf(l.t("%s reloaded from disk", "%s 已从磁盘重新加载"), tag), nil
	default:
		return aliasUsage(l), nil
	}
}

func aliasDetail(snap aliasadmin.Snapshot, l lang) string {
	form := l.t("append", "追加")
	if snap.ReplaceSuffix {
		form = l.t("replace tld", "替换末级标签")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", snap.Tag)
	fmt.Fprintf(&b, l.t("file: %s\n", "文件：%s\n"), snap.File)
	fmt.Fprintf(&b, l.t("suffix: .%s (%s)\n", "后缀：.%s（%s）\n"), snap.Suffix, form)
	fmt.Fprintf(&b, l.t("range: %s\ndefault scheme: %s\nproxy: %s\nredirect: %s\ntls 443: %s\ndot replacement: %s\nentries: %d\n",
		"网段：%s\n默认协议：%s\n代理：%s\n跳转：%s\nTLS 443：%s\n点替换符：%s\n条目：%d\n"),
		snap.IPv4Range, snap.DefaultScheme, l.yesNo(snap.ProxyActive), l.yesNo(snap.Redirect), l.yesNo(snap.TLS), snap.DotReplacement, snap.Total)
	b.WriteString(l.t("usage: /alias <tag> list|add|del|mod|clear|suffix|range|reload",
		"用法：/alias <tag> list|add|del|mod|clear|suffix|range|reload"))
	b.WriteString("\n")
	b.WriteString(l.t("examples: /alias <tag> add https://ip138.com, /alias <tag> del ip138.com",
		"示例：/alias <tag> add https://ip138.com、/alias <tag> del ip138.com"))
	return b.String()
}

func aliasList(snap aliasadmin.Snapshot, rest []string, l lang) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s  %d", snap.Tag, snap.Total)
	if snap.Total > aliasListLimit {
		fmt.Fprintf(&b, l.t(" (showing first %d)", "（仅显示前 %d 条）"), aliasListLimit)
	}
	for i, e := range snap.Entries {
		if i >= aliasListLimit {
			break
		}
		prefix := ""
		if e.Scheme != snap.DefaultScheme {
			prefix = e.Scheme + "://"
		}
		aliasHost := e.Alias
		if aliasHost == "" {
			// Compatibility fallback for an admin implementation that only
			// returns the real domain.
			aliasHost = e.Domain + "." + snap.Suffix
			if snap.ReplaceSuffix {
				if idx := strings.LastIndexByte(e.Domain, '.'); idx > 0 {
					aliasHost = e.Domain[:idx] + "." + snap.Suffix
				}
			}
		}
		if e.IPv4 != "" {
			fmt.Fprintf(&b, "\n%d. %s%s -> %s (%s)", i+1, prefix, e.Domain, aliasHost, e.IPv4)
			continue
		}
		fmt.Fprintf(&b, "\n%d. %s%s -> %s", i+1, prefix, e.Domain, aliasHost)
	}
	return b.String()
}

func aliasUsage(l lang) string {
	return l.t("usage: /alias <tag> list|add|del|mod|clear|suffix|range|reload",
		"用法：/alias <tag> list|add|del|mod|clear|suffix|range|reload")
}

// persistAliasArg writes one args.<key> of the alias plugin back to the config
// file, so a runtime change survives a restart. The plugin stays authoritative
// for validation; this only records the accepted value.
func (p *telegramBot) persistAliasArg(tag, key, raw string) (string, error) {
	path := p.configPath()
	doc, err := loadConfigDocument(path)
	if err != nil {
		return "", err
	}
	idx := pluginIndexByTag(doc, tag)
	if idx < 0 {
		return "", fmt.Errorf("plugin %q is not declared in %s", tag, path)
	}
	if err := setConfigValue(doc, []string{fmt.Sprintf("plugins[%d]", idx), "args", key}, raw); err != nil {
		return "", err
	}
	return writeConfigDocument(path, doc)
}

// pluginIndexByTag returns the position of a plugin entry in plugins:, or -1.
func pluginIndexByTag(doc *yaml.Node, tag string) int {
	plugins := nodePath(doc, []string{"plugins"})
	if plugins == nil || plugins.Kind != yaml.SequenceNode {
		return -1
	}
	for i, n := range plugins.Content {
		if n.Kind != yaml.MappingNode {
			continue
		}
		for j := 0; j+1 < len(n.Content); j += 2 {
			if n.Content[j].Value == "tag" && n.Content[j+1].Value == tag {
				return i
			}
		}
	}
	return -1
}

// aliasMutationReport appends the purge result of the affected name: a change
// in the list must not leave an answer or a mapping that follows the old rule.
func (p *telegramBot) aliasMutationReport(ctx context.Context, l lang, snap aliasadmin.Snapshot, tag, head, raw string) string {
	real := aliasRuleDomain(raw)
	res := p.purgeDomainData(ctx, real)
	// The answer a client actually asked for is the alias host, and that is
	// the key a cache plugin stores it under, so purge both forms.
	aliasHost := aliasHostFor(snap, real)
	res2 := p.purgeDomainData(ctx, aliasHost)
	res.Mappings += res2.Mappings
	res.RealIPs += res2.RealIPs
	res.Access += res2.Access
	res.Cached += res2.Cached
	res.FakeIP += res2.FakeIP
	res.Caches += res2.Caches
	res.Warnings = append(res.Warnings, res2.Warnings...)
	if head == "" {
		head = tag
	}
	if res.removed() || len(res.Warnings) > 0 {
		head += "\n" + purgeSummary(res, l)
	}
	return head
}

// aliasHostFor renders the served name of a domain for a snapshot.
func aliasHostFor(snap aliasadmin.Snapshot, domainName string) string {
	if snap.DotReplacement != "" && snap.DotReplacement != "." {
		return strings.ReplaceAll(domainName, ".", snap.DotReplacement) + "." + snap.Suffix
	}
	if snap.ReplaceSuffix {
		if idx := strings.LastIndexByte(domainName, '.'); idx > 0 {
			return domainName[:idx] + "." + snap.Suffix
		}
	}
	return domainName + "." + snap.Suffix
}

// aliasRuleDomain turns one "[scheme://]domain" argument into its domain.
func aliasRuleDomain(raw string) string {
	value := strings.TrimSpace(raw)
	if idx := strings.Index(value, "://"); idx >= 0 {
		value = value[idx+3:]
	}
	return domain.NormalizeDomain(value)
}
