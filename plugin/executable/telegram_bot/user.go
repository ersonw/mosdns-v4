package telegram_bot

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/timeutil"
	"github.com/ersonw/mosdns-v4/plugin/executable/radius"
)

const userHelp = `radius account commands (optional tag first, e.g. /user radius2 list)
/user tags                     configured targets
/user list                     accounts: name, group, state
/user add <name> <pass> [grp]  create an account
/user del <name>               delete an account
/user pass <name> <pass>       replace the password
/user enable <name>            allow authentication
/user disable <name>           block authentication, keep the row
/user group <name> <group>     set the ocserv group (class attribute)
/user ip <name> <ipv4|->       pin or clear a fixed VPN IP (Framed-IP)
/user sessions [active] [n]    accounting sessions, newest first
/user limit <name> <max|0|-> [period]  set total quota (0/- = unlimited)
                               period: 30d, 168h, 0/- = never reset, omit = keep
/user usage <name>            used up/down, limit and next reset
/user reset <name>            clear usage now, start a new period`

const userHelpZH = `radius 账号命令（可选 tag 放在最前，例如 /user radius2 list）
/user tags                    已配置的目标
/user list                    账号：名称、组、状态
/user add <name> <pass> [grp] 创建账号
/user del <name>              删除账号
/user pass <name> <pass>      替换密码
/user enable <name>           允许认证
/user disable <name>          禁止认证，保留记录
/user group <name> <group>    设置 ocserv 组（Class 属性）
/user ip <name> <ipv4|->      固定或清除 VPN IP（Framed-IP）
/user sessions [active] [n]   记账会话，最新在前
/user limit <name> <max|0|-> [period]  设置总配额（0/- = 无限制）
                               period：30d、168h、0/- = 永不重置，省略 = 保持
/user usage <name>            上下行用量、上限和下次重置
/user reset <name>            立即清空用量并开始新周期`

// resolveRadiusFor finds the radius plugin that owns the account table. Lookup
// is lazy and cached per tag, same as the fakeip and ocserv resolvers.
func (p *telegramBot) resolveRadiusFor(tag string, langs ...lang) (radius.Admin, error) {
	l := replyLang(langs)
	p.radiusMu.Lock()
	defer p.radiusMu.Unlock()
	if p.radius != nil {
		return p.radius, nil // injected by a test
	}
	if a, ok := p.radiusCache[tag]; ok {
		return a, nil
	}

	e, ok := p.M().GetExecutables()[tag]
	if !ok {
		return nil, fmt.Errorf(l.t("plugin %q is not loaded", "插件 %q 未加载"), tag)
	}
	a, ok := e.(radius.Admin)
	if !ok {
		return nil, fmt.Errorf(l.t("plugin %q is not a radius plugin", "插件 %q 不是 radius 插件"), tag)
	}
	p.radiusCache[tag] = a
	return a, nil
}

// handleUser manages RADIUS accounts through the radius plugin.
func (p *telegramBot) handleUser(args []string, langs ...lang) string {
	l := replyLang(langs)
	tag, rest := pickTag(p.args.RadiusTags, args)
	if len(rest) == 0 || rest[0] == "help" {
		return l.t(userHelp, userHelpZH)
	}
	if rest[0] == "tags" {
		return l.t("radius targets: ", "radius 目标：") + strings.Join(p.args.RadiusTags, ", ")
	}

	adm, err := p.resolveRadiusFor(tag, l)
	if err != nil {
		return err.Error()
	}
	loc := p.locationFor(adm)

	switch rest[0] {
	case "list":
		users, err := adm.Users()
		if err != nil {
			return l.t("list failed: ", "列表失败：") + err.Error()
		}
		return formatUsers(tag, users, loc, l)

	case "add":
		if len(rest) < 3 {
			return l.t("usage: /user add <name> <password> [group]",
				"用法：/user add <name> <password> [group]")
		}
		group := ""
		if len(rest) > 3 {
			group = rest[3]
		}
		if err := adm.AddUser(rest[1], rest[2], group); err != nil {
			return l.t("add failed: ", "添加失败：") + err.Error()
		}
		if group != "" {
			return l.t(fmt.Sprintf("added %s (group %s)", rest[1], group),
				fmt.Sprintf("已添加 %s（组 %s）", rest[1], group))
		}
		return l.t("added "+rest[1], "已添加 "+rest[1])

	case "del":
		if len(rest) < 2 {
			return l.t("usage: /user del <name>", "用法：/user del <name>")
		}
		ok, err := adm.DeleteUser(rest[1])
		if err != nil {
			return l.t("delete failed: ", "删除失败：") + err.Error()
		}
		if !ok {
			return l.t("no such user: "+rest[1], "没有这个用户："+rest[1])
		}
		return l.t("deleted "+rest[1], "已删除 "+rest[1])

	case "pass":
		if len(rest) < 3 {
			return l.t("usage: /user pass <name> <password>",
				"用法：/user pass <name> <password>")
		}
		ok, err := adm.SetPassword(rest[1], rest[2])
		if err != nil {
			return l.t("password change failed: ", "修改密码失败：") + err.Error()
		}
		if !ok {
			return l.t("no such user: "+rest[1], "没有这个用户："+rest[1])
		}
		return l.t("password changed for "+rest[1], "已修改密码："+rest[1])

	case "enable", "disable":
		if len(rest) < 2 {
			return l.t("usage: /user "+rest[0]+" <name>", "用法：/user "+rest[0]+" <name>")
		}
		ok, err := adm.SetEnabled(rest[1], rest[0] == "enable")
		if err != nil {
			return l.t("toggle failed: ", "切换失败：") + err.Error()
		}
		if !ok {
			return l.t("no such user: "+rest[1], "没有这个用户："+rest[1])
		}
		if rest[0] == "enable" {
			return l.t(rest[1]+": enabled", rest[1]+"：已启用")
		}
		return l.t(rest[1]+": disabled", rest[1]+"：已禁用")

	case "group":
		if len(rest) < 3 {
			return l.t("usage: /user group <name> <group>", "用法：/user group <name> <group>")
		}
		setter, ok := adm.(interface {
			SetGroup(name, group string) (bool, error)
		})
		if !ok {
			return l.t("this radius plugin cannot set groups", "这个 radius 插件不支持设置组")
		}
		changed, err := setter.SetGroup(rest[1], rest[2])
		if err != nil {
			return l.t("group change failed: ", "修改组失败：") + err.Error()
		}
		if !changed {
			return l.t("no such user: "+rest[1], "没有这个用户："+rest[1])
		}
		return l.t(fmt.Sprintf("%s: group %s", rest[1], rest[2]),
			fmt.Sprintf("%s：组 %s", rest[1], rest[2]))

	case "ip":
		if len(rest) < 3 {
			return l.t("usage: /user ip <name> <ipv4|->", "用法：/user ip <name> <ipv4|->")
		}
		ok, err := adm.SetIP(rest[1], rest[2])
		if err != nil {
			return l.t("ip change failed: ", "修改 IP 失败：") + err.Error()
		}
		if !ok {
			return l.t("no such user: "+rest[1], "没有这个用户："+rest[1])
		}
		if rest[2] == "-" || rest[2] == "" {
			return l.t(rest[1]+": fixed ip cleared", rest[1]+"：已清除固定 IP")
		}
		return l.t(fmt.Sprintf("%s: fixed ip %s", rest[1], rest[2]),
			fmt.Sprintf("%s：固定 IP %s", rest[1], rest[2]))

	case "limit":
		if len(rest) < 3 {
			return l.t("usage: /user limit <name> <max|0|-> [period|0|-]",
				"用法：/user limit <name> <max|0|-> [period|0|-]")
		}
		maxTotal, err := parseByteSize(rest[2], l)
		if err != nil {
			return l.t("limit failed: ", "设置配额失败：") + err.Error()
		}
		period := int64(-1) // omitted: keep the account's current period
		if len(rest) > 3 {
			period, err = parseResetPeriod(rest[3], l)
			if err != nil {
				return l.t("limit failed: ", "设置配额失败：") + err.Error()
			}
		}
		ok, err := adm.SetQuota(rest[1], maxTotal, period)
		if err != nil {
			return l.t("limit failed: ", "设置配额失败：") + err.Error()
		}
		if !ok {
			return l.t(rest[1]+": no such user", rest[1]+"：没有这个用户")
		}
		reset := l.t("unchanged", "不变")
		if period >= 0 {
			reset = formatPeriod(period, l)
		}
		return l.t(fmt.Sprintf("%s: max=%s reset=%s", rest[1], formatLimit(maxTotal, l), reset),
			fmt.Sprintf("%s：上限=%s 重置=%s", rest[1], formatLimit(maxTotal, l), reset))

	case "usage":
		if len(rest) < 2 {
			return l.t("usage: /user usage <name>", "用法：/user usage <name>")
		}
		users, err := adm.Users()
		if err != nil {
			return l.t("usage failed: ", "查询用量失败：") + err.Error()
		}
		for _, u := range users {
			if strings.EqualFold(u.Name, rest[1]) {
				return formatUsage(tag, u, loc, l)
			}
		}
		return l.t(rest[1]+": no such user", rest[1]+"：没有这个用户")

	case "reset":
		if len(rest) < 2 {
			return l.t("usage: /user reset <name>", "用法：/user reset <name>")
		}
		ok, err := adm.ResetQuota(rest[1])
		if err != nil {
			return l.t("reset failed: ", "重置失败：") + err.Error()
		}
		if !ok {
			return l.t(rest[1]+": no such user", rest[1]+"：没有这个用户")
		}
		return l.t(rest[1]+": usage cleared, new period started",
			rest[1]+"：用量已清空，新周期已开始")

	case "sessions":
		activeOnly := false
		limit := 20
		for _, a := range rest[1:] {
			switch {
			case a == "active" || a == "--active":
				activeOnly = true
			default:
				if n, err := parseIntArg(a); err == nil {
					limit = n
				}
			}
		}
		rows, err := adm.Sessions(activeOnly, limit)
		if err != nil {
			return l.t("sessions failed: ", "查询会话失败：") + err.Error()
		}
		return formatSessions(tag, rows, activeOnly, loc, l)
	}
	return l.t("unknown user subcommand, send /user help", "未知用户子命令，请发送 /user help")
}

func parseIntArg(s string) (int, error) {
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, fmt.Errorf("not a positive number")
	}
	if n > 500 {
		n = 500
	}
	return n, nil
}

func formatUsers(tag string, users []radius.User, loc *time.Location, langs ...lang) string {
	l := replyLang(langs)
	if len(users) == 0 {
		return l.t(fmt.Sprintf("users on %s: none", tag), fmt.Sprintf("%s 上没有用户", tag))
	}
	var b strings.Builder
	fmt.Fprintf(&b, l.t("users on %s (%d)\n", "%s 上的用户（%d）\n"), tag, len(users))
	for _, u := range users {
		state := l.t("enabled", "启用")
		if !u.Enabled {
			state = l.t("disabled", "禁用")
			if u.QuotaDisabled {
				state = l.t("quota-blocked", "配额限制")
			}
		}
		group := u.Group
		if group == "" {
			group = "-"
		}
		ip := u.IP
		if ip == "" {
			ip = "-"
		}
		fmt.Fprintf(&b, l.t("%-20s group=%-12s ip=%-15s %s used=%s/%s reset=%s updated %s\n",
			"%-20s 组=%-12s IP=%-15s %s 已用=%s/%s 重置=%s 更新 %s\n"),
			u.Name, group, ip, state, formatOctets(u.UsedIn+u.UsedOut), formatLimit(u.MaxTotal, l),
			formatPeriod(u.ResetPeriod, l), timeutil.FormatUnix(u.UpdatedAt, "2006-01-02 15:04", loc))
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatSessions(tag string, rows []radius.Session, activeOnly bool, loc *time.Location, langs ...lang) string {
	l := replyLang(langs)
	if len(rows) == 0 {
		if activeOnly {
			return l.t(fmt.Sprintf("sessions on %s: none active", tag), fmt.Sprintf("%s 上没有活动会话", tag))
		}
		return l.t(fmt.Sprintf("sessions on %s: none", tag), fmt.Sprintf("%s 上没有会话", tag))
	}
	var b strings.Builder
	fmt.Fprintf(&b, l.t("sessions on %s (%d)\n", "%s 上的会话（%d）\n"), tag, len(rows))
	for _, s := range rows {
		state := l.t("closed", "已关闭")
		if s.Active {
			state = l.t("active", "活动")
		}
		fmt.Fprintf(&b, l.t("%-16s %-20s %-16s %s  in=%s out=%s %s\n",
			"%-16s %-20s %-16s %s  上行=%s 下行=%s %s\n"),
			s.SessionID, s.Name, s.RemoteIP,
			timeutil.FormatUnix(s.StartedAt, "2006-01-02 15:04", loc),
			formatOctets(s.In), formatOctets(s.Out), state)
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatOctets(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 3; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGT"[exp])
}

// formatLimit renders a byte limit; zero means unlimited.
func formatLimit(n int64, langs ...lang) string {
	l := replyLang(langs)
	if n <= 0 {
		return l.t("unlimited", "无限制")
	}
	return formatOctets(n)
}

// formatPeriod renders a reset period in seconds; zero means no reset.
func formatPeriod(seconds int64, langs ...lang) string {
	l := replyLang(langs)
	if seconds <= 0 {
		return l.t("none", "永不重置")
	}
	d := time.Duration(seconds) * time.Second
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf(l.t("%dd", "%d天"), int64(d/(24*time.Hour)))
	}
	return d.String()
}

// formatUsage shows the per-direction counters of one account.
func formatUsage(tag string, u radius.User, loc *time.Location, langs ...lang) string {
	l := replyLang(langs)
	state := l.t("enabled", "启用")
	if !u.Enabled {
		state = l.t("disabled", "禁用")
		if u.QuotaDisabled {
			state = l.t("quota-blocked", "配额限制")
		}
	}
	remaining := l.t("unlimited", "无限制")
	if u.MaxTotal > 0 {
		left := u.MaxTotal - u.UsedIn - u.UsedOut
		if left < 0 {
			left = 0
		}
		remaining = formatOctets(left)
	}
	next := l.t("none", "无")
	if u.ResetPeriod > 0 && u.PeriodStart > 0 {
		next = timeutil.FormatUnix(u.PeriodStart+u.ResetPeriod, "2006-01-02 15:04", loc)
	}
	var b strings.Builder
	fmt.Fprintf(&b, l.t("%s on %s: %s\n", "%s（%s）：%s\n"), u.Name, tag, state)
	fmt.Fprintf(&b, l.t("up: %s\ndown: %s\ntotal: %s / %s\n",
		"上行：%s\n下行：%s\n总计：%s / %s\n"),
		formatOctets(u.UsedIn), formatOctets(u.UsedOut),
		formatOctets(u.UsedIn+u.UsedOut), formatLimit(u.MaxTotal, l))
	fmt.Fprintf(&b, l.t("remaining: %s\nreset period: %s\nnext reset: %s",
		"剩余：%s\n重置周期：%s\n下次重置：%s"),
		remaining, formatPeriod(u.ResetPeriod, l), next)
	return b.String()
}

// parseByteSize accepts 0, -, unlimited, a bare byte count, or an integer with
// a binary unit: 100MB, 10GB, 1TiB.
func parseByteSize(s string, langs ...lang) (int64, error) {
	l := replyLang(langs)
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "", "0", "-", "none", "unlimited":
		return 0, nil
	}
	units := []struct {
		suffix string
		mul    int64
	}{
		{"tib", 1 << 40}, {"tb", 1 << 40}, {"ti", 1 << 40}, {"t", 1 << 40},
		{"gib", 1 << 30}, {"gb", 1 << 30}, {"gi", 1 << 30}, {"g", 1 << 30},
		{"mib", 1 << 20}, {"mb", 1 << 20}, {"mi", 1 << 20}, {"m", 1 << 20},
		{"kib", 1 << 10}, {"kb", 1 << 10}, {"ki", 1 << 10}, {"k", 1 << 10},
		{"b", 1},
	}
	number, mul := s, int64(1)
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			number = strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			mul = u.mul
			break
		}
	}
	n, err := strconv.ParseInt(number, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf(l.t("invalid size %q, use e.g. 10GB, 500MB, 0",
			"无效大小 %q，例如 10GB、500MB、0"), s)
	}
	if n > math.MaxInt64/mul {
		return 0, fmt.Errorf(l.t("size %q is too large", "大小 %q 超出范围"), s)
	}
	return n * mul, nil
}

// parseResetPeriod accepts 0, -, none, a Go duration (168h), or d/w suffixes.
func parseResetPeriod(s string, langs ...lang) (int64, error) {
	l := replyLang(langs)
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "", "0", "-", "none", "never":
		return 0, nil
	}
	mult := int64(0)
	switch {
	case strings.HasSuffix(s, "d"):
		mult = 24 * 60 * 60
	case strings.HasSuffix(s, "w"):
		mult = 7 * 24 * 60 * 60
	}
	if mult > 0 {
		n, err := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(s, s[len(s)-1:])), 10, 64)
		if err != nil || n < 0 {
			return 0, fmt.Errorf(l.t("invalid period %q, use e.g. 30d, 168h, 0",
				"无效周期 %q，例如 30d、168h、0"), s)
		}
		if n > math.MaxInt64/mult {
			return 0, fmt.Errorf(l.t("period %q is too large", "周期 %q 超出范围"), s)
		}
		return n * mult, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf(l.t("invalid period %q, use e.g. 30d, 168h, 0",
			"无效周期 %q，例如 30d、168h、0"), s)
	}
	return int64(d / time.Second), nil
}
