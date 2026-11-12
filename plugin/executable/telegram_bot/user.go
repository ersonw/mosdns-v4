package telegram_bot

import (
	"fmt"
	"strings"
	"time"

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
/user sessions [active] [n]    accounting sessions, newest first`

// resolveRadiusFor finds the radius plugin that owns the account table. Lookup
// is lazy and cached per tag, same as the fakeip and ocserv resolvers.
func (p *telegramBot) resolveRadiusFor(tag string) (radius.Admin, error) {
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
		return nil, fmt.Errorf("plugin %q is not loaded", tag)
	}
	a, ok := e.(radius.Admin)
	if !ok {
		return nil, fmt.Errorf("plugin %q is not a radius plugin", tag)
	}
	p.radiusCache[tag] = a
	return a, nil
}

// handleUser manages RADIUS accounts through the radius plugin.
func (p *telegramBot) handleUser(args []string) string {
	tag, rest := pickTag(p.args.RadiusTags, args)
	if len(rest) == 0 || rest[0] == "help" {
		return userHelp
	}
	if rest[0] == "tags" {
		return "radius targets: " + strings.Join(p.args.RadiusTags, ", ")
	}

	adm, err := p.resolveRadiusFor(tag)
	if err != nil {
		return err.Error()
	}

	switch rest[0] {
	case "list":
		users, err := adm.Users()
		if err != nil {
			return "list failed: " + err.Error()
		}
		return formatUsers(tag, users)

	case "add":
		if len(rest) < 3 {
			return "usage: /user add <name> <password> [group]"
		}
		group := ""
		if len(rest) > 3 {
			group = rest[3]
		}
		if err := adm.AddUser(rest[1], rest[2], group); err != nil {
			return "add failed: " + err.Error()
		}
		if group != "" {
			return fmt.Sprintf("added %s (group %s)", rest[1], group)
		}
		return "added " + rest[1]

	case "del":
		if len(rest) < 2 {
			return "usage: /user del <name>"
		}
		ok, err := adm.DeleteUser(rest[1])
		if err != nil {
			return "delete failed: " + err.Error()
		}
		if !ok {
			return "no such user: " + rest[1]
		}
		return "deleted " + rest[1]

	case "pass":
		if len(rest) < 3 {
			return "usage: /user pass <name> <password>"
		}
		ok, err := adm.SetPassword(rest[1], rest[2])
		if err != nil {
			return "password change failed: " + err.Error()
		}
		if !ok {
			return "no such user: " + rest[1]
		}
		return "password changed for " + rest[1]

	case "enable", "disable":
		if len(rest) < 2 {
			return "usage: /user " + rest[0] + " <name>"
		}
		ok, err := adm.SetEnabled(rest[1], rest[0] == "enable")
		if err != nil {
			return "toggle failed: " + err.Error()
		}
		if !ok {
			return "no such user: " + rest[1]
		}
		return fmt.Sprintf("%s: %sd", rest[1], strings.TrimSuffix(rest[0], "e")+"e")

	case "group":
		if len(rest) < 3 {
			return "usage: /user group <name> <group>"
		}
		setter, ok := adm.(interface {
			SetGroup(name, group string) (bool, error)
		})
		if !ok {
			return "this radius plugin cannot set groups"
		}
		changed, err := setter.SetGroup(rest[1], rest[2])
		if err != nil {
			return "group change failed: " + err.Error()
		}
		if !changed {
			return "no such user: " + rest[1]
		}
		return fmt.Sprintf("%s: group %s", rest[1], rest[2])

	case "ip":
		if len(rest) < 3 {
			return "usage: /user ip <name> <ipv4|->"
		}
		ok, err := adm.SetIP(rest[1], rest[2])
		if err != nil {
			return "ip change failed: " + err.Error()
		}
		if !ok {
			return "no such user: " + rest[1]
		}
		if rest[2] == "-" || rest[2] == "" {
			return rest[1] + ": fixed ip cleared"
		}
		return fmt.Sprintf("%s: fixed ip %s", rest[1], rest[2])

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
			return "sessions failed: " + err.Error()
		}
		return formatSessions(tag, rows, activeOnly)
	}
	return "unknown user subcommand, send /user help"
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

func formatUsers(tag string, users []radius.User) string {
	if len(users) == 0 {
		return fmt.Sprintf("users on %s: none", tag)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "users on %s (%d)\n", tag, len(users))
	for _, u := range users {
		state := "enabled"
		if !u.Enabled {
			state = "disabled"
		}
		group := u.Group
		if group == "" {
			group = "-"
		}
		ip := u.IP
		if ip == "" {
			ip = "-"
		}
		fmt.Fprintf(&b, "%-20s group=%-12s ip=%-15s %s  updated %s\n",
			u.Name, group, ip, state, time.Unix(u.UpdatedAt, 0).Format("2006-01-02 15:04"))
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatSessions(tag string, rows []radius.Session, activeOnly bool) string {
	if len(rows) == 0 {
		if activeOnly {
			return fmt.Sprintf("sessions on %s: none active", tag)
		}
		return fmt.Sprintf("sessions on %s: none", tag)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "sessions on %s (%d)\n", tag, len(rows))
	for _, s := range rows {
		state := "closed"
		if s.Active {
			state = "active"
		}
		fmt.Fprintf(&b, "%-16s %-20s %-16s %s  in=%s out=%s %s\n",
			s.SessionID, s.Name, s.RemoteIP,
			time.Unix(s.StartedAt, 0).Format("2006-01-02 15:04"),
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
