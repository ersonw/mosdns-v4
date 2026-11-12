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

// This file maps an administrator chat to a role, and a role to the command
// groups it may use. A role can inherit other roles, so permissions compose:
// a role that inherits "fakeip_admin" and adds "exec_script" may manage fakeip
// and trigger scripts but still cannot touch ocserv or the config file.

package telegram_bot

import (
	"fmt"
	"sort"
	"strings"
)

// Permission names. Each one gates a command group, not a single command, so
// the config stays readable.
const (
	PermStatus     = "status"      // /status, /plugins, /plugin, /perm, /help
	PermFakeIP     = "fakeip"      // /fip and its short aliases
	PermOcserv     = "ocserv"      // /vpn
	PermRadius     = "radius"      // /user
	PermConfig     = "config"      // /config read and write
	PermProvider   = "provider"    // /provider data source management
	PermReload     = "reload"      // /reload confirm
	PermExecScript = "exec_script" // /exec <tag> <ip> <domain>
	PermAccess     = "access"      // /access <user> [days]: export visit records

	// PermAll is the wildcard a role may write in allow to mean "everything".
	PermAll = "all"
)

// Built-in roles. They are not declared under roles:, they always exist,
// and a config role may inherit them.
const (
	// RoleAdmin observes: status, user management, ocserv, the access record
	// export and data_providers domain lists. It cannot touch the config file,
	// run scripts, reload the process or rewrite fakeip mappings.
	RoleAdmin = "admin"
	// RoleSuperAdmin inherits RoleAdmin and adds every remaining permission.
	RoleSuperAdmin = "superadmin"
)

// allPermissions is the canonical list used to validate role allow entries.
var allPermissions = []string{
	PermStatus,
	PermFakeIP,
	PermOcserv,
	PermRadius,
	PermConfig,
	PermProvider,
	PermReload,
	PermExecScript,
	PermAccess,
}

// adminPermissions is the built-in plain administrator: see everything, manage
// people, the VPN session set and the data_providers domain lists, but never
// change how the process runs or rewrite the config file.
var adminPermissions = []string{
	PermStatus,
	PermOcserv,
	PermRadius,
	PermAccess,
	PermProvider,
}

// superAdminPermissions is explicit inheritance: everything admin may do, plus
// the remaining write/control permissions. Adding a permission to
// adminPermissions therefore also grants it to superadmin.
var superAdminPermissions = unionPermissions(adminPermissions, allPermissions)

func unionPermissions(lists ...[]string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, list := range lists {
		for _, p := range list {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// AdminUser binds one Telegram chat to a role.
type AdminUser struct {
	ChatID int64  `yaml:"chat_id"`
	Role   string `yaml:"role"`
}

// Role is one named permission set. Inherits pulls in other roles, allow adds
// its own permissions; both are unioned.
type Role struct {
	Inherits []string `yaml:"inherits"`
	Allow    []string `yaml:"allow"`
}

type accessTable struct {
	perms map[int64]map[string]bool
	roles map[int64]string
}

func permissionSet(list ...string) map[string]bool {
	set := make(map[string]bool, len(list))
	for _, p := range list {
		set[p] = true
	}
	return set
}

func validPermission(p string) bool {
	if p == PermAll {
		return true
	}
	for _, known := range allPermissions {
		if known == p {
			return true
		}
	}
	return false
}

// buildAccess resolves the roles into a per-chat permission set once at
// startup, so a command check never walks the inheritance graph.
//
// Two roles are built in and need no declaration: "superadmin" holds every
// permission, "admin" only observes and manages people plus data_providers
// domain lists (status, ocserv, radius, access, provider). Every chat in
// chat_ids gets default_role, which defaults to "admin".
func buildAccess(args *Args) (*accessTable, error) {
	t := &accessTable{
		perms: make(map[int64]map[string]bool),
		roles: make(map[int64]string),
	}

	resolved := make(map[string]map[string]bool)
	var resolve func(name string, stack []string) (map[string]bool, error)
	resolve = func(name string, stack []string) (map[string]bool, error) {
		if set, ok := resolved[name]; ok {
			return set, nil
		}
		for _, seen := range stack {
			if seen == name {
				return nil, fmt.Errorf("role %q inherits itself (%s)", name, strings.Join(stack, " -> "))
			}
		}

		switch name {
		case "", RoleSuperAdmin, PermAll:
			set := permissionSet(superAdminPermissions...)
			resolved[name] = set
			return set, nil
		case RoleAdmin:
			set := permissionSet(adminPermissions...)
			resolved[name] = set
			return set, nil
		}

		role, ok := args.Roles[name]
		if !ok {
			return nil, fmt.Errorf("role %q is not defined under roles", name)
		}

		set := make(map[string]bool)
		for _, p := range role.Allow {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			// "all" is the documented wildcard; "admin" is accepted because
			// older configs used it in allow lists to mean the same thing.
			if p == PermAll || p == RoleAdmin {
				for _, known := range allPermissions {
					set[known] = true
				}
				continue
			}
			if !validPermission(p) {
				return nil, fmt.Errorf("role %q has unknown permission %q (known: %s)",
					name, p, strings.Join(append(allPermissions, PermAll), ", "))
			}
			set[p] = true
		}
		for _, parent := range role.Inherits {
			parent = strings.TrimSpace(parent)
			if parent == "" {
				continue
			}
			parentSet, err := resolve(parent, append(stack, name))
			if err != nil {
				return nil, err
			}
			for p := range parentSet {
				set[p] = true
			}
		}
		resolved[name] = set
		return set, nil
	}

	add := func(chatID int64, role string) error {
		set, err := resolve(role, nil)
		if err != nil {
			return err
		}
		t.perms[chatID] = set
		t.roles[chatID] = role
		return nil
	}

	for _, a := range args.Admins {
		if a.ChatID == 0 {
			return nil, fmt.Errorf("admins entry has no chat_id")
		}
		role := strings.TrimSpace(a.Role)
		if role == "" {
			role = args.DefaultRole
		}
		if err := add(a.ChatID, role); err != nil {
			return nil, err
		}
	}
	for _, id := range args.ChatIDs {
		if _, ok := t.perms[id]; ok {
			continue
		}
		if err := add(id, args.DefaultRole); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func (t *accessTable) allowed(chatID int64, perm string) bool {
	set, ok := t.perms[chatID]
	if !ok {
		return false
	}
	return set[perm] || set[PermAll]
}

func (t *accessTable) permissionNames(chatID int64) string {
	set := t.perms[chatID]
	var names []string
	for p, on := range set {
		if on {
			names = append(names, p)
		}
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// requiredPermission maps a command to the permission that gates it. Unknown
// commands need only the status permission, so a typo cannot be used to probe
// what a role can do.
func requiredPermission(cmd string) string {
	switch cmd {
	case "/start", "/help":
		// Help describes what a chat may do, so it must never be gated on one
		// of those permissions.
		return ""
	case "/fip", "/list", "/stats", "/lookup", "/rev", "/del", "/clear":
		return PermFakeIP
	case "/vpn":
		return PermOcserv
	case "/user":
		return PermRadius
	case "/access":
		return PermAccess
	case "/config", "/proxy", "/sweep":
		return PermConfig
	case "/provider":
		return PermProvider
	case "/diag":
		return PermFakeIP
	case "/reload":
		return PermReload
	case "/exec":
		return PermExecScript
	}
	return PermStatus
}

func (p *telegramBot) require(chatID int64, perm string, langs ...lang) error {
	l := replyLang(langs)
	if p.access == nil {
		return nil
	}
	if _, ok := p.access.perms[chatID]; !ok {
		return fmt.Errorf(l.t("permission denied: chat %d is not an administrator",
			"权限不足：聊天 %d 不是管理员"), chatID)
	}
	if perm == "" || p.access.allowed(chatID, perm) {
		return nil
	}
	return fmt.Errorf(l.t("permission denied: role %q lacks %q (allowed: %s)",
		"权限不足：角色 %q 缺少 %q（允许：%s）"),
		p.access.roles[chatID], perm, p.access.permissionNames(chatID))
}

func (p *telegramBot) handlePerm(chatID int64, langs ...lang) string {
	l := replyLang(langs)
	if p.access == nil {
		return l.t("permissions are not configured", "未配置权限")
	}
	return fmt.Sprintf(l.t("chat_id: %d\nrole: %s\npermissions: %s",
		"chat_id：%d\n角色：%s\n权限：%s"),
		chatID, p.access.roles[chatID], p.access.permissionNames(chatID))
}
