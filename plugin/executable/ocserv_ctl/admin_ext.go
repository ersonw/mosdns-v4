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

package ocserv_ctl

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"go.uber.org/zap"
)

// AdminReload asks systemd to reload ocserv. Reload re-reads the configuration
// without dropping connected users.
func (p *ocservCtl) AdminReload(ctx context.Context) (string, error) {
	return p.systemctl(ctx, "reload")
}

// AdminRestart restarts ocserv through systemd. Every connected user is
// dropped; disable_restart can block this when the bot is exposed to operators
// who should not be able to kick the whole server.
func (p *ocservCtl) AdminRestart(ctx context.Context) (string, error) {
	if p.args.DisabledRestart {
		return "", fmt.Errorf("restart is disabled by disable_restart: true")
	}
	return p.systemctl(ctx, "restart")
}

func (p *ocservCtl) systemctl(parent context.Context, action string) (string, error) {
	unit := strings.TrimSpace(p.args.SystemdUnit)
	if unit == "" {
		return "", fmt.Errorf("systemd_unit is not set")
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(p.args.Timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, p.args.SystemctlPath, action, unit)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if msg == "" {
			msg = err.Error()
		}
		return msg, fmt.Errorf("systemctl %s %s: %s", action, unit, msg)
	}
	msg := strings.TrimSpace(out.String())
	if msg == "" {
		msg = fmt.Sprintf("%s %s: ok", action, unit)
	}
	p.L().Info("ocserv service controlled",
		zap.String("action", action), zap.String("unit", unit))
	return msg, nil
}

// AdminPool prints the lease pool parsed from ocserv.conf and every address
// currently known to be taken, either pinned in config-per-user or held by an
// online session.
func (p *ocservCtl) AdminPool(ctx context.Context) (string, error) {
	conf, pool, err := p.loadPool()
	if err != nil {
		return "", err
	}
	used, err := poolUsage(conf.ConfigPerUser, p.onlineUsers(ctx))
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "config: %s", conf.Path)
	fmt.Fprintf(&b, "\nnetwork: %s", pool.IPNet.String())
	fmt.Fprintf(&b, "\nserver address (reserved): %s", pool.Server)
	fmt.Fprintf(&b, "\nleases: %s - %s", pool.First, pool.Last)
	if conf.ConfigPerUser == "" {
		b.WriteString("\nconfig-per-user: (not set, allocation unavailable)")
	} else {
		fmt.Fprintf(&b, "\nconfig-per-user: %s", conf.ConfigPerUser)
	}
	fmt.Fprintf(&b, "\nin use (%d):\n%s", len(used), formatIPList(used))
	return b.String(), nil
}

// AdminAllocIP pins an address for a user by writing explicit-ipv4 into the
// config-per-user file. An empty want means "pick the lowest free address".
// The change takes effect on the next ocserv reload.
func (p *ocservCtl) AdminAllocIP(ctx context.Context, user, want string) (string, error) {
	if !validUser(user) {
		return "", fmt.Errorf("invalid user name %q", user)
	}
	conf, pool, err := p.loadPool()
	if err != nil {
		return "", err
	}
	if conf.ConfigPerUser == "" {
		return "", fmt.Errorf("ocserv.conf has no config-per-user directory, cannot pin addresses")
	}

	p.allocMu.Lock()
	defer p.allocMu.Unlock()

	byIP, byUser, err := explicitIPs(conf.ConfigPerUser)
	if err != nil {
		return "", err
	}
	used, err := poolUsage(conf.ConfigPerUser, p.onlineUsers(ctx))
	if err != nil {
		return "", err
	}

	var ip net.IP
	if want != "" {
		ip, err = parseIPv4(want)
		if err != nil {
			return "", err
		}
		if !pool.contains(ip) {
			return "", fmt.Errorf("%s is outside the lease range %s - %s", ip, pool.First, pool.Last)
		}
		if owner, ok := byIP[ip.String()]; ok && owner != user {
			return "", fmt.Errorf("%s is already assigned to %s", ip, owner)
		}
		if holder, ok := used[ip.String()]; ok && holder != user {
			return "", fmt.Errorf("%s is in use by %s", ip, holder)
		}
	} else {
		if cur, ok := byUser[user]; ok {
			return fmt.Sprintf("%s already has %s", user, cur), nil
		}
		usedMap := make(map[string]bool, len(used))
		for usedIP := range used {
			usedMap[usedIP] = true
		}
		usedMap[pool.Server.String()] = true
		ip, err = pool.allocate(usedMap)
		if err != nil {
			return "", err
		}
	}

	if err := writeExplicitIP(conf.ConfigPerUser, user, ip); err != nil {
		return "", err
	}
	p.L().Info("ocserv user address pinned",
		zap.String("user", user), zap.String("ip", ip.String()), zap.String("config", conf.Path))
	return fmt.Sprintf("assigned %s to %s; run /vpn reload to apply", ip, user), nil
}

// AdminReleaseIP removes a pinned address. A user without one is not an error.
func (p *ocservCtl) AdminReleaseIP(ctx context.Context, user string) (string, error) {
	if !validUser(user) {
		return "", fmt.Errorf("invalid user name %q", user)
	}
	conf, _, err := p.loadPool()
	if err != nil {
		return "", err
	}
	if conf.ConfigPerUser == "" {
		return "", fmt.Errorf("ocserv.conf has no config-per-user directory")
	}

	p.allocMu.Lock()
	defer p.allocMu.Unlock()

	_, byUser, err := explicitIPs(conf.ConfigPerUser)
	if err != nil {
		return "", err
	}
	ip, ok := byUser[user]
	if !ok {
		return fmt.Sprintf("%s has no pinned address", user), nil
	}
	if _, err := removeExplicitIP(conf.ConfigPerUser, user); err != nil {
		return "", err
	}
	p.L().Info("ocserv user address released", zap.String("user", user), zap.String("ip", ip))
	return fmt.Sprintf("released %s from %s; run /vpn reload to apply", ip, user), nil
}

func (p *ocservCtl) loadPool() (*ocservConf, *ipv4Pool, error) {
	if strings.TrimSpace(p.args.ConfigPath) == "" {
		return nil, nil, fmt.Errorf("config_path is not set")
	}
	conf, err := readOcservConf(p.args.ConfigPath)
	if err != nil {
		return nil, nil, err
	}
	pool, err := conf.pool()
	if err != nil {
		return nil, nil, err
	}
	return conf, pool, nil
}

// onlineUsers returns the current occtl snapshot, or nil when occtl is not
// configured or not reachable. Allocation must not fail just because the
// control socket is down.
func (p *ocservCtl) onlineUsers(ctx context.Context) []ocservUser {
	if !p.args.enabled() || !p.available() {
		return nil
	}
	return p.table(ctx)
}
