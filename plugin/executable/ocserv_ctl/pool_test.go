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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConf(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "ocserv.conf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write conf: %v", err)
	}
	return path
}

func poolArgs(t *testing.T) (*Args, string) {
	t.Helper()
	dir := t.TempDir()
	perUser := filepath.Join(dir, "config-per-user")
	conf := writeConf(t, dir, "ipv4-network = 10.8.0.0/24\nconfig-per-user = "+perUser+"\n")
	return &Args{ConfigPath: conf}, perUser
}

func TestPoolParsesCIDR(t *testing.T) {
	args, _ := poolArgs(t)
	p := newTestPlugin(t, args)
	_, pool, err := p.loadPool()
	if err != nil {
		t.Fatalf("loadPool: %v", err)
	}
	if pool.Server.String() != "10.8.0.1" {
		t.Fatalf("server = %s", pool.Server)
	}
	if pool.First.String() != "10.8.0.2" || pool.Last.String() != "10.8.0.254" {
		t.Fatalf("leases = %s - %s", pool.First, pool.Last)
	}
}

func TestPoolParsesNetmask(t *testing.T) {
	dir := t.TempDir()
	conf := writeConf(t, dir, "ipv4-network = 192.168.9.0\nipv4-netmask = 255.255.255.0\n")
	p := newTestPlugin(t, &Args{ConfigPath: conf})
	_, pool, err := p.loadPool()
	if err != nil {
		t.Fatalf("loadPool: %v", err)
	}
	if pool.First.String() != "192.168.9.2" || pool.Last.String() != "192.168.9.254" {
		t.Fatalf("leases = %s - %s", pool.First, pool.Last)
	}
}

func TestPoolRejectsTooSmallNetwork(t *testing.T) {
	dir := t.TempDir()
	conf := writeConf(t, dir, "ipv4-network = 10.8.0.0/31\n")
	p := newTestPlugin(t, &Args{ConfigPath: conf})
	if _, _, err := p.loadPool(); err == nil {
		t.Fatalf("a /31 pool must be rejected")
	}
}

func TestAllocPinsLowestFreeAddress(t *testing.T) {
	args, perUser := poolArgs(t)
	if err := os.MkdirAll(perUser, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(perUser, "alice"), []byte("explicit-ipv4 = 10.8.0.2\n"), 0o600); err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	p := newTestPlugin(t, args)

	msg, err := p.AdminAllocIP(context.Background(), "bob", "")
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}
	if !strings.Contains(msg, "10.8.0.3") {
		t.Fatalf("message = %q", msg)
	}
	body, err := os.ReadFile(filepath.Join(perUser, "bob"))
	if err != nil {
		t.Fatalf("read bob: %v", err)
	}
	if !strings.Contains(string(body), "explicit-ipv4 = 10.8.0.3") {
		t.Fatalf("bob file = %q", body)
	}
}

func TestAllocIsIdempotent(t *testing.T) {
	p := newTestPlugin(t, mustArgs(t))
	first, err := p.AdminAllocIP(context.Background(), "carol", "")
	if err != nil {
		t.Fatalf("alloc: %v", err)
	}
	second, err := p.AdminAllocIP(context.Background(), "carol", "")
	if err != nil {
		t.Fatalf("re-alloc: %v", err)
	}
	if !strings.Contains(first, "assigned 10.8.0.2") || !strings.Contains(second, "already has 10.8.0.2") {
		t.Fatalf("alloc messages = %q / %q", first, second)
	}
}

func mustArgs(t *testing.T) *Args {
	t.Helper()
	args, _ := poolArgs(t)
	return args
}

func TestAllocRejectsTakenAndInvalid(t *testing.T) {
	args, perUser := poolArgs(t)
	if err := os.MkdirAll(perUser, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(perUser, "alice"), []byte("explicit-ipv4 = 10.8.0.2\n"), 0o600); err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	p := newTestPlugin(t, args)

	if _, err := p.AdminAllocIP(context.Background(), "bob", "10.8.0.2"); err == nil {
		t.Fatalf("an address pinned to alice must not be handed to bob")
	}
	if _, err := p.AdminAllocIP(context.Background(), "bob", "10.8.0.1"); err == nil {
		t.Fatalf("the reserved server address must be rejected")
	}
	if _, err := p.AdminAllocIP(context.Background(), "bob", "192.0.2.5"); err == nil {
		t.Fatalf("an address outside the pool must be rejected")
	}
	if _, err := p.AdminAllocIP(context.Background(), "../evil", ""); err == nil {
		t.Fatalf("path traversal user name must be rejected")
	}
}

func TestAllocKeepsExistingFileContent(t *testing.T) {
	p := newTestPlugin(t, mustArgs(t))
	perUser := p.mustConfigPerUser(t)
	path := filepath.Join(perUser, "dave")
	if err := os.WriteFile(path, []byte("dns = 1.1.1.1\n"), 0o600); err != nil {
		t.Fatalf("seed dave: %v", err)
	}
	if _, err := p.AdminAllocIP(context.Background(), "dave", "10.8.0.9"); err != nil {
		t.Fatalf("alloc: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read dave: %v", err)
	}
	if !strings.Contains(string(body), "dns = 1.1.1.1") || !strings.Contains(string(body), "explicit-ipv4 = 10.8.0.9") {
		t.Fatalf("dave file = %q", body)
	}
}

func (p *ocservCtl) mustConfigPerUser(t *testing.T) string {
	t.Helper()
	conf, _, err := p.loadPool()
	if err != nil {
		t.Fatalf("loadPool: %v", err)
	}
	if err := os.MkdirAll(conf.ConfigPerUser, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return conf.ConfigPerUser
}

func TestReleaseKeepsOtherSettings(t *testing.T) {
	p := newTestPlugin(t, mustArgs(t))
	perUser := p.mustConfigPerUser(t)
	path := filepath.Join(perUser, "erin")
	if err := os.WriteFile(path, []byte("dns = 9.9.9.9\nexplicit-ipv4 = 10.8.0.4\n"), 0o600); err != nil {
		t.Fatalf("seed erin: %v", err)
	}
	if _, err := p.AdminReleaseIP(context.Background(), "erin"); err != nil {
		t.Fatalf("release: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read erin: %v", err)
	}
	if !strings.Contains(string(body), "dns = 9.9.9.9") || strings.Contains(string(body), "explicit-ipv4") {
		t.Fatalf("erin file = %q", body)
	}

	// A file that only held the pinned address disappears entirely.
	perUser = p.mustConfigPerUser(t)
	path = filepath.Join(perUser, "frank")
	if err := os.WriteFile(path, []byte("explicit-ipv4 = 10.8.0.5\n"), 0o600); err != nil {
		t.Fatalf("seed frank: %v", err)
	}
	if _, err := p.AdminReleaseIP(context.Background(), "frank"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("an allocation-only file must be removed, stat err = %v", err)
	}
}

func fakeSystemctl(t *testing.T) (path, log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "calls.log")
	path = filepath.Join(dir, "systemctl")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> " + log + "\nexit 0\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}
	return path, log
}

func TestSystemctlReloadAndRestart(t *testing.T) {
	bin, log := fakeSystemctl(t)
	p := newTestPlugin(t, &Args{SystemctlPath: bin})

	if _, err := p.AdminReload(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if got := strings.Join(strings.Fields(string(raw)), " "); got != "reload ocserv" {
		t.Fatalf("systemctl args = %q", got)
	}

	if _, err := p.AdminRestart(context.Background()); err != nil {
		t.Fatalf("restart: %v", err)
	}
	raw, _ = os.ReadFile(log)
	if got := strings.Join(strings.Fields(string(raw)), " "); got != "reload ocserv restart ocserv" {
		t.Fatalf("systemctl args = %q", got)
	}

	p.args.DisabledRestart = true
	if _, err := p.AdminRestart(context.Background()); err == nil {
		t.Fatalf("disable_restart must block restart")
	}
}

func TestPoolCommandReportsRange(t *testing.T) {
	args, perUser := poolArgs(t)
	if err := os.MkdirAll(perUser, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(perUser, "alice"), []byte("explicit-ipv4 = 10.8.0.2\n"), 0o600); err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	p := newTestPlugin(t, args)
	out, err := p.AdminPool(context.Background())
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	for _, want := range []string{"10.8.0.0/24", "10.8.0.1", "10.8.0.2 - 10.8.0.254", "alice"} {
		if !strings.Contains(out, want) {
			t.Fatalf("pool output %q missing %q", out, want)
		}
	}
}
