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
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// explicitIPPattern matches the per-user key that pins a tunnel address:
// "explicit-ipv4 = 192.168.1.20". ocserv also accepts explicit-ipv4 with a
// prefix, but a plain address is what this plugin writes.
var explicitIPPattern = regexp.MustCompile(`(?mi)^\s*explicit-ipv4\s*=\s*([0-9a-fA-F:.]+)`)

// userNamePattern keeps allocation from ever writing a path traversal or an
// unexpected character into the config-per-user directory.
var userNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$`)

// ocservConf is the subset of ocserv.conf this plugin needs: the IPv4 lease
// pool and where per-user files live.
type ocservConf struct {
	Path          string
	IPv4Network   string
	IPv4Netmask   string
	ConfigPerUser string
}

// readOcservConf parses the keys we care about. ocserv's file format is a flat
// "key = value" list; inline comments are rare but stripped when the value is
// clearly followed by whitespace and '#'.
func readOcservConf(path string) (*ocservConf, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open ocserv config: %w", err)
	}
	defer f.Close()

	c := &ocservConf{Path: path}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		if i := strings.Index(val, " #"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		switch key {
		case "ipv4-network":
			c.IPv4Network = val
		case "ipv4-netmask":
			c.IPv4Netmask = val
		case "config-per-user":
			c.ConfigPerUser = val
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read ocserv config: %w", err)
	}
	if c.IPv4Network == "" {
		return nil, fmt.Errorf("%s: ipv4-network is not set", path)
	}
	return c, nil
}

// pool builds the lease pool from ipv4-network. Both forms are accepted:
// "192.168.1.0/24" and "192.168.1.0" plus ipv4-netmask.
//
// The first usable address is reserved for the server side of the tun link;
// ocserv needs at least one address outside the client leases (the manual says
// so explicitly for explicit-ipv4 leases).
func (c *ocservConf) pool() (*ipv4Pool, error) {
	var ipnet *net.IPNet
	if strings.Contains(c.IPv4Network, "/") {
		_, n, err := net.ParseCIDR(c.IPv4Network)
		if err != nil {
			return nil, fmt.Errorf("ipv4-network %q: %w", c.IPv4Network, err)
		}
		ipnet = n
	} else {
		ip := net.ParseIP(c.IPv4Network)
		if ip == nil {
			return nil, fmt.Errorf("ipv4-network %q is not an IPv4 address", c.IPv4Network)
		}
		mask := net.ParseIP(c.IPv4Netmask)
		if mask == nil {
			return nil, fmt.Errorf("ipv4-netmask %q is not an IPv4 netmask", c.IPv4Netmask)
		}
		ip4 := ip.To4()
		m := net.IPMask(mask.To4())
		if ip4 == nil || len(m) != net.IPv4len {
			return nil, fmt.Errorf("ipv4-network %q is not IPv4", c.IPv4Network)
		}
		ipnet = &net.IPNet{IP: ip4.Mask(m), Mask: m}
	}
	if ipnet.IP.To4() == nil {
		return nil, fmt.Errorf("ipv4-network %q is not IPv4", c.IPv4Network)
	}

	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("ipv4-network %q is not IPv4", c.IPv4Network)
	}
	network := ipnet.IP.To4()
	hosts := uint32(1)<<uint(32-ones) - 1 // broadcast offset from network
	if ones >= 31 {
		// /31 and /32 have no room for both a server address and leases.
		return nil, fmt.Errorf("ipv4-network %q is too small for explicit leases", c.IPv4Network)
	}

	base := binaryIP(network)
	p := &ipv4Pool{
		IPNet:  ipnet,
		Server: uint32ToIP(base + 1),
		First:  uint32ToIP(base + 2),
		Last:   uint32ToIP(base + hosts - 1),
	}
	return p, nil
}

func binaryIP(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// ipv4Pool is the allocatable slice of the configured network.
type ipv4Pool struct {
	IPNet  *net.IPNet
	Server net.IP // reserved for the tun link, never handed to a user
	First  net.IP // first address a user may get
	Last   net.IP // last address a user may get
}

func (p *ipv4Pool) contains(ip net.IP) bool {
	return ip != nil && p.IPNet.Contains(ip) && binaryIP(ip) >= binaryIP(p.First) && binaryIP(ip) <= binaryIP(p.Last)
}

// allocate returns the lowest free address, skipping the server address and
// anything already present in used.
func (p *ipv4Pool) allocate(used map[string]bool) (net.IP, error) {
	last := binaryIP(p.Last)
	for v := binaryIP(p.First); v <= last; v++ {
		ip := uint32ToIP(v)
		if used[ip.String()] {
			continue
		}
		return ip, nil
	}
	return nil, fmt.Errorf("no free address in %s (pool %s-%s, all in use)", p.IPNet.String(), p.First, p.Last)
}

// explicitIPs scans the config-per-user directory and returns two indexes:
// ip -> user and user -> ip.
func explicitIPs(dir string) (byIP map[string]string, byUser map[string]string, err error) {
	byIP = make(map[string]string)
	byUser = make(map[string]string)
	if dir == "" {
		return byIP, byUser, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return byIP, byUser, nil
		}
		return nil, nil, fmt.Errorf("read %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		m := explicitIPPattern.FindSubmatch(b)
		if len(m) != 2 {
			continue
		}
		ip := net.ParseIP(string(m[1]))
		if ip == nil || ip.To4() == nil {
			continue
		}
		byIP[ip.To4().String()] = e.Name()
		byUser[e.Name()] = ip.To4().String()
	}
	return byIP, byUser, nil
}

// writeExplicitIP sets explicit-ipv4 for one user, preserving every other line
// of the file. The write is atomic: a rename replaces the file, so ocserv never
// reads a half written config.
func writeExplicitIP(dir, user string, ip net.IP) error {
	if dir == "" {
		return fmt.Errorf("config-per-user is not set in ocserv.conf")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	path := filepath.Join(dir, user)
	body := ""
	if b, err := os.ReadFile(path); err == nil {
		body = string(b)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}

	line := "explicit-ipv4 = " + ip.To4().String()
	if explicitIPPattern.MatchString(body) {
		body = explicitIPPattern.ReplaceAllString(body, line)
	} else {
		if body != "" && !strings.HasSuffix(body, "\n") {
			body += "\n"
		}
		body += line + "\n"
	}
	return writeFileAtomic(path, []byte(body))
}

// removeExplicitIP drops the explicit-ipv4 key. The file is removed only when
// nothing but this key and blank lines was in it, so other per-user settings
// survive.
func removeExplicitIP(dir, user string) (bool, error) {
	if dir == "" {
		return false, fmt.Errorf("config-per-user is not set in ocserv.conf")
	}
	path := filepath.Join(dir, user)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	body := explicitIPPattern.ReplaceAllString(string(b), "")
	if strings.TrimSpace(body) == "" {
		if err := os.Remove(path); err != nil {
			return false, fmt.Errorf("remove %s: %w", path, err)
		}
		return true, nil
	}
	if err := writeFileAtomic(path, []byte(body)); err != nil {
		return false, err
	}
	return true, nil
}

func writeFileAtomic(path string, body []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".ocserv-ctl-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o640); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// poolUsage lists addresses pinned in config-per-user plus the ones currently
// online. online may be nil when ocserv is unreachable.
func poolUsage(dir string, online []ocservUser) (used map[string]string, err error) {
	used = make(map[string]string)
	byIP, _, err := explicitIPs(dir)
	if err != nil {
		return nil, err
	}
	for ip, user := range byIP {
		used[ip] = user
	}
	for _, u := range online {
		ip := net.ParseIP(u.VPNIP)
		if ip == nil || ip.To4() == nil {
			continue
		}
		ip4 := ip.To4().String()
		if _, ok := used[ip4]; !ok {
			used[ip4] = u.Username
		}
	}
	return used, nil
}

// formatIPList renders ip -> user sorted by address for stable output.
func formatIPList(used map[string]string) string {
	if len(used) == 0 {
		return "(none)"
	}
	type row struct {
		ip     string
		user   string
		binary uint32
	}
	rows := make([]row, 0, len(used))
	for ip, user := range used {
		rows = append(rows, row{ip: ip, user: user, binary: binaryIP(net.ParseIP(ip))})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].binary < rows[j].binary })
	var b strings.Builder
	for i, r := range rows {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(r.ip)
		b.WriteString("  ")
		b.WriteString(r.user)
	}
	return b.String()
}

func validUser(user string) bool {
	return userNamePattern.MatchString(user)
}

func parseIPv4(s string) (net.IP, error) {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("%q is not an IPv4 address", s)
	}
	return ip.To4(), nil
}
