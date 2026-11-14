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

package fakeipnat

import (
	"context"
	"testing"
)

func insertRealIP(t *testing.T, p *FakeIPNatPlugin, domain, realIP string, lastSeen int64) {
	t.Helper()
	if _, err := p.db.ExecContext(context.Background(),
		"INSERT INTO "+p.ipTable+" (domain, real_ip, last_seen) VALUES (?, ?, ?)",
		domain, realIP, lastSeen); err != nil {
		t.Fatalf("insert real ip %s %s: %v", domain, realIP, err)
	}
}

func insertAccess(t *testing.T, p *FakeIPNatPlugin, clientIP, domain, fakeIP string, lastSeen int64) {
	t.Helper()
	if _, err := p.db.ExecContext(context.Background(),
		"INSERT INTO "+p.accessTable+" (client_ip, domain, fake_ip, first_seen, last_seen, hits) VALUES (?, ?, ?, ?, ?, ?)",
		clientIP, domain, fakeIP, lastSeen, lastSeen, 1); err != nil {
		t.Fatalf("insert access %s %s: %v", clientIP, domain, err)
	}
}

func countRows(t *testing.T, p *FakeIPNatPlugin, table, domain string) int {
	t.Helper()
	var n int
	if err := p.db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM "+table+" WHERE domain = ?", domain).Scan(&n); err != nil {
		t.Fatalf("count %s rows of %s: %v", table, domain, err)
	}
	return n
}

// Purge has to take the domain and everything recorded under its subdomains,
// in all three tables, and leave the neighbouring names alone.
func TestAdminPurgeDomain(t *testing.T) {
	p := newTestPlugin(t, "198.18.0.0/15")
	ctx := context.Background()

	insertMapping(t, p, "example.com", "198.18.0.2", 1700000000)
	insertMapping(t, p, "a.example.com", "198.18.0.3", 1700000001)
	insertMapping(t, p, "other.com", "198.18.0.4", 1700000002)

	insertRealIP(t, p, "example.com", "93.184.216.34", 1700000000)
	insertRealIP(t, p, "a.example.com", "93.184.216.35", 1700000001)
	insertRealIP(t, p, "other.com", "93.184.216.36", 1700000002)

	insertAccess(t, p, "10.9.0.10", "example.com", "198.18.0.2", 1700000000)
	insertAccess(t, p, "10.9.0.10", "a.example.com", "198.18.0.3", 1700000001)
	insertAccess(t, p, "10.9.0.10", "other.com", "198.18.0.4", 1700000002)

	rep, err := p.AdminPurgeDomain(ctx, "Example.COM.")
	if err != nil {
		t.Fatalf("AdminPurgeDomain: %v", err)
	}
	if rep.Mappings != 2 || rep.RealIPs != 2 || rep.Access != 2 {
		t.Fatalf("report = %+v, want 2/2/2", rep)
	}
	if len(rep.Domains) != 2 {
		t.Fatalf("touched domains = %v, want example.com and a.example.com", rep.Domains)
	}

	for _, table := range []string{p.mapTable, p.ipTable, p.accessTable} {
		if n := countRows(t, p, table, "example.com"); n != 0 {
			t.Fatalf("%s still has %d row(s) for example.com", table, n)
		}
		if n := countRows(t, p, table, "a.example.com"); n != 0 {
			t.Fatalf("%s still has %d row(s) for a.example.com", table, n)
		}
		if n := countRows(t, p, table, "other.com"); n != 1 {
			t.Fatalf("%s has %d row(s) for other.com, want 1", table, n)
		}
	}

	if _, ok := p.runtime.fakeOf("example.com"); ok {
		t.Fatalf("runtime kept example.com")
	}
	if _, ok := p.runtime.fakeOf("a.example.com"); ok {
		t.Fatalf("runtime kept a.example.com")
	}
	if _, ok := p.runtime.fakeOf("other.com"); !ok {
		t.Fatalf("runtime dropped other.com")
	}
	if got := len(p.runtime.realsOf("example.com")); got != 0 {
		t.Fatalf("runtime kept %d real ip(s) of example.com", got)
	}

	// A second purge finds nothing left, so a device that retries the command
	// does not fail.
	rep, err = p.AdminPurgeDomain(ctx, "example.com")
	if err != nil {
		t.Fatalf("second AdminPurgeDomain: %v", err)
	}
	if rep.Mappings != 0 || rep.RealIPs != 0 || rep.Access != 0 {
		t.Fatalf("second purge removed %+v", rep)
	}

	// A domain that still has a mapping can be added again after the purge.
	insertMapping(t, p, "example.com", "198.18.0.9", 1700000100)
	if _, ok, err := p.AdminLookupDomain(ctx, "example.com"); err != nil || !ok {
		t.Fatalf("re-adding after purge: ok=%v err=%v", ok, err)
	}
}
