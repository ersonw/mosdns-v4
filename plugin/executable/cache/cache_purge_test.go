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

package cache

import (
	"context"
	"testing"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/cache/mem_cache"
	"github.com/ersonw/mosdns-v4/pkg/dnsutils"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func testMsgKey(t *testing.T, name string, qtype uint16) string {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	key, err := dnsutils.GetMsgKey(q, 0)
	if err != nil {
		t.Fatalf("GetMsgKey(%s): %v", name, err)
	}
	return key
}

// A purge must drop the domain and its subdomains, both query types included,
// and must leave every other name in the cache alone.
func TestAdminPurgeDomain(t *testing.T) {
	bp := coremain.NewBP("test_cache", PluginType, zap.NewNop(), nil)
	// The constructor registers Prometheus metrics on a real Mosdns instance,
	// which a unit test does not have; the purge only needs the backend.
	c := &cachePlugin{
		BP:      bp,
		args:    &Args{},
		backend: mem_cache.NewMemCache(1024, 0),
	}
	defer c.Shutdown()

	now := time.Now()
	ttl := now.Add(10 * time.Minute)
	stores := []struct {
		name  string
		qtype uint16
	}{
		{"example.com.", dns.TypeA},
		{"example.com.", dns.TypeAAAA},
		{"a.example.com.", dns.TypeA},
		{"other.com.", dns.TypeA},
	}
	for _, s := range stores {
		c.backend.Store(testMsgKey(t, s.name, s.qtype), []byte{0}, now, ttl)
	}

	n, err := c.AdminPurgeDomain(context.Background(), "Example.com.")
	if err != nil {
		t.Fatalf("AdminPurgeDomain: %v", err)
	}
	if n != 3 {
		t.Fatalf("purged %d entries, want 3", n)
	}

	for _, s := range stores[:3] {
		if v, _, _ := c.backend.Get(testMsgKey(t, s.name, s.qtype)); len(v) != 0 {
			t.Fatalf("%s %s survived the purge", dns.TypeToString[s.qtype], s.name)
		}
	}
	if v, _, _ := c.backend.Get(testMsgKey(t, "other.com.", dns.TypeA)); len(v) == 0 {
		t.Fatalf("other.com was purged as well")
	}

	if _, err := c.AdminPurgeDomain(context.Background(), "example.com"); err != nil {
		t.Fatalf("second purge: %v", err)
	}
}

func TestMsgKeyIsDomain(t *testing.T) {
	cases := []struct {
		name   string
		domain string
		want   bool
	}{
		{"example.com.", "example.com", true},
		{"a.b.example.com.", "example.com", true},
		{"notexample.com.", "example.com", false},
		{"example.com.evil.net.", "example.com", false},
	}
	for _, c := range cases {
		key := testMsgKey(t, c.name, dns.TypeA)
		if got := msgKeyIsDomain(key, c.domain); got != c.want {
			t.Fatalf("msgKeyIsDomain(%s, %s) = %v, want %v", c.name, c.domain, got, c.want)
		}
	}
	if msgKeyIsDomain("not a dns message", "example.com") {
		t.Fatalf("a non-message key matched a domain")
	}
}
