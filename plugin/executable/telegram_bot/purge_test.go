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

package telegram_bot

import (
	"strings"
	"testing"
)

// A provider rule has to be turned into the bare domain the purge works on; a
// pattern rule names no domain, so there is nothing to enumerate.
func TestRuleDomain(t *testing.T) {
	cases := []struct {
		rule   string
		domain string
		ok     bool
	}{
		{"domain:Example.COM.", "example.com", true},
		{"full:cip.cc", "cip.cc", true},
		{"6.ipchaxun.net", "6.ipchaxun.net", true},
		{"keyword:ip138", "", false},
		{"regexp:^a\\.b$", "", false},
		{"", "", false},
		{"two words", "", false},
	}
	for _, c := range cases {
		domain, ok := ruleDomain(c.rule)
		if ok != c.ok || domain != c.domain {
			t.Fatalf("ruleDomain(%q) = %q,%v want %q,%v", c.rule, domain, ok, c.domain, c.ok)
		}
	}
}

// The reply has to show what was actually removed, and a clean domain must not
// look like a failure.
func TestPurgeSummary(t *testing.T) {
	l := replyLang(nil)

	clean := purgeSummary(purgeDomainResult{}, l)
	if !strings.Contains(clean, "no cached answer") && !strings.Contains(clean, "没有残留") {
		t.Fatalf("clean summary = %q", clean)
	}

	res := purgeDomainResult{Mappings: 2, RealIPs: 3, Access: 1, Cached: 4}
	got := purgeSummary(res, l)
	if !strings.Contains(got, "mappings 2") && !strings.Contains(got, "映射 2") {
		t.Fatalf("summary lost the counts: %q", got)
	}

	res.Warnings = []string{"cache_main: purge failed: redis"}
	if got := purgeSummary(res, l); !strings.Contains(got, "cache_main") {
		t.Fatalf("summary dropped the warning: %q", got)
	}
}
