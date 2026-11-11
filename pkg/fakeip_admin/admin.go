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

// Package fakeipadmin holds the data types and the interface shared by a
// fakeip data plane and any control surface that manages it. Keeping them in
// a neutral package means a management plugin (for example the Telegram bot)
// can talk to a fakeip plugin by its tag without importing that plugin.
package fakeipadmin

import "context"

// Entry is one row of the domain -> fake ip table.
type Entry struct {
	Domain    string
	FakeIP    string
	CreatedAt int64
}

// Stats is the aggregate view of a fakeip plugin.
type Stats struct {
	Mappings int // rows in the mapping table, pending included
	Pending  int // rows whose fake ip is not allocated yet
	RealIPs  int // rows in the real ip table
	Runtime  int // entries in the in-memory domain map
}

// Admin is implemented by fakeip_nat. A control surface resolves a plugin by
// tag, type-asserts it to Admin, and never needs to know the concrete type.
type Admin interface {
	AdminListMappings(ctx context.Context, limit int) ([]Entry, error)
	AdminLookupDomain(ctx context.Context, domain string) (*Entry, bool, error)
	AdminLookupFakeIP(ctx context.Context, fakeIP string) (*Entry, bool, error)
	AdminPutMapping(ctx context.Context, domain, fakeIP string) error
	AdminDeleteDomain(ctx context.Context, domain string) (bool, error)
	AdminClearMappings(ctx context.Context) (int64, error)
	AdminStats(ctx context.Context) (Stats, error)
}
