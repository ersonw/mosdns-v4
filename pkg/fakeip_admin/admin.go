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

// AccessRecord is one client's visit to one domain: who resolved it, what fake
// ip it was given, which real address was learned for it, and when.
type AccessRecord struct {
	ClientIP  string
	Domain    string
	FakeIP    string
	RealIP    string
	FirstSeen int64
	LastSeen  int64
	Hits      int
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
	// AdminAccessRecords returns the visits of the given client addresses,
	// newest first. since is a unix timestamp; 0 means no lower bound. A
	// plugin with the access log disabled returns an empty slice.
	AdminAccessRecords(ctx context.Context, clientIPs []string, since int64, limit int) ([]AccessRecord, error)
}

// Plane is what the data plane has installed on the machine right now, next to
// the state the plugin recorded for a later cleanup. It exists so a control
// surface can answer "what is actually running" without shell access: every
// field is read from the plugin or from the kernel, never guessed.
type Plane struct {
	DataPlane   string            // "tun" or "nft"
	Device      string            // tun device name, empty on the nft plane
	Range       string            // ipv4_range
	ProxyActive bool              // the proxy carries the answers
	MarkEnabled bool              // route marking is in effect for this configuration
	RouteMark   uint32            // route_mark value, 0 when unset
	RouteTable  string            // table the mark rule points at
	OutletTable string            // table the stack's own dials use (tun plane)
	RealIPs     int               // elements in the nft mark set
	Rules       []string          // our lines of "ip rule show"
	Routes      []string          // default route of each table we own
	Recorded    map[string]string // plugin_state rows a later run uses to clean
}

// Diagnosis answers "what happens to this domain": its mapping, the real
// addresses the plane learned for it, and where the stack would dial from.
type Diagnosis struct {
	Domain      string
	FakeIP      string
	CreatedAt   int64
	RealIPs     []string
	RealIPKnown bool // false when the plane has not learned any real address yet
	ProxyActive bool
	Outlet      string // human readable: "proxy", "tun next_hop ...", "nft"
	Marked      bool   // the mark path is in effect, so those warns can fire
}

// PlaneAdmin is implemented by a fakeip plugin next to Admin. It is a separate
// interface so a surface that only lists mappings keeps working unchanged.
type PlaneAdmin interface {
	AdminPlane(ctx context.Context) (Plane, error)
	AdminDiagnose(ctx context.Context, domain string) (Diagnosis, error)
	// AdminSweep removes the objects a previous run recorded that this run does
	// not own, and returns a line per removed object.
	AdminSweep(ctx context.Context) ([]string, error)
}
