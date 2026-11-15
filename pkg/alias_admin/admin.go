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

// Package aliasadmin holds the interface between an alias data plane and a
// control surface. The list is owned by the plugin, so every mutation goes
// through the plugin: one writer, one reload, one purge.

package aliasadmin

import "context"

// Entry is one line of the served list.
type Entry struct {
	Domain string // normalized real domain
	Scheme string // http, https or https+insecure
	Alias  string // rendered alias host, including the configured suffix
	IPv4   string // virtual address assigned to Domain, empty if unavailable
}

// Snapshot is the read-only view of one alias plugin.
type Snapshot struct {
	Tag            string
	File           string
	Suffix         string
	ReplaceSuffix  bool
	IPv4Range      string
	DefaultScheme  string
	ProxyActive    bool
	Redirect       bool   // redirect_to_alias: real names share the IP and HTTP 302s to the alias
	DotReplacement string // separator substituted for dots in the source domain, "." = none
	TLS            bool   // tls_cert_file/tls_key_file are loaded; 443 is terminated
	Total          int
	Entries        []Entry
}

// Admin is implemented by the alias plugin.
type Admin interface {
	AdminAliasSnapshot(ctx context.Context) (Snapshot, error)
	// AdminAliasAdd appends one "[scheme://]domain" entry. A duplicate returns
	// added=false and no error, so the caller can report "already present".
	AdminAliasAdd(ctx context.Context, raw string) (added bool, err error)
	// AdminAliasDelete removes one entry and drops the virtual address it had,
	// so a later add starts clean.
	AdminAliasDelete(ctx context.Context, raw string) (removed bool, err error)
	// AdminAliasModify replaces an entry and purges the state of the old name.
	AdminAliasModify(ctx context.Context, oldRaw, newRaw string) error
	// AdminAliasClear empties the list and purges every mapping.
	AdminAliasClear(ctx context.Context) (removed int, err error)
	// AdminAliasSetSuffix changes the served suffix at runtime.
	AdminAliasSetSuffix(ctx context.Context, suffix string) error
	// AdminAliasReload re-reads the list file from disk and drops the mapping
	// of names it no longer serves.
	AdminAliasReload(ctx context.Context) error
	// AdminAliasCheckRange validates a candidate ipv4_range before the caller
	// writes it to the config file. A range can not change without restarting
	// the tun plane, so checking is all this plugin does here.
	AdminAliasCheckRange(ctx context.Context, cidr string) error
}
