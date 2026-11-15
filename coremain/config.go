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

package coremain

import (
	"github.com/ersonw/mosdns-v4/mlog"
	"github.com/ersonw/mosdns-v4/pkg/data_provider"
	"github.com/ersonw/mosdns-v4/pkg/utils"
)

type Config struct {
	Log           mlog.LogConfig                     `yaml:"log"`
	Include       []string                           `yaml:"include"`
	DataProviders []data_provider.DataProviderConfig `yaml:"data_providers"`
	Plugins       []PluginConfig                     `yaml:"plugins"`
	Servers       []ServerConfig                     `yaml:"servers"`
	API           APIConfig                          `yaml:"api"`

	// Runtime tunes the Go runtime itself: its thread count, GC target and
	// memory ceiling. Every field is optional, and an empty block leaves the
	// values Go was built with, so an existing configuration keeps working
	// unchanged.
	Runtime RuntimeConfig `yaml:"runtime"`

	// Experimental
	Security SecurityConfig `yaml:"security"`

	// configDir is the directory of the loaded main config file. It is filled
	// by startServer after config loading and is not part of the YAML schema.
	configDir string
}

// RuntimeConfig is the optional `runtime:` block. A router has a small,
// fixed amount of memory and shares its CPU with the packet path, so the
// runtime has to be told about the ceiling instead of growing until the OOM
// killer intervenes:
//
//	runtime:
//	  maxprocs: 2               # GOMAXPROCS; 0 keeps the detected core count
//	  gc_percent: 50            # GOGC; 0 keeps the default 100
//	  memory_limit: 256MiB      # GOMEMLIMIT style soft ceiling; empty disables
//	  scavenge_interval: 10m    # return free pages to the OS on this period
type RuntimeConfig struct {
	MaxProcs         int    `yaml:"maxprocs"`
	GCPercent        int    `yaml:"gc_percent"`
	MemoryLimit      string `yaml:"memory_limit"`
	ScavengeInterval string `yaml:"scavenge_interval"`
}

// ConfigDir returns the directory of the loaded main config file.
func (c *Config) ConfigDir() string {
	return c.configDir
}

// PluginConfig represents a plugin config
type PluginConfig struct {
	// Tag, required
	Tag string `yaml:"tag"`

	// Type, required
	Type string `yaml:"type"`

	// Args, might be required by some plugins.
	// The type of Args is depended on RegNewPluginFunc.
	// If it's a map[string]interface{}, it will be converted by mapstruct.
	Args interface{} `yaml:"args"`
}

type ServerConfig struct {
	Exec      string                  `yaml:"exec"`
	Timeout   uint                    `yaml:"timeout"` // (sec) query timeout.
	Listeners []*ServerListenerConfig `yaml:"listeners"`
}

type ServerListenerConfig struct {
	// Protocol: server protocol, can be:
	// "", "udp" -> udp
	// "tcp" -> tcp
	// "dot", "tls" -> dns over tls
	// "doh", "https" -> dns over https (rfc 8844)
	// "http" -> dns over https (rfc 8844) but without tls
	Protocol string `yaml:"protocol"`

	// Addr: server "host:port" addr.
	// Addr cannot be empty.
	Addr string `yaml:"addr"`

	Cert                string `yaml:"cert"`                    // certificate path, used by dot, doh
	Key                 string `yaml:"key"`                     // certificate key path, used by dot, doh
	URLPath             string `yaml:"url_path"`                // used by doh, http. If it's empty, any path will be handled.
	GetUserIPFromHeader string `yaml:"get_user_ip_from_header"` // used by doh, http.
	ProxyProtocol       bool   `yaml:"proxy_protocol"`          // accepting the PROXYProtocol
	Unix                bool
	IdleTimeout         uint `yaml:"idle_timeout"` // (sec) used by tcp, dot, doh as connection idle timeout.
}

type APIConfig struct {
	HTTP string `yaml:"http"`
}

type SecurityConfig struct {
	BadIPObserver BadIPObserverConfig `yaml:"bad_ip_observer"`
}

// BadIPObserverConfig is a copy of ip_observer.BadIPObserverOpts.
type BadIPObserverConfig struct {
	Threshold        int    `yaml:"threshold"` // Zero Threshold will disable the bad ip observer.
	Interval         int    `yaml:"interval"`  // (sec) Default is 10.
	TTL              int    `yaml:"ttl"`       // (sec) Default is 600 (10min).
	OnUpdateCallBack string `yaml:"on_update_callback"`
	// IP masks to aggregate an IP range.
	IPv4Mask int `yaml:"ipv4_mask"` // Default is 32.
	IPv6Mask int `yaml:"ipv6_mask"` // Default is 48.
}

func (c *BadIPObserverConfig) Init() {
	utils.SetDefaultNum(&c.Interval, 10)
	utils.SetDefaultNum(&c.TTL, 600)
	utils.SetDefaultNum(&c.IPv4Mask, 32)
	utils.SetDefaultNum(&c.IPv6Mask, 48)
}
