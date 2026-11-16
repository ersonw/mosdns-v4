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

package main

import (
	"fmt"
	_ "net/http/pprof"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/mlog"
	_ "github.com/ersonw/mosdns-v4/plugin"
	_ "github.com/ersonw/mosdns-v4/tools"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
)

func init() {
	coremain.SetBuildVersion(version)

	// check-config exists for the updater: the binary that is about to be
	// installed is the only one that can say whether it accepts the migrated
	// configuration. It parses and exits without touching anything.
	var checkDir, checkCfg string
	check := &cobra.Command{
		Use:   "check-config",
		Short: "Parse the config file, report schema problems and exit.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return coremain.CheckConfigFile(checkDir, checkCfg)
		},
	}
	check.Flags().StringVarP(&checkDir, "dir", "d", "", "working directory")
	check.Flags().StringVarP(&checkCfg, "config", "c", "config.yaml", "config file")
	coremain.AddSubCmd(check)

	// update runs the same check the loop runs, once, in the foreground: the
	// operator sees the decision, the checksum, the config validation and the
	// scheduled swap instead of waiting for a log line.
	var (
		updDir, updCfg string
		updDryRun      bool
	)
	upd := &cobra.Command{
		Use:   "update",
		Short: "Check for a newer release and install it, then exit.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return coremain.UpdateNow(updDir, updCfg, updDryRun)
		},
	}
	upd.Flags().StringVarP(&updDir, "dir", "d", "", "working directory")
	upd.Flags().StringVarP(&updCfg, "config", "c", "config.yaml", "config file")
	upd.Flags().BoolVar(&updDryRun, "dry-run", false, "download and validate, do not install")
	coremain.AddSubCmd(upd)

	coremain.AddSubCmd(&cobra.Command{
		Use:   "version",
		Short: "Print out version info and exit.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	})
}

func main() {
	if err := coremain.Run(); err != nil {
		mlog.S().Fatal(err)
	}
}
