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
	"fmt"
	"github.com/ersonw/mosdns-v4/mlog"
	"github.com/kardianos/service"
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

type serverFlags struct {
	c         string
	dir       string
	cpu       int
	asService bool
}

var rootCmd = &cobra.Command{
	Use: "mosdns",
}

func init() {
	sf := new(serverFlags)
	startCmd := &cobra.Command{
		Use:   "start [-c config_file] [-d working_dir]",
		Short: "Start mosdns main program.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if sf.asService {
				svc, err := service.New(&serverService{f: sf}, svcCfg)
				if err != nil {
					return fmt.Errorf("failed to init service, %w", err)
				}
				return svc.Run()
			}
			return StartServer(sf)
		},
		DisableFlagsInUseLine: true,
		SilenceUsage:          true,
	}
	rootCmd.AddCommand(startCmd)
	fs := startCmd.Flags()
	fs.StringVarP(&sf.c, "config", "c", "", "config file")
	fs.StringVarP(&sf.dir, "dir", "d", "", "working dir")
	fs.IntVar(&sf.cpu, "cpu", 0, "set runtime.GOMAXPROCS")
	fs.BoolVar(&sf.asService, "as-service", false, "start as a service")
	fs.MarkHidden("as-service")

	serviceCmd := &cobra.Command{
		Use:   "service",
		Short: "Manage mosdns as a system service.",
	}
	serviceCmd.PersistentPreRunE = initService
	serviceCmd.AddCommand(
		newSvcInstallCmd(),
		newSvcUninstallCmd(),
		newSvcStartCmd(),
		newSvcStopCmd(),
		newSvcRestartCmd(),
		newSvcStatusCmd(),
	)
	rootCmd.AddCommand(serviceCmd)
}

func AddSubCmd(c *cobra.Command) {
	rootCmd.AddCommand(c)
}

func Run() error {
	return rootCmd.Execute()
}

func StartServer(sf *serverFlags) error {
	return startServer(sf, true)
}

// watchShutdownSignals turns SIGTERM and SIGINT into the close signal RunMosdns
// waits on. Without it the default signal action kills the process and no plugin
// Close runs, which is exactly how data plane objects survive a restart. A
// repeated signal exits immediately: the first one is not making progress.
func watchShutdownSignals() func() {
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		shuttingDown := false
		for sig := range sigChan {
			if shuttingDown {
				mlog.L().Warn("forced exit on a repeated signal", zap.String("signal", sig.String()))
				os.Exit(1)
			}
			shuttingDown = true
			if !RequestShutdown("shutdown requested by " + sig.String()) {
				mlog.L().Warn("signal with nothing to shut down", zap.String("signal", sig.String()))
				os.Exit(1)
			}
			mlog.L().Info("shutdown started", zap.String("signal", sig.String()))
		}
	}()
	return func() { signal.Stop(sigChan) }
}

// startServer runs the server. handleSignals is false when the caller is the
// service wrapper, which owns SIGTERM itself and stops through Stop.
func startServer(sf *serverFlags, handleSignals bool) error {
	if sf.cpu > 0 {
		runtime.GOMAXPROCS(sf.cpu)
	}

	if len(sf.dir) > 0 {
		err := os.Chdir(sf.dir)
		if err != nil {
			return fmt.Errorf("failed to change the current working directory, %w", err)
		}
		mlog.L().Info("working directory changed", zap.String("path", sf.dir))
	}

	v := viper.New()
	if len(sf.c) > 0 {
		v.SetConfigFile(sf.c)
	} else {
		v.SetConfigName("config")
		v.AddConfigPath(".")
	}

	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config file, %w", err)
	}

	cfg := new(Config)
	if err := v.Unmarshal(cfg, decoderOpt); err != nil {
		return fmt.Errorf("failed to parse config file, %w", err)
	}

	cfgPath := v.ConfigFileUsed()
	cfg.configDir = filepath.Dir(cfgPath)
	if err := mergeInclude(cfg, 0, []string{cfgPath}, []string{tryGetAbsPath(cfgPath)}); err != nil {
		return fmt.Errorf("failed to load sub config file, %w", err)
	}

	if handleSignals {
		stopWatching := watchShutdownSignals()
		defer stopWatching()
	}

	if err := RunMosdns(cfg); err != nil {
		return fmt.Errorf("mosdns exited, %w", err)
	}
	return nil
}

func decoderOpt(cfg *mapstructure.DecoderConfig) {
	cfg.ErrorUnused = true
	cfg.TagName = "yaml"
	cfg.WeaklyTypedInput = true
}

func mergeInclude(cfg *Config, depth int, paths, absPaths []string) error {
	depth++
	if depth > 8 {
		return fmt.Errorf("maximun include depth reached, include path is %s", strings.Join(paths, " -> "))
	}

	includedCfg := new(Config)
	for _, subCfgFile := range cfg.Include {
		subPaths := append(paths, subCfgFile)
		subCfgAbsPath := tryGetAbsPath(subCfgFile)
		subAbsPaths := append(absPaths, subCfgAbsPath)
		for _, includedAbsPath := range absPaths {
			if includedAbsPath == subCfgAbsPath {
				return fmt.Errorf("cycle include depth detected, include path is %s", strings.Join(subPaths, " -> "))
			}
		}

		mlog.L().Info("reading sub config", zap.String("file", subCfgFile))
		subV := viper.New()
		subV.SetConfigFile(subCfgFile)
		if err := subV.ReadInConfig(); err != nil {
			mlog.L().Fatal("failed to read sub config file", zap.String("file", subCfgFile), zap.Error(err))
		}
		subCfg := new(Config)
		if err := subV.Unmarshal(subCfg, decoderOpt); err != nil {
			mlog.L().Fatal("failed to parse sub config file", zap.String("file", subCfgFile), zap.Error(err))
		}
		if err := mergeInclude(subCfg, depth, subPaths, subAbsPaths); err != nil {
			return err
		}

		includedCfg.DataProviders = append(includedCfg.DataProviders, subCfg.DataProviders...)
		includedCfg.Plugins = append(includedCfg.Plugins, subCfg.Plugins...)
		includedCfg.Servers = append(includedCfg.Servers, subCfg.Servers...)
	}

	cfg.DataProviders = append(includedCfg.DataProviders, cfg.DataProviders...)
	cfg.Plugins = append(includedCfg.Plugins, cfg.Plugins...)
	cfg.Servers = append(includedCfg.Servers, cfg.Servers...)
	return nil
}

func tryGetAbsPath(s string) string {
	p, err := filepath.Abs(s)
	if err != nil {
		return s
	}
	return p
}
