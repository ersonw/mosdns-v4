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
	"errors"
	"fmt"
	"github.com/ersonw/mosdns-v4/mlog"
	"github.com/ersonw/mosdns-v4/pkg/concurrent_limiter"
	"github.com/ersonw/mosdns-v4/pkg/data_provider"
	"github.com/ersonw/mosdns-v4/pkg/executable_seq"
	"github.com/ersonw/mosdns-v4/pkg/ip_observer"
	"github.com/ersonw/mosdns-v4/pkg/safe_close"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"net/http"
	"net/http/pprof"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

type Mosdns struct {
	logger *zap.Logger

	// configDir is the directory of the main config file; plugins use it to
	// resolve relative assets such as helper scripts.
	configDir string

	// Data
	dataManager *data_provider.DataManager

	// Plugins
	execs    map[string]executable_seq.Executable
	matchers map[string]executable_seq.Matcher

	httpAPIMux    *http.ServeMux
	httpAPIServer *http.Server

	metricsReg *prometheus.Registry

	badIPObserver ip_observer.IPObserver

	sc *safe_close.SafeClose
}

// The service wrapper and the signal handler need a way to ask the running
// instance to close. RunMosdns owns the instance and the channel that closes
// once its close pass is over, so it publishes both here: a caller outside the
// process' main goroutine cannot reach them otherwise.
var (
	activeMu   sync.Mutex
	active     *Mosdns
	activeDone chan struct{}
)

func registerActive(m *Mosdns) chan struct{} {
	done := make(chan struct{})
	activeMu.Lock()
	active, activeDone = m, done
	activeMu.Unlock()
	return done
}

func clearActive(m *Mosdns, done chan struct{}) {
	activeMu.Lock()
	if active == m {
		active, activeDone = nil, nil
	}
	activeMu.Unlock()
	close(done)
}

// ErrShutdownRequested marks a close that was asked for on purpose - a signal,
// a service stop - so the caller can exit quietly instead of reporting a failure
// and having the service manager count the stop as a crash.
var ErrShutdownRequested = errors.New("shutdown requested")

// RequestShutdown asks the running instance to start its close pass. It reports
// false when nothing is up yet or when the instance already finished closing.
func RequestShutdown(reason string) bool {
	activeMu.Lock()
	m, done := active, activeDone
	activeMu.Unlock()
	if m == nil || done == nil {
		return false
	}
	select {
	case <-done:
		return false
	default:
	}
	m.GetSafeClose().SendCloseSignal(fmt.Errorf("%w: %s", ErrShutdownRequested, reason))
	return true
}

// WaitShutdown blocks until the running instance finished closing every plugin.
// A timeout is returned as false so the caller can still exit instead of
// hanging the stop.
func WaitShutdown(timeout time.Duration) bool {
	activeMu.Lock()
	done := activeDone
	activeMu.Unlock()
	if done == nil {
		return true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

func RunMosdns(cfg *Config) error {
	lg, err := mlog.NewLogger(&cfg.Log)
	if err != nil {
		return err
	}

	m := &Mosdns{
		logger:      lg,
		configDir:   cfg.configDir,
		dataManager: data_provider.NewDataManager(),
		execs:       make(map[string]executable_seq.Executable),
		matchers:    make(map[string]executable_seq.Matcher),
		httpAPIMux:  http.NewServeMux(),
		metricsReg:  newMetricsReg(),
		sc:          safe_close.NewSafeClose(),
	}

	done := registerActive(m)
	defer clearActive(m, done)

	m.httpAPIMux.Handle("/metrics", promhttp.HandlerFor(m.metricsReg, promhttp.HandlerOpts{}))
	m.httpAPIMux.HandleFunc("/debug/pprof/", pprof.Index)
	m.httpAPIMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	m.httpAPIMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	m.httpAPIMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	m.httpAPIMux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	// Init ip observer
	obCfg := cfg.Security.BadIPObserver
	obCfg.Init()
	if obCfg.Threshold > 0 {
		ob, err := ip_observer.NewBadIPObserver(ip_observer.BadIPObserverOpts{
			HPLimiterOpts: concurrent_limiter.HPLimiterOpts{
				Threshold: obCfg.Threshold,
				Interval:  time.Duration(obCfg.Interval) * time.Second,
				IPv4Mask:  obCfg.IPv4Mask,
				IPv6Mask:  obCfg.IPv6Mask,
			},
			TTL:              time.Duration(obCfg.TTL) * time.Second,
			OnUpdateCallBack: obCfg.OnUpdateCallBack,
			Logger:           lg,
		})
		if err != nil {
			return fmt.Errorf("failed to init bad ip observer, %w", err)
		}
		m.badIPObserver = ob
		defer ob.Close()
		m.httpAPIMux.Handle("/security/bad_ip_observer", ob)
	} else {
		m.badIPObserver = ip_observer.NewNopObserver()
	}

	// Init data manager
	dupTag := make(map[string]struct{})
	for _, dpc := range cfg.DataProviders {
		if len(dpc.Tag) == 0 {
			continue
		}
		if _, ok := dupTag[dpc.Tag]; ok {
			return fmt.Errorf("duplicated provider tag %s", dpc.Tag)
		}
		dupTag[dpc.Tag] = struct{}{}

		dp, err := data_provider.NewDataProvider(lg, &dpc)
		if err != nil {
			return fmt.Errorf("failed to init data provider %s, %w", dpc.Tag, err)
		}
		m.dataManager.AddDataProvider(dpc.Tag, dp)
	}

	// Init preset plugins
	for tag, f := range LoadNewPersetPluginFuncs() {
		p, err := f(NewBP(tag, "preset", m.logger, m))
		if err != nil {
			return fmt.Errorf("failed to init preset plugin %s, %w", tag, err)
		}
		m.addPlugin(p)
	}

	// Init plugins
	dupTag = make(map[string]struct{})
	for i, pc := range cfg.Plugins {
		if len(pc.Type) == 0 || len(pc.Tag) == 0 {
			continue
		}
		if _, dup := dupTag[pc.Tag]; dup {
			return fmt.Errorf("duplicated plugin tag %s", pc.Tag)
		}
		dupTag[pc.Tag] = struct{}{}

		m.logger.Info("loading plugin", zap.String("tag", pc.Tag), zap.String("type", pc.Type))
		p, err := NewPlugin(&pc, m.logger, m)
		if err != nil {
			return fmt.Errorf("failed to init plugin #%d, %w", i, err)
		}

		m.addPlugin(p)
		// Also add it to api mux if plugin implements http.Handler.
		if h, ok := p.(http.Handler); ok {
			m.httpAPIMux.Handle(fmt.Sprintf("/plugins/%s/", p.Tag()), h)
		}
	}

	if len(cfg.Servers) == 0 {
		return errors.New("no server is configured")
	}
	for i, sc := range cfg.Servers {
		if err := m.startServers(&sc); err != nil {
			return fmt.Errorf("failed to start server #%d, %w", i, err)
		}
	}

	// Start http api server
	if httpAddr := cfg.API.HTTP; len(httpAddr) > 0 {
		httpServer := &http.Server{
			Addr:    httpAddr,
			Handler: m.httpAPIMux,
		}
		m.sc.Attach(func(done func(), closeSignal <-chan struct{}) {
			defer done()
			errChan := make(chan error, 1)
			go func() {
				m.logger.Info("starting api http server", zap.String("addr", httpAddr))
				errChan <- httpServer.ListenAndServe()
			}()
			select {
			case err := <-errChan:
				m.sc.SendCloseSignal(err)
			case <-closeSignal:
				httpServer.Close()
			}
		})
	}

	time.AfterFunc(time.Second*1, func() {
		runtime.GC()
		debug.FreeOSMemory()
	})
	<-m.sc.ReceiveCloseSignal()
	m.sc.Done()
	m.sc.CloseWait()
	if err := m.sc.Err(); errors.Is(err, ErrShutdownRequested) {
		return nil
	} else {
		return err
	}
}

func (m *Mosdns) addPlugin(p Plugin) {
	t := p.Tag()
	if p, ok := p.(ExecutablePlugin); ok {
		m.execs[t] = p
	}
	if p, ok := p.(MatcherPlugin); ok {
		m.matchers[p.Tag()] = p
	}
}

func (m *Mosdns) GetDataManager() *data_provider.DataManager {
	return m.dataManager
}

// ConfigDir returns the directory of the main config file, or an empty string
// when the instance was built without one (for example in tests).
func (m *Mosdns) ConfigDir() string {
	if m == nil {
		return ""
	}
	return m.configDir
}

func (m *Mosdns) GetSafeClose() *safe_close.SafeClose {
	return m.sc
}

func (m *Mosdns) GetExecutables() map[string]executable_seq.Executable {
	return m.execs
}

func (m *Mosdns) GetMatchers() map[string]executable_seq.Matcher {
	return m.matchers
}

// GetMetricsReg returns a prometheus.Registerer with a prefix of "mosdns_"
func (m *Mosdns) GetMetricsReg() prometheus.Registerer {
	return prometheus.WrapRegistererWithPrefix("mosdns_", m.metricsReg)
}

// GetHTTPAPIMux returns the api http.ServeMux.
// The pattern "/plugins/plugin_tag/" has been registered if
// Plugin implements http.Handler interface.
// Plugin caller should register path that has "/plugins/plugin_tag/"
// prefix only.
func (m *Mosdns) GetHTTPAPIMux() *http.ServeMux {
	return m.httpAPIMux
}

// GetBadIPObserver returns the ip_observer.BadIPObserver. It returns nil if is not enabled.
func (m *Mosdns) GetBadIPObserver() ip_observer.IPObserver {
	return m.badIPObserver
}

func newMetricsReg() *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	reg.MustRegister(collectors.NewGoCollector())
	return reg
}
