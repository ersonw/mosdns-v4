package fakeipnat

// Init sits on the configuration path: mosdns answers nothing until every plugin
// returns from it. Cleanup of what an earlier run left behind therefore cannot
// live there - each removed route, rule or table is one exec call, and a ledger
// that collected a few thousand host routes turns into tens of seconds of
// silence for the socket layer. Those tasks are queued instead and drained by a
// single goroutine right after Init returns.

import (
	"time"

	"go.uber.org/zap"
)

// startupTask is one queued cleanup step, named so the log says which one is
// slow when a box has to catch up after a crash.
type startupTask struct {
	name string
	fn   func()
}

// deferStartup appends a task to the startup queue. One goroutine drains the
// queue in order, so two tasks never race each other's exec calls.
func (p *FakeIPNatPlugin) deferStartup(name string, fn func()) {
	p.startupMu.Lock()
	p.startupTasks = append(p.startupTasks, startupTask{name: name, fn: fn})
	p.startupMu.Unlock()
}

// startStartupQueue hands the queued tasks to their goroutine. It is called once
// at the end of Init: running them earlier could race the objects this run is
// still installing.
func (p *FakeIPNatPlugin) startStartupQueue() {
	p.startupMu.Lock()
	tasks := p.startupTasks
	p.startupTasks = nil
	p.startupMu.Unlock()
	if len(tasks) == 0 {
		return
	}
	p.startupWG.Add(1)
	go func() {
		defer p.startupWG.Done()
		for _, t := range tasks {
			started := time.Now()
			p.L().Debug("fakeip nat: deferred startup task started", zap.String("task", t.name))
			t.fn()
			p.logStep("deferred "+t.name, started)
		}
	}()
}

// logStep reports one Init or startup step: a second is the point where it
// starts to matter, because that second is taken out of DNS availability.
func (p *FakeIPNatPlugin) logStep(name string, started time.Time) {
	d := time.Since(started)
	if d >= time.Second {
		p.L().Info("fakeip nat: slow startup step", zap.String("step", name), zap.Duration("elapsed", d))
		return
	}
	p.L().Debug("fakeip nat: startup step", zap.String("step", name), zap.Duration("elapsed", d))
}
