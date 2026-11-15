package coremain

// The runtime block keeps a healthy process from growing without bound, but it
// does not stop a hot path from saturating the box: once the Go scheduler and
// the packet path together eat every core, sshd is queued behind them and the
// operator cannot log in to fix anything. This watchdog samples the process's
// own CPU and RSS footprint and reacts while there is still head room.
//
// Go cannot reclaim goroutines on demand - they are cooperative and cannot be
// killed from outside. What the runtime does allow, and what the guard does, is
// force a GC and hand free pages back to the kernel, and temporarily lower
// GOMAXPROCS so the kernel, sshd and the packet path keep a share of the CPU.
// It never exits the process: a self-inflicted restart would drop DNS for
// every client on the box, so recovery stays inside the process.

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/safe_close"
	"go.uber.org/zap"
)

const (
	defaultGuardCPUPercent = 90.0
	defaultGuardMemPercent = 90.0
	defaultGuardInterval   = 5 * time.Second
	defaultGuardSustain    = 15 * time.Second
	defaultGuardCooldown   = 5 * time.Minute

	minimumGuardInterval = time.Second
	// guardScavengeThrottle keeps a sustained high watermark from turning
	// FreeOSMemory, which is a full GC plus a page walk, into a CPU consumer of
	// its own.
	guardScavengeThrottle = 30 * time.Second
	// guardGoroutineFloor is the smallest goroutine count that is worth
	// reporting; a healthy mosdns idles well below it.
	guardGoroutineFloor = 512
	// userHZ is USER_HZ, the unit of the utime/stime fields in /proc/self/stat.
	// It is 100 on every mainstream Linux build, including VyOS.
	userHZ = 100
)

var (
	procStatPath    = "/proc/self/stat"
	procStatmPath   = "/proc/self/statm"
	procMeminfoPath = "/proc/meminfo"
)

// guardOptions is the resolved form of the optional `runtime.self_guard` block.
type guardOptions struct {
	cpuPercent float64       // process CPU as a percentage of the whole machine
	memPercent float64       // process RSS as a percentage of total system memory
	interval   time.Duration // sampling period
	sustain    time.Duration // how long a condition must hold before acting
	cooldown   time.Duration // how long a downshift lasts
}

func guardOptionsFrom(cfg RuntimeConfig) guardOptions {
	o := guardOptions{
		cpuPercent: defaultGuardCPUPercent,
		memPercent: defaultGuardMemPercent,
		interval:   defaultGuardInterval,
		sustain:    defaultGuardSustain,
		cooldown:   defaultGuardCooldown,
	}
	if cfg.GuardCPUPercent > 0 {
		o.cpuPercent = math.Min(100, float64(cfg.GuardCPUPercent))
	}
	if cfg.GuardMemPercent > 0 {
		o.memPercent = math.Min(100, float64(cfg.GuardMemPercent))
	}
	if d, err := time.ParseDuration(cfg.GuardInterval); err == nil && d >= minimumGuardInterval {
		o.interval = d
	}
	if d, err := time.ParseDuration(cfg.GuardSustain); err == nil && d >= minimumGuardInterval {
		o.sustain = d
	}
	if d, err := time.ParseDuration(cfg.GuardCooldown); err == nil && d >= minimumGuardInterval {
		o.cooldown = d
	}
	if o.sustain < o.interval {
		o.sustain = o.interval
	}
	return o
}

// guardState is the hysteresis that keeps the guard from oscillating: an action
// needs the condition to hold for the sustain period, and a downshift expires
// only after the cooldown and only once CPU has really fallen back.
type guardState struct {
	memHighSince   time.Time
	lastScavenge   time.Time
	cpuHighSince   time.Time
	downshifted    bool
	downshiftUntil time.Time
	originalProcs  int
}

// guardDecision is what the sampler should do on this tick.
type guardDecision struct {
	scavenge  bool
	downshift bool
	restore   bool
	extend    bool
}

func (s *guardState) decide(now time.Time, cpuPct, memPct float64, opts guardOptions, curProcs int) guardDecision {
	var d guardDecision

	if opts.memPercent > 0 && memPct >= opts.memPercent {
		if s.memHighSince.IsZero() {
			s.memHighSince = now
		}
		if now.Sub(s.memHighSince) >= opts.sustain && now.Sub(s.lastScavenge) >= guardScavengeThrottle {
			d.scavenge = true
			s.lastScavenge = now
		}
	} else {
		s.memHighSince = time.Time{}
	}

	if s.downshifted {
		if now.Before(s.downshiftUntil) {
			return d
		}
		// Leave the downshifted state only when the box has actually recovered,
		// otherwise the guard would return the CPU to a process that is still
		// saturating it.
		if cpuPct < opts.cpuPercent/2 {
			s.downshifted = false
			d.restore = true
		} else {
			s.downshiftUntil = now.Add(opts.cooldown)
			d.extend = true
		}
		return d
	}

	if opts.cpuPercent > 0 && cpuPct >= opts.cpuPercent {
		if s.cpuHighSince.IsZero() {
			s.cpuHighSince = now
		}
		if now.Sub(s.cpuHighSince) >= opts.sustain {
			s.downshifted = true
			s.downshiftUntil = now.Add(opts.cooldown)
			s.originalProcs = curProcs
			s.cpuHighSince = time.Time{}
			d.downshift = true
		}
	} else {
		s.cpuHighSince = time.Time{}
	}
	return d
}

// startSelfGuard runs the sampler for the lifetime of the process. It is a
// no-op unless runtime.self_guard is enabled.
func startSelfGuard(lg *zap.Logger, cfg RuntimeConfig, sc *safe_close.SafeClose) error {
	if !cfg.SelfGuard {
		return nil
	}
	if runtime.GOOS != "linux" {
		lg.Warn("self guard disabled: process accounting requires linux /proc",
			zap.String("goos", runtime.GOOS))
		return nil
	}

	opts := guardOptionsFrom(cfg)
	sc.Attach(func(done func(), closeSignal <-chan struct{}) {
		defer done()

		prevCPUTime, err := readProcCPUTime(procStatPath)
		if err != nil {
			lg.Warn("self guard disabled: cannot read process cpu time", zap.Error(err))
			return
		}
		prevAt := time.Now()

		st := &guardState{}
		baselineGoroutines := runtime.NumGoroutine()
		goroutineCeiling := baselineGoroutines * 4
		if goroutineCeiling < guardGoroutineFloor {
			goroutineCeiling = guardGoroutineFloor
		}
		var lastGoroutineWarn time.Time

		ticker := time.NewTicker(opts.interval)
		defer ticker.Stop()

		for {
			select {
			case <-closeSignal:
				if st.downshifted {
					runtime.GOMAXPROCS(st.originalProcs)
				}
				return
			case now := <-ticker.C:
				cpuTime, err := readProcCPUTime(procStatPath)
				if err != nil {
					continue
				}
				rss, err := readRSSBytes(procStatmPath)
				if err != nil {
					continue
				}
				total, err := readMemTotalBytes(procMeminfoPath)
				if err != nil {
					total = 0
				}

				wall := now.Sub(prevAt)
				cpuPct := cpuPercentOfMachine(cpuTime-prevCPUTime, wall, runtime.NumCPU())
				memPct := memoryPercent(rss, total)
				prevCPUTime, prevAt = cpuTime, now

				d := st.decide(now, cpuPct, memPct, opts, runtime.GOMAXPROCS(0))

				if d.scavenge {
					var ms runtime.MemStats
					runtime.ReadMemStats(&ms)
					lg.Warn("self guard: memory pressure, returning pages",
						zap.Uint64("rss_bytes", rss),
						zap.Uint64("system_memory_bytes", total),
						zap.Float64("memory_percent", memPct),
						zap.Uint64("heap_alloc_bytes", ms.HeapAlloc),
						zap.Uint64("heap_inuse_bytes", ms.HeapInuse),
						zap.Int64("memory_limit_bytes", debug.SetMemoryLimit(-1)),
						zap.Int("goroutines", runtime.NumGoroutine()),
					)
					debug.FreeOSMemory()
				}

				if d.downshift {
					runtime.GOMAXPROCS(1)
					lg.Warn("self guard: cpu saturation, downshifting gomaxprocs",
						zap.Float64("cpu_percent_of_machine", cpuPct),
						zap.Int("gomaxprocs_before", st.originalProcs),
						zap.Int("gomaxprocs_after", 1),
						zap.Duration("cooldown", opts.cooldown),
						zap.Int("goroutines", runtime.NumGoroutine()),
					)
				}
				if d.extend {
					lg.Warn("self guard: cpu still saturated, cooldown extended",
						zap.Float64("cpu_percent_of_machine", cpuPct),
						zap.Duration("cooldown", opts.cooldown),
					)
				}
				if d.restore {
					runtime.GOMAXPROCS(st.originalProcs)
					lg.Info("self guard: cpu recovered, gomaxprocs restored",
						zap.Float64("cpu_percent_of_machine", cpuPct),
						zap.Int("gomaxprocs", st.originalProcs),
					)
				}

				if n := runtime.NumGoroutine(); n > goroutineCeiling && now.Sub(lastGoroutineWarn) >= time.Minute {
					lastGoroutineWarn = now
					lg.Warn("self guard: goroutine growth, goroutines cannot be killed from outside",
						zap.Int("goroutines", n),
						zap.Int("baseline", baselineGoroutines),
						zap.Int("ceiling", goroutineCeiling),
					)
				}
			}
		}
	})

	lg.Info("self guard started",
		zap.Float64("cpu_percent_of_machine", opts.cpuPercent),
		zap.Float64("memory_percent", opts.memPercent),
		zap.Duration("interval", opts.interval),
		zap.Duration("sustain", opts.sustain),
		zap.Duration("cooldown", opts.cooldown),
	)
	return nil
}

// readProcCPUTime returns the process's consumed CPU time from /proc/self/stat.
func readProcCPUTime(path string) (time.Duration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	// Fields after the comm field, which is wrapped in parentheses and may itself
	// contain spaces.
	idx := strings.LastIndexByte(string(data), ')')
	if idx <= 0 || idx+2 >= len(data) {
		return 0, fmt.Errorf("unexpected %s format", path)
	}
	fields := strings.Fields(string(data[idx+2:]))
	if len(fields) < 13 {
		return 0, fmt.Errorf("unexpected %s field count: %d", path, len(fields))
	}
	// utime is the 14th field and stime the 15th, i.e. indexes 11 and 12 after
	// the comm field.
	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse utime in %s: %w", path, err)
	}
	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse stime in %s: %w", path, err)
	}
	return ticksToDuration(utime + stime), nil
}

func ticksToDuration(ticks uint64) time.Duration {
	return time.Duration(float64(ticks) / float64(userHZ) * float64(time.Second))
}

// readRSSBytes returns the resident set size from /proc/self/statm.
func readRSSBytes(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, fmt.Errorf("unexpected %s field count: %d", path, len(fields))
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse resident pages in %s: %w", path, err)
	}
	return pages * uint64(os.Getpagesize()), nil
}

// readMemTotalBytes returns MemTotal from /proc/meminfo.
func readMemTotalBytes(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("unexpected MemTotal line in %s", path)
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse MemTotal in %s: %w", path, err)
		}
		return kb * 1024, nil
	}
	return 0, fmt.Errorf("MemTotal not found in %s", path)
}

// cpuPercentOfMachine converts consumed CPU time over a wall interval into a
// percentage of the whole machine's capacity.
func cpuPercentOfMachine(consumed, wall time.Duration, numCPU int) float64 {
	if wall <= 0 || numCPU <= 0 {
		return 0
	}
	return float64(consumed) / float64(wall) / float64(numCPU) * 100
}

func memoryPercent(rss, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(rss) / float64(total) * 100
}
