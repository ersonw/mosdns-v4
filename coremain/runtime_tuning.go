package coremain

// The Go runtime is not built for a box that shares its memory and CPU with the
// packet path. Without a ceiling the heap is allowed to double before every GC,
// and freed spans stay mapped to the process because the kernel is only asked
// to reclaim them lazily (MADV_FREE). On a router that reads as "RSS keeps
// climbing after a day". The `runtime:` block lets the operator state the
// ceiling, the GC target and the scavenge period instead of hoping the defaults
// fit.

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/safe_close"
	"go.uber.org/zap"
)

// minimumScavengeInterval keeps a misconfigured value from turning the
// scavenge, which is a stop-the-world GC, into a CPU consumer of its own.
const minimumScavengeInterval = time.Minute

// applyRuntimeConfig applies the non-zero fields of the runtime block. Called
// once, before any plugin is loaded, so every later allocation already sees the
// limits.
func applyRuntimeConfig(cfg RuntimeConfig) error {
	if cfg.MaxProcs > 0 {
		runtime.GOMAXPROCS(cfg.MaxProcs)
	}
	if cfg.GCPercent > 0 {
		debug.SetGCPercent(cfg.GCPercent)
	}
	if len(cfg.MemoryLimit) > 0 {
		limit, err := parseMemorySize(cfg.MemoryLimit)
		if err != nil {
			return fmt.Errorf("invalid runtime.memory_limit %q: %w", cfg.MemoryLimit, err)
		}
		if limit <= 0 {
			return fmt.Errorf("invalid runtime.memory_limit %q: must be positive", cfg.MemoryLimit)
		}
		debug.SetMemoryLimit(limit)
	}
	return nil
}

// logRuntimeSettings reports what the process is actually running with, so the
// configuration can be checked from the log instead of from a graph.
func logRuntimeSettings(lg *zap.Logger, cfg RuntimeConfig) {
	lg.Info("runtime configured",
		zap.Int("gomaxprocs", runtime.GOMAXPROCS(0)),
		zap.Int("cpu_count", runtime.NumCPU()),
		zap.String("gc_percent", gcPercentSetting(cfg)),
		zap.Int64("memory_limit_bytes", debug.SetMemoryLimit(-1)),
		zap.Duration("scavenge_interval", scavengeInterval(cfg)),
	)
}

// gcPercentSetting reports the effective GOGC without reading it back: the only
// way to ask the runtime is SetGCPercent(-1), which would disable the
// collector, so the configured value is reported instead.
func gcPercentSetting(cfg RuntimeConfig) string {
	if cfg.GCPercent > 0 {
		return strconv.Itoa(cfg.GCPercent)
	}
	return "default(100)"
}

func scavengeInterval(cfg RuntimeConfig) time.Duration {
	if len(cfg.ScavengeInterval) == 0 {
		return 0
	}
	interval, err := time.ParseDuration(cfg.ScavengeInterval)
	if err != nil || interval < minimumScavengeInterval {
		return 0
	}
	return interval
}

// startMemoryGovernor returns freed pages to the OS on a timer. Go keeps them
// mapped by design, which is why RSS on a router only grows; a periodic
// FreeOSMemory is the only way to hand them back without restarting the
// process. Every pass also logs the heap, so a slow climb shows up in the log
// long before the box runs out of memory.
func startMemoryGovernor(lg *zap.Logger, cfg RuntimeConfig, sc *safe_close.SafeClose) error {
	interval := scavengeInterval(cfg)
	if interval == 0 {
		if len(cfg.ScavengeInterval) > 0 {
			return fmt.Errorf("invalid runtime.scavenge_interval %q: must parse and be >= %s", cfg.ScavengeInterval, minimumScavengeInterval)
		}
		return nil
	}

	sc.Attach(func(done func(), closeSignal <-chan struct{}) {
		defer done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-closeSignal:
				return
			case <-ticker.C:
				var ms runtime.MemStats
				runtime.ReadMemStats(&ms)
				lg.Info("runtime memory",
					zap.Uint64("heap_alloc_bytes", ms.HeapAlloc),
					zap.Uint64("heap_inuse_bytes", ms.HeapInuse),
					zap.Uint64("heap_released_bytes", ms.HeapReleased),
					zap.Uint64("sys_bytes", ms.Sys),
					zap.Uint32("num_gc", ms.NumGC),
					zap.Int("goroutines", runtime.NumGoroutine()),
				)
				// FreeOSMemory runs a GC and then returns the unused spans to the
				// kernel, which is exactly what MADV_FREE would only do under
				// memory pressure.
				debug.FreeOSMemory()
			}
		}
	})
	lg.Info("runtime memory governor started", zap.Duration("interval", interval))
	return nil
}

// parseMemorySize parses "256MiB", "256MB", "1G" or a plain byte count.
func parseMemorySize(raw string) (int64, error) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	units := []struct {
		suffix string
		scale  int64
	}{
		{"GIB", 1 << 30}, {"MIB", 1 << 20}, {"KIB", 1 << 10},
		{"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10},
		{"GI", 1 << 30}, {"MI", 1 << 20}, {"KI", 1 << 10},
		{"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10},
		{"B", 1},
	}
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			value := strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			n, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return 0, fmt.Errorf("parse %q as a number: %w", value, err)
			}
			if n < 0 {
				return 0, fmt.Errorf("negative size %q", raw)
			}
			return int64(n * float64(u.scale)), nil
		}
	}
	return strconv.ParseInt(s, 10, 64)
}
