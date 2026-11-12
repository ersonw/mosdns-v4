// Package timeutil centralizes the timezone used to render stored Unix
// timestamps. Databases keep seconds since the epoch, which are timezone
// independent; only the presentation layer needs a location.
package timeutil

import (
	"fmt"
	"strings"
	"time"
)

// Default is the timezone used when a plugin does not configure one.
const Default = "Asia/Shanghai"

// Load resolves a timezone name. An empty name means Default. If the system
// zoneinfo database lacks Asia/Shanghai, the fixed +08:00 zone is used so a
// minimal router image still renders local time instead of failing startup.
func Load(name string) (*time.Location, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = Default
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		if name == Default {
			return time.FixedZone("CST", 8*60*60), nil
		}
		return nil, fmt.Errorf("load timezone %q: %w", name, err)
	}
	return loc, nil
}

// MustDefault returns Default and never fails.
func MustDefault() *time.Location {
	loc, err := Load("")
	if err != nil {
		return time.FixedZone("CST", 8*60*60)
	}
	return loc
}

// FormatUnix renders Unix seconds in loc. Non-positive values are empty.
func FormatUnix(ts int64, layout string, loc *time.Location) string {
	if ts <= 0 {
		return ""
	}
	if loc == nil {
		loc = time.FixedZone("CST", 8*60*60)
	}
	return time.Unix(ts, 0).In(loc).Format(layout)
}
