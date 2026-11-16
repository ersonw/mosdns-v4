package routepolicy

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Runner runs one host command and returns its combined output. Tests supply a
// recording implementation; production reaches the kernel through `ip`.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// Installer applies a Decision to policy routing and takes it back out.
//
// It deliberately owns no nft object: which destinations carry a mark is the
// plugin's own decision, while where that mark leads is the part the plugins
// used to duplicate. Splitting it here is what lets one exit be declared once
// and borrowed by whoever needs it.
type Installer struct {
	runner Runner
}

// NewInstaller returns an installer that reaches the kernel through r.
func NewInstaller(r Runner) *Installer { return &Installer{runner: r} }

// RuleArgs is the single shape of the policy rule, used for add and delete so
// the two can never drift apart.
func RuleArgs(d Decision, action string) []string {
	return []string{
		"rule", action,
		"fwmark", strconv.FormatUint(uint64(d.Mark), 10),
		"lookup", d.Table,
		"prio", strconv.Itoa(d.Priority),
	}
}

// RouteArgs is the single default route a dedicated table holds: everything
// that arrives there is already known to belong to a mapped destination, so
// per-address routes would only duplicate it.
func RouteArgs(d Decision) []string {
	args := []string{"route", "replace", "default"}
	if d.NextHop != "" {
		args = append(args, "via", d.NextHop)
	}
	if d.Dev != "" {
		args = append(args, "dev", d.Dev)
	}
	return append(args, "table", d.Table)
}

// Apply installs the table route and the rule that points at it. Deleting the
// old rule first keeps a restart from leaving a duplicate behind: two rules
// with the same mark both stay in force, and the second one is unreachable.
func (i *Installer) Apply(ctx context.Context, d Decision) error {
	if d.Mark == 0 {
		return fmt.Errorf("route install needs a mark, %s has none", d)
	}
	if d.Table == "" {
		return fmt.Errorf("route install needs a table, %s has none", d)
	}
	if d.NextHop == "" && d.Dev == "" {
		return fmt.Errorf("route install needs a next hop or a device, %s has neither", d)
	}

	route := RouteArgs(d)
	if _, err := i.runner.Run(ctx, "ip", route...); err != nil {
		return fmt.Errorf("ip %s: %w", strings.Join(route, " "), err)
	}

	_, _ = i.runner.Run(ctx, "ip", RuleArgs(d, "del")...)
	rule := RuleArgs(d, "add")
	if _, err := i.runner.Run(ctx, "ip", rule...); err != nil {
		return fmt.Errorf("ip %s: %w", strings.Join(rule, " "), err)
	}
	return nil
}

// Remove drops the rule and the table route. A missing rule or route is the
// normal case for a plugin that never installed or was already cleaned up, so
// the caller only logs the first error instead of failing startup.
func (i *Installer) Remove(ctx context.Context, d Decision) error {
	if d.Mark == 0 || d.Table == "" {
		return nil
	}
	var first error
	if _, err := i.runner.Run(ctx, "ip", RuleArgs(d, "del")...); err != nil && first == nil {
		first = err
	}
	if _, err := i.runner.Run(ctx, "ip", "route", "del", "default", "table", d.Table); err != nil && first == nil {
		first = err
	}
	return first
}
