package routepolicy

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type recorded struct {
	cmd  string
	args []string
}

type fakeRunner struct {
	calls []recorded
	fail  func(name string, args []string) error
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, recorded{cmd: name, args: append([]string(nil), args...)})
	if f.fail != nil {
		return "", f.fail(name, args)
	}
	return "", nil
}

func (f *fakeRunner) joined() []string {
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, strings.Join(append([]string{c.cmd}, c.args...), " "))
	}
	return out
}

func TestApplyInstallsRouteThenRule(t *testing.T) {
	r := &fakeRunner{}
	i := NewInstaller(r)
	d := Decision{Mark: 0x7e, Table: "126", Priority: 1001, NextHop: "11.10.12.1", Dev: "wg0"}
	if err := i.Apply(context.Background(), d); err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	want := []string{
		"ip route replace default via 11.10.12.1 dev wg0 table 126",
		"ip rule del fwmark 126 lookup 126 prio 1001",
		"ip rule add fwmark 126 lookup 126 prio 1001",
	}
	got := r.joined()
	if len(got) != len(want) {
		t.Fatalf("ran %d commands, want %d: %v", len(got), len(want), got)
	}
	for idx := range want {
		if got[idx] != want[idx] {
			t.Fatalf("command %d = %q, want %q", idx, got[idx], want[idx])
		}
	}
}

func TestApplyRejectsDecisionsTheKernelCannotUse(t *testing.T) {
	cases := []struct {
		name string
		d    Decision
		want string
	}{
		{"no mark", Decision{Table: "126", Dev: "wg0"}, "needs a mark"},
		{"no table", Decision{Mark: 1, Dev: "wg0"}, "needs a table"},
		{"no destination", Decision{Mark: 1, Table: "126"}, "next hop or a device"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := NewInstaller(&fakeRunner{}).Apply(context.Background(), c.d)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want an error containing %q", err, c.want)
			}
		})
	}
}

func TestApplyStopsWhenTheRuleCannotBeInstalled(t *testing.T) {
	r := &fakeRunner{fail: func(_ string, args []string) error {
		if len(args) > 0 && args[0] == "rule" && args[1] == "add" {
			return errors.New("RTNETLINK answers: File exists")
		}
		return nil
	}}
	err := NewInstaller(r).Apply(context.Background(), Decision{Mark: 1, Table: "9", Dev: "wg0"})
	if err == nil || !strings.Contains(err.Error(), "File exists") {
		t.Fatalf("got %v, want the rule failure to be returned", err)
	}
}

func TestRemoveDropsRuleAndRoute(t *testing.T) {
	r := &fakeRunner{}
	if err := NewInstaller(r).Remove(context.Background(), Decision{Mark: 126, Table: "126", Priority: 1001}); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	want := []string{
		"ip rule del fwmark 126 lookup 126 prio 1001",
		"ip route del default table 126",
	}
	got := r.joined()
	for idx := range want {
		if got[idx] != want[idx] {
			t.Fatalf("command %d = %q, want %q", idx, got[idx], want[idx])
		}
	}
}

func TestRemoveOfAnUnusedExitIsSilent(t *testing.T) {
	r := &fakeRunner{}
	if err := NewInstaller(r).Remove(context.Background(), Decision{}); err != nil {
		t.Fatalf("remove of an empty exit returned %v", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("remove of an empty exit ran commands: %v", r.joined())
	}
}
