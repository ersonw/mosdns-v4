package configmigrate

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMigrateAppliesOnlyTheNeededSteps(t *testing.T) {
	registry = nil
	Register(Migration{
		From: "v4.0.4", To: "v4.0.5", Describe: "rename old to new",
		Apply: func(root *yaml.Node) error {
			return renameKey(root, "old", "new")
		},
	})
	Register(Migration{
		From: "v4.0.5", To: "v4.0.6", Describe: "add another",
		Apply: func(*yaml.Node) error { return nil },
	})

	out, applied, err := Migrate([]byte("old: 1\n"), "v4.0.4", "v4.0.6")
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 2 {
		t.Fatalf("applied %q, want both steps", applied)
	}
	if !strings.Contains(string(out), "new: 1") {
		t.Fatalf("rename did not run:\n%s", out)
	}

	// At the same version nothing may be rewritten.
	out2, applied2, err := Migrate([]byte("new: 1\n"), "v4.0.6", "v4.0.6")
	if err != nil {
		t.Fatal(err)
	}
	if len(applied2) != 0 || string(out2) != "new: 1\n" {
		t.Fatalf("same version was rewritten: %q %v", out2, applied2)
	}

	// A dev build of the newest tag must not be downgraded by migrations.
	out3, applied3, err := Migrate([]byte("new: 1\n"), "dev/v4.0.6-2-gabc", "v4.0.6")
	if err != nil || len(applied3) != 0 || string(out3) != "new: 1\n" {
		t.Fatalf("dev build at the newest tag was rewritten: %q %v %v", out3, applied3, err)
	}
}

func TestMigrateRejectsUnknownVersion(t *testing.T) {
	if _, _, err := Migrate([]byte("a: 1\n"), "dev", "v4.0.5"); err == nil {
		t.Fatal("an unparseable version must be refused, not guessed")
	}
}

// renameKey is the smallest useful migration: it moves a top-level key, which
// is the shape a key rename takes in this project's config.
func renameKey(root *yaml.Node, from, to string) error {
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil
	}
	m := root.Content[0]
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == from {
			m.Content[i].Value = to
		}
	}
	return nil
}
