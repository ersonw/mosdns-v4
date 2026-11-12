package coremain_test

import (
	"os"
	"testing"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/utils"
	_ "github.com/ersonw/mosdns-v4/plugin"
	"gopkg.in/yaml.v3"
)

// The exhaustive example is the list of keys the binary accepts, so it must be
// decoded the same way startup does: mapstructure with ErrorUnused over the
// registered args type of every plugin. A renamed or misspelled field, a
// missing plugin type, or a type that was added to the binary but never shown
// in the example all fail here instead of at a customer's startup.
func TestFullExampleConfigDecodes(t *testing.T) {
	const path = "../etc/mosdns/config-full.yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var cfg coremain.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(cfg.Plugins) == 0 {
		t.Fatalf("%s declares no plugin", path)
	}
	if len(cfg.Servers) == 0 {
		t.Errorf("%s declares no server", path)
	}

	seen := make(map[string]string, len(cfg.Plugins))
	for _, pc := range cfg.Plugins {
		if pc.Tag == "" || pc.Type == "" {
			t.Errorf("plugin entry with empty tag or type: %+v", pc)
			continue
		}
		if prev, dup := seen[pc.Tag]; dup {
			t.Errorf("duplicate tag %q: %s and %s", pc.Tag, prev, pc.Type)
		}
		seen[pc.Tag] = pc.Type

		info, ok := coremain.GetPluginType(pc.Type)
		if !ok {
			t.Errorf("plugin %q: type %q is not registered", pc.Tag, pc.Type)
			continue
		}
		if info.NewArgs == nil || pc.Args == nil {
			continue
		}
		argsMap, ok := pc.Args.(map[string]interface{})
		if !ok {
			t.Errorf("plugin %q: args decoded as %T, want a mapping", pc.Tag, pc.Args)
			continue
		}
		if err := utils.WeakDecode(argsMap, info.NewArgs()); err != nil {
			t.Errorf("plugin %q (%s): cannot decode args: %v", pc.Tag, pc.Type, err)
		}
	}

	types := coremain.GetAllPluginTypes()
	if len(types) < 20 {
		// A low number means the plugin packages were not registered in this
		// test binary, which would make the coverage loop below a no-op.
		t.Fatalf("only %d plugin types registered, want at least 20", len(types))
	}
	for _, typ := range types {
		found := false
		for _, pc := range cfg.Plugins {
			if pc.Type == typ {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("plugin type %q has no instance in %s", typ, path)
		}
	}
}
