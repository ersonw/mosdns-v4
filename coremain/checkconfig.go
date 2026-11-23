package coremain

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// CheckConfigFile parses a config file exactly the way a start would, and
// reports schema problems without opening a listener, a database or a tunnel.
// The updater calls this on the migrated config through the binary it is about
// to install, which is the only trustworthy opinion about that schema.
func CheckConfigFile(dir, path string) error {
	_, err := LoadConfigFile(dir, path)
	return err
}

// LoadConfigFile parses a config file into the same Config a start would build,
// without opening anything. The updater CLI needs the update block from the
// operator's own file rather than a flag for every field.
func LoadConfigFile(dir, path string) (*Config, error) {
	if dir != "" {
		if err := os.Chdir(dir); err != nil {
			return nil, fmt.Errorf("failed to change the current working directory, %w", err)
		}
	}

	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file, %w", err)
	}

	cfg := new(Config)
	if err := v.Unmarshal(cfg, decoderOpt); err != nil {
		return nil, fmt.Errorf("failed to parse config file, %w", err)
	}
	cfg.configDir = filepath.Dir(v.ConfigFileUsed())
	cfg.configPath = v.ConfigFileUsed()
	if err := mergeInclude(cfg, 0, []string{cfg.configPath}, []string{tryGetAbsPath(cfg.configPath)}); err != nil {
		return nil, fmt.Errorf("failed to load sub config file, %w", err)
	}
	if err := cfg.prepareProxyProvides(); err != nil {
		return nil, err
	}
	return cfg, nil
}
