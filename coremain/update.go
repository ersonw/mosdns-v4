package coremain

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/configmigrate"
	"github.com/ersonw/mosdns-v4/pkg/selfupdate"
	"go.uber.org/zap"
)

// UpdateConfig is the optional `update:` block:
//
//	update:
//	  enabled: true
//	  repo: ersonw/mosdns-v4
//	  interval: 6h
//	  asset: mosdns-linux-amd64
//	  checksum_asset: SHA256SUMS.txt
//	  proxy: ""                # http:// or socks5:// when GitHub needs a hop
//	  dry_run: false           # download and validate, never swap
//
// The updater polls the repository's newest release, and when it is newer than
// the running binary it downloads it, migrates the configuration for the new
// schema, has the downloaded binary validate that configuration, and only then
// schedules the swap. The swap itself runs detached from this process because
// it ends with a service restart.
type UpdateConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Repo          string `yaml:"repo"`
	Interval      string `yaml:"interval"`
	Asset         string `yaml:"asset"`
	ChecksumAsset string `yaml:"checksum_asset"`
	Proxy         string `yaml:"proxy"`
	DryRun        bool   `yaml:"dry_run"`

	// Where the running binary and config live. Empty means the defaults below,
	// which match the systemd unit this project ships.
	BinaryPath  string `yaml:"binary_path"`
	ConfigPath  string `yaml:"config_path"`
	ServiceName string `yaml:"service_name"`
}

func (c UpdateConfig) interval() time.Duration {
	if c.Interval != "" {
		if d, err := time.ParseDuration(c.Interval); err == nil && d >= 5*time.Minute {
			return d
		}
	}
	return 6 * time.Hour
}

// asset defaults to this build target: the release publishes one asset per
// platform under the same name the cross build produced, so a router running
// linux/amd64 asks for mosdns-linux-amd64 without being told.
func (c UpdateConfig) asset() string {
	if c.Asset != "" {
		return c.Asset
	}
	return selfupdate.CurrentAsset()
}

func (c UpdateConfig) checksumAsset() string {
	if c.ChecksumAsset != "" {
		return c.ChecksumAsset
	}
	return "SHA256SUMS.txt"
}

func (c UpdateConfig) binaryPath() string {
	if c.BinaryPath != "" {
		return c.BinaryPath
	}
	return "/usr/local/bin/mosdns"
}

func (c UpdateConfig) serviceName() string {
	if c.ServiceName != "" {
		return c.ServiceName
	}
	return "mosdns"
}

// buildVersion is the version stamped at link time. The updater compares the
// release tag against it, so it has to see exactly what the binary reports.
var buildVersion = "dev"

func SetBuildVersion(v string) {
	if v != "" {
		buildVersion = v
	}
}

func BuildVersion() string { return buildVersion }

type updater struct {
	cfg     UpdateConfig
	cfgPath string
	l       *zap.Logger
}

// startUpdateLoop spawns the polling loop. It waits one interval before the
// first check: a binary that was just started by an operator should not be
// replaced under their feet moments later.
// startUpdateLoop is called from RunMosdns, after the logger has been built
// from the config: starting it earlier sent its first lines to the default
// stderr logger, which a service does not have.
func startUpdateLoop(ctx context.Context, cfg *Config, lg *zap.Logger) {
	if !cfg.Update.Enabled {
		return
	}
	if cfg.Update.Repo == "" {
		lg.Warn("update: enabled without a repo, the loop stays off")
		return
	}
	cfgPath := cfg.Update.ConfigPath
	if cfgPath == "" {
		cfgPath = cfg.configPath
	}
	u := &updater{cfg: cfg.Update, cfgPath: cfgPath, l: lg.Named("update")}
	go u.loop(ctx)
}

func (u *updater) loop(ctx context.Context) {
	interval := u.cfg.interval()
	u.l.Info("update loop started",
		zap.String("repo", u.cfg.Repo),
		zap.Duration("interval", interval),
		zap.String("version", BuildVersion()),
		zap.Bool("dry_run", u.cfg.DryRun))

	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			u.checkOnce(ctx)
			timer.Reset(interval)
		}
	}
}

// checkOnce performs one full check. Every failure is logged and swallowed:
// a router must keep serving DNS whether or not GitHub is reachable.
func (u *updater) checkOnce(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	client := selfupdate.Client(u.cfg.Proxy)
	rel, err := selfupdate.LatestRelease(ctx, client, u.cfg.Repo)
	if err != nil {
		u.l.Warn("update: cannot read the latest release", zap.Error(err))
		return
	}
	if rel.Prerelease {
		u.l.Debug("update: newest release is a prerelease, skipped", zap.String("tag", rel.TagName))
		return
	}
	if !selfupdate.Newer(BuildVersion(), rel.TagName) {
		u.l.Debug("update: already current", zap.String("running", BuildVersion()), zap.String("latest", rel.TagName))
		return
	}
	u.l.Info("update: a newer release exists",
		zap.String("running", BuildVersion()), zap.String("latest", rel.TagName))

	dir := filepath.Join(filepath.Dir(u.cfgPath), ".update-"+time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		u.l.Error("update: cannot create a work directory", zap.Error(err))
		return
	}

	newBin := filepath.Join(dir, "mosdns.new")
	f, err := os.OpenFile(newBin, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		u.l.Error("update: cannot create the download target", zap.Error(err))
		return
	}
	sha, dlErr := selfupdate.Download(ctx, client, selfupdate.AssetURL(u.cfg.Repo, rel.TagName, u.cfg.asset()), f)
	closeErr := f.Close()
	if dlErr != nil {
		u.l.Warn("update: download failed", zap.Error(dlErr))
		_ = os.RemoveAll(dir)
		return
	}
	if closeErr != nil {
		u.l.Warn("update: cannot finish writing the download", zap.Error(closeErr))
		_ = os.RemoveAll(dir)
		return
	}

	if err := u.verifyChecksum(ctx, client, rel.TagName, sha); err != nil {
		u.l.Error("update: the download does not match its published checksum, refusing it", zap.Error(err))
		_ = os.RemoveAll(dir)
		return
	}

	// The new schema may reject the current file, and the swap has no way back
	// once the service restarted, so the config is migrated and validated first.
	migratedCfg, applied, err := u.migrateConfig(rel.TagName)
	if err != nil {
		u.l.Error("update: cannot migrate the config for the new release", zap.Error(err))
		_ = os.RemoveAll(dir)
		return
	}
	tmpCfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(tmpCfg, migratedCfg, 0o644); err != nil {
		u.l.Error("update: cannot write the migrated config", zap.Error(err))
		_ = os.RemoveAll(dir)
		return
	}
	if len(applied) > 0 {
		u.l.Info("update: config migrated", zap.Strings("steps", applied))
	}

	if err := u.validateWithNewBinary(ctx, newBin, tmpCfg); err != nil {
		u.l.Error("update: the new binary rejects the migrated config, nothing will be replaced", zap.Error(err))
		_ = os.RemoveAll(dir)
		return
	}

	if u.cfg.DryRun {
		u.l.Info("update: dry run, the release is valid but will not be installed",
			zap.String("tag", rel.TagName), zap.String("dir", dir))
		return
	}

	script := filepath.Join(dir, "install.sh")
	if err := os.WriteFile(script, []byte(u.installScript(dir, newBin, tmpCfg, rel.TagName)), 0o700); err != nil {
		u.l.Error("update: cannot write the install script", zap.Error(err))
		_ = os.RemoveAll(dir)
		return
	}
	if err := launchInstallerScript(script); err != nil {
		u.l.Error("update: cannot start the install script", zap.Error(err))
		_ = os.RemoveAll(dir)
		return
	}
	u.l.Info("update: install scheduled, the service restarts with the new release",
		zap.String("tag", rel.TagName), zap.String("script", script))
}

// verifyChecksum compares the download against the checksum file published
// next to it. A missing entry is not fatal (an older release may predate the
// checksum asset), but a mismatch is: a truncated binary would only fail later,
// as a service that will not come back.
func (u *updater) verifyChecksum(ctx context.Context, client *http.Client, tag, sha string) error {
	url := selfupdate.AssetURL(u.cfg.Repo, tag, u.cfg.checksumAsset())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "mosdns-selfupdate")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot fetch %s, %w", u.cfg.checksumAsset(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		u.l.Warn("update: the release publishes no checksums, skipping verification", zap.String("asset", u.cfg.checksumAsset()))
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("checksum download returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	want, ok := selfupdate.ChecksumFor(body, u.cfg.asset())
	if !ok {
		u.l.Warn("update: the checksum file does not list this asset, skipping verification", zap.String("asset", u.cfg.asset()))
		return nil
	}
	if !strings.EqualFold(want, sha) {
		return fmt.Errorf("sha256 mismatch: downloaded %s, published %s", sha, want)
	}
	return nil
}

// migrateConfig runs the built-in migration chain from the running version to
// the release about to be installed.
func (u *updater) migrateConfig(tag string) ([]byte, []string, error) {
	data, err := os.ReadFile(u.cfgPath)
	if err != nil {
		return nil, nil, err
	}
	return configmigrate.Migrate(data, BuildVersion(), tag)
}

// validateWithNewBinary runs the downloaded binary's own parser over the
// migrated file. Only the binary that is about to serve traffic can judge
// whether it accepts that configuration.
func (u *updater) validateWithNewBinary(ctx context.Context, bin, cfg string) error {
	cmd := exec.CommandContext(ctx, bin, "check-config", "-d", filepath.Dir(u.cfgPath), "-c", cfg)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	msg := strings.TrimSpace(string(out))
	if strings.Contains(msg, "unknown command") || strings.Contains(msg, "unknown flag") {
		u.l.Warn("update: the release has no check-config command, relying on the checksum only", zap.String("output", msg))
		return nil
	}
	return fmt.Errorf("%w: %s", err, msg)
}

// installScript is the part that cannot run inside the process it replaces: it
// backs up both the binary and the config, restarts the service, and puts
// everything back if the new binary does not come up.
func (u *updater) installScript(dir, newBin, newCfg, tag string) string {
	stay := u.cfg.binaryPath()
	svc := u.cfg.serviceName()
	log := filepath.Join(filepath.Dir(u.cfgPath), "update.log")
	ts := time.Now().Format("20060102-150405")
	var b strings.Builder
	fmt.Fprintf(&b, `#!/bin/sh
# Generated by mosdns self-update for %s. Runs detached because it restarts the
# service that spawned it.
set -u
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
BIN='%s'
CFG='%s'
NEW='%s'
NEWCFG='%s'
TS='%s'
LOG='%s'
DIR='%s'

cp -a "$BIN" "$BIN.bak-$TS" || exit 1
cp -a "$CFG" "$CFG.bak-$TS" || exit 1
install -m 755 -o root -g root "$NEW" "$BIN" || { cp -a "$BIN.bak-$TS" "$BIN"; exit 1; }
if [ -f "$NEWCFG" ]; then
	install -m 644 -o root -g root "$NEWCFG" "$CFG"
fi
systemctl restart '%s'
sleep 10
if systemctl is-active --quiet '%s'; then
	echo "$(date -Is) installed %s" >> "$LOG"
	rm -rf "$DIR"
else
	install -m 755 -o root -g root "$BIN.bak-$TS" "$BIN"
	install -m 644 -o root -g root "$CFG.bak-$TS" "$CFG"
	systemctl restart '%s'
	echo "$(date -Is) rolled back %s" >> "$LOG"
fi
`, tag, stay, u.cfgPath, newBin, newCfg, ts, log, dir, svc, svc, tag, svc, tag)
	return b.String()
}
