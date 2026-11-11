/*
 * RADIUS server for ocserv.
 *
 * ocserv authenticates against a RADIUS server when it is configured with
 * "auth = radius". This plugin is that server: it owns the account table and
 * answers Access-Request (PAP) and Accounting-Request, so accounts are managed
 * from the bot instead of ocserv's own ocpasswd file.
 *
 * It is registered as an executable plugin so the bot can reach it through
 * Mosdns.GetExecutables(); on the DNS path it is a pass-through and is never
 * referenced by a sequence.
 */

package radius

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/ersonw/mosdns-v4/coremain"
	"github.com/ersonw/mosdns-v4/pkg/executable_seq"
	"github.com/ersonw/mosdns-v4/pkg/query_context"
	"go.uber.org/zap"
)

const PluginType = "radius"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var (
	_ coremain.ExecutablePlugin = (*Plugin)(nil)
	_ Admin                     = (*Plugin)(nil)
)

// Args configures the listener, the shared secret and the account database.
type Args struct {
	// Listen is the authentication endpoint. Default "0.0.0.0:1812".
	Listen string `yaml:"listen"`
	// AccountingListen is the accounting endpoint. Default "0.0.0.0:1813";
	// "" or "off" disables accounting, which makes ocserv retry and log errors.
	AccountingListen string `yaml:"accounting_listen"`
	// Secret is the shared secret from the ocserv radius section. Required.
	Secret string `yaml:"secret"`
	// DBPath is the SQLite file holding accounts and sessions.
	// Default "radius.db" next to the process working directory.
	DBPath string `yaml:"db_path"`
}

func (a *Args) initDefault() error {
	a.Listen = strings.TrimSpace(a.Listen)
	if a.Listen == "" {
		a.Listen = "0.0.0.0:1812"
	}
	a.AccountingListen = strings.TrimSpace(a.AccountingListen)
	if a.AccountingListen == "" {
		a.AccountingListen = "0.0.0.0:1813"
	}
	if a.AccountingListen == "off" || a.AccountingListen == "0" {
		a.AccountingListen = ""
	}
	a.Secret = strings.TrimSpace(a.Secret)
	if a.Secret == "" {
		return fmt.Errorf("secret is required: ocserv has to share it")
	}
	a.DBPath = strings.TrimSpace(a.DBPath)
	if a.DBPath == "" {
		a.DBPath = "radius.db"
	}
	if _, err := net.ResolveUDPAddr("udp", a.Listen); err != nil {
		return fmt.Errorf("invalid listen address %q: %w", a.Listen, err)
	}
	if a.AccountingListen != "" {
		if _, err := net.ResolveUDPAddr("udp", a.AccountingListen); err != nil {
			return fmt.Errorf("invalid accounting_listen address %q: %w", a.AccountingListen, err)
		}
	}
	return nil
}

// User is one account as exposed to the admin surface.
type User struct {
	Name      string
	Group     string
	Enabled   bool
	CreatedAt int64
	UpdatedAt int64
}

// Session is one accounting session as exposed to the admin surface.
type Session struct {
	SessionID string
	Name      string
	RemoteIP  string
	StartedAt int64
	UpdatedAt int64
	EndedAt   int64
	In        int64
	Out       int64
	Active    bool
}

// Admin is the interface telegram_bot type-asserts against. Keeping it in this
// package means the bot only depends on the method set, not the internals.
type Admin interface {
	Users() ([]User, error)
	AddUser(name, password, group string) error
	DeleteUser(name string) (bool, error)
	SetPassword(name, password string) (bool, error)
	SetEnabled(name string, enabled bool) (bool, error)
	Sessions(activeOnly bool, limit int) ([]Session, error)
}

type Plugin struct {
	*coremain.BP
	args  *Args
	store *store
	srv   *server
}

func Init(bp *coremain.BP, args interface{}) (coremain.Plugin, error) {
	a, ok := args.(*Args)
	if !ok {
		return nil, fmt.Errorf("radius: unexpected args type %T", args)
	}
	if err := a.initDefault(); err != nil {
		return nil, err
	}

	st, err := openStore(a.DBPath)
	if err != nil {
		return nil, err
	}
	srv, err := newServer(bp.L(), []byte(a.Secret), st, a.Listen, a.AccountingListen)
	if err != nil {
		_ = st.close()
		return nil, fmt.Errorf("radius: %w", err)
	}

	p := &Plugin{BP: bp, args: a, store: st, srv: srv}
	srv.start()

	users, _ := st.listUsers()
	p.L().Info("radius: plugin initialized",
		zap.String("db_path", a.DBPath),
		zap.String("listen", a.Listen),
		zap.String("accounting_listen", a.AccountingListen),
		zap.Int("users", len(users)),
	)
	return p, nil
}

// Exec is a pass-through: this plugin is a service, not a query-chain step.
func (p *Plugin) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (p *Plugin) Close() error {
	if p.srv != nil {
		p.srv.close()
	}
	if p.store != nil {
		if err := p.store.close(); err != nil {
			p.L().Warn("radius: close database failed", zap.Error(err))
		}
	}
	p.L().Info("radius: plugin closed")
	return nil
}

// Users lists every account, ordered by name.
func (p *Plugin) Users() ([]User, error) {
	rows, err := p.store.listUsers()
	if err != nil {
		return nil, err
	}
	out := make([]User, 0, len(rows))
	for _, r := range rows {
		out = append(out, User{
			Name: r.Name, Group: r.Group, Enabled: r.Enabled,
			CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt,
		})
	}
	return out, nil
}

// AddUser creates an account. Names and passwords are validated here so the bot
// does not have to duplicate the rules.
func (p *Plugin) AddUser(name, password, group string) error {
	if err := validateCredentials(name, password); err != nil {
		return err
	}
	if err := p.store.addUser(name, password, strings.TrimSpace(group)); err != nil {
		return err
	}
	p.L().Info("radius: user added", zap.String("user", name), zap.String("group", strings.TrimSpace(group)))
	return nil
}

func (p *Plugin) DeleteUser(name string) (bool, error) {
	ok, err := p.store.deleteUser(name)
	if err != nil {
		return false, err
	}
	if ok {
		p.L().Info("radius: user deleted", zap.String("user", name))
	}
	return ok, nil
}

func (p *Plugin) SetPassword(name, password string) (bool, error) {
	if err := validatePassword(password); err != nil {
		return false, err
	}
	ok, err := p.store.setPassword(name, password)
	if err != nil {
		return false, err
	}
	if ok {
		p.L().Info("radius: password changed", zap.String("user", name))
	}
	return ok, nil
}

func (p *Plugin) SetEnabled(name string, enabled bool) (bool, error) {
	ok, err := p.store.setEnabled(name, enabled)
	if err != nil {
		return false, err
	}
	if ok {
		p.L().Info("radius: user toggled", zap.String("user", name), zap.Bool("enabled", enabled))
	}
	return ok, nil
}

// SetGroup changes the class attribute handed to ocserv.
func (p *Plugin) SetGroup(name, group string) (bool, error) {
	ok, err := p.store.setGroup(name, strings.TrimSpace(group))
	if err != nil {
		return false, err
	}
	if ok {
		p.L().Info("radius: group changed", zap.String("user", name), zap.String("group", group))
	}
	return ok, nil
}

func (p *Plugin) Sessions(activeOnly bool, limit int) ([]Session, error) {
	rows, err := p.store.listSessions(activeOnly, limit)
	if err != nil {
		return nil, err
	}
	out := make([]Session, 0, len(rows))
	for _, r := range rows {
		out = append(out, Session{
			SessionID: r.SessionID, Name: r.Name, RemoteIP: r.RemoteIP,
			StartedAt: r.StartedAt, UpdatedAt: r.UpdatedAt, EndedAt: r.EndedAt,
			In: r.InOctets, Out: r.OutOctets, Active: r.Active,
		})
	}
	return out, nil
}

func validateCredentials(name, password string) error {
	if err := validateName(name); err != nil {
		return err
	}
	return validatePassword(password)
}

func validateName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return fmt.Errorf("name is empty")
	}
	if trimmed != name {
		return fmt.Errorf("name has leading or trailing spaces")
	}
	if len(name) > 64 {
		return fmt.Errorf("name is longer than 64 characters")
	}
	for _, r := range name {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("name contains a space or control character")
		}
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 6 {
		return fmt.Errorf("password is shorter than 6 characters")
	}
	if len(password) > 128 {
		return fmt.Errorf("password is longer than 128 characters")
	}
	for _, r := range password {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("password contains a space or control character")
		}
	}
	return nil
}
