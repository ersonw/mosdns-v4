package radius

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	pbkdf2Iterations = 12000 // cheap enough for a login, slow enough for a dump
	pbkdf2KeyLen     = 32
	userTableName    = "radius_users"
	sessionTableName = "radius_sessions"
)

// errUserExists is returned by AddUser when the name is already taken.
var errUserExists = errors.New("radius: user already exists")

// errIPInUse is returned when a fixed address is already pinned to another
// account. ocserv would hand the same tunnel address to two users otherwise.
var errIPInUse = errors.New("radius: ip already assigned to another user")

// errInvalidIP is returned for anything that is not a usable IPv4 address.
var errInvalidIP = errors.New("radius: invalid ipv4 address")

// userRow is one account, as stored and as handed to the admin surface.
type userRow struct {
	Name      string
	Password  string // the stored hash, never the plaintext
	Group     string
	IP        string // fixed tunnel address, empty means "from the pool"
	Enabled   bool
	CreatedAt int64
	UpdatedAt int64
	// Quota counters are bytes. MaxTotal == 0 means unlimited, ResetPeriod ==
	// 0 means the counter is never reset automatically.
	UsedIn        int64
	UsedOut       int64
	MaxTotal      int64
	ResetPeriod   int64
	PeriodStart   int64
	QuotaDisabled bool
}

// sessionRow is one accounting session.
type sessionRow struct {
	SessionID string
	Name      string
	RemoteIP  string
	StartedAt int64
	UpdatedAt int64
	EndedAt   int64
	InOctets  int64
	OutOctets int64
	// CountedIn/CountedOut is how much of this session already went into the
	// user quota counters. It makes repeated interim/stop records idempotent.
	CountedIn  int64
	CountedOut int64
	Active     bool
}

type store struct {
	db *sql.DB
}

func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("radius: open database: %w", err)
	}
	// One connection: RADIUS requests are serialized by the server loop and the
	// admin path is low volume, so a pool only adds lock contention.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("radius: ping database: %w", err)
	}
	s := &store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *store) migrate() error {
	stmts := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			name TEXT PRIMARY KEY,
			password TEXT NOT NULL,
			group_name TEXT NOT NULL DEFAULT '',
			ip TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			used_in INTEGER NOT NULL DEFAULT 0,
			used_out INTEGER NOT NULL DEFAULT 0,
			max_total INTEGER NOT NULL DEFAULT 0,
			reset_period INTEGER NOT NULL DEFAULT 0,
			period_start INTEGER NOT NULL DEFAULT 0,
			quota_disabled INTEGER NOT NULL DEFAULT 0
		)`, userTableName),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			session_id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			remote_ip TEXT NOT NULL DEFAULT '',
			started_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			ended_at INTEGER NOT NULL DEFAULT 0,
			input_octets INTEGER NOT NULL DEFAULT 0,
			output_octets INTEGER NOT NULL DEFAULT 0,
			counted_in INTEGER NOT NULL DEFAULT 0,
			counted_out INTEGER NOT NULL DEFAULT 0,
			active INTEGER NOT NULL DEFAULT 1
		)`, sessionTableName),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_%s_name ON %s (name)`, sessionTableName, sessionTableName),
		fmt.Sprintf(`CREATE INDEX IF NOT EXISTS idx_%s_active ON %s (active, updated_at)`, sessionTableName, sessionTableName),
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("radius: migrate: %w", err)
		}
	}

	// Databases created before fixed IP support have no ip column. SQLite has
	// no ADD COLUMN IF NOT EXISTS, so check PRAGMA table_info first.
	hasIP, err := s.hasColumn(userTableName, "ip")
	if err != nil {
		return err
	}
	if !hasIP {
		if _, err := s.db.Exec(fmt.Sprintf(
			"ALTER TABLE %s ADD COLUMN ip TEXT NOT NULL DEFAULT ''", userTableName)); err != nil {
			return fmt.Errorf("radius: add ip column: %w", err)
		}
	}
	// Quota columns are added the same way so an existing database keeps its
	// accounts and sessions.
	extraUserColumns := []struct {
		name string
		def  string
	}{
		{"used_in", "INTEGER NOT NULL DEFAULT 0"},
		{"used_out", "INTEGER NOT NULL DEFAULT 0"},
		{"max_total", "INTEGER NOT NULL DEFAULT 0"},
		{"reset_period", "INTEGER NOT NULL DEFAULT 0"},
		{"period_start", "INTEGER NOT NULL DEFAULT 0"},
		{"quota_disabled", "INTEGER NOT NULL DEFAULT 0"},
	}
	for _, c := range extraUserColumns {
		has, err := s.hasColumn(userTableName, c.name)
		if err != nil {
			return err
		}
		if has {
			continue
		}
		if _, err := s.db.Exec(fmt.Sprintf(
			"ALTER TABLE %s ADD COLUMN %s %s", userTableName, c.name, c.def)); err != nil {
			return fmt.Errorf("radius: add %s column: %w", c.name, err)
		}
	}
	extraSessionColumns := []struct {
		name string
		def  string
	}{
		{"counted_in", "INTEGER NOT NULL DEFAULT 0"},
		{"counted_out", "INTEGER NOT NULL DEFAULT 0"},
	}
	for _, c := range extraSessionColumns {
		has, err := s.hasColumn(sessionTableName, c.name)
		if err != nil {
			return err
		}
		if has {
			continue
		}
		if _, err := s.db.Exec(fmt.Sprintf(
			"ALTER TABLE %s ADD COLUMN %s %s", sessionTableName, c.name, c.def)); err != nil {
			return fmt.Errorf("radius: add session %s column: %w", c.name, err)
		}
	}

	// Partial unique index: empty means "no fixed address", and many users may
	// share that value, but a non-empty address belongs to exactly one user.
	if _, err := s.db.Exec(fmt.Sprintf(
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_%s_ip ON %s (ip) WHERE ip <> ''",
		userTableName, userTableName)); err != nil {
		return fmt.Errorf("radius: create ip index: %w", err)
	}
	return nil
}

func (s *store) hasColumn(table, column string) (bool, error) {
	rows, err := s.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false, fmt.Errorf("radius: table info: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid        int
			name       string
			typ        string
			notNull    int
			dflt       sql.NullString
			primaryKey int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &primaryKey); err != nil {
			return false, fmt.Errorf("radius: table info scan: %w", err)
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *store) close() error { return s.db.Close() }

// hashPassword stores a PBKDF2-HMAC-SHA256 hash with a random salt. The plaintext
// has to stay recoverable at verification time only, so the database never holds
// a readable password.
func hashPassword(plain string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("radius: salt: %w", err)
	}
	sum := pbkdf2SHA256([]byte(plain), salt, pbkdf2Iterations, pbkdf2KeyLen)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum)), nil
}

func verifyPassword(stored, plain string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(plain), salt, iter, len(want))
	return hmac.Equal(got, want)
}

// pbkdf2SHA256 is RFC 8018 PBKDF2 with HMAC-SHA256. Std lib has no PBKDF2 and
// pulling in x/crypto just for this is not worth a dependency bump.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	blocks := (keyLen + hashLen - 1) / hashLen
	dk := make([]byte, 0, blocks*hashLen)
	buf := make([]byte, 4)
	for block := 1; block <= blocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf)
		u := prf.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func (s *store) getUser(name string) (userRow, bool, error) {
	var u userRow
	var enabled, quotaDisabled int
	err := s.db.QueryRow(fmt.Sprintf(
		"SELECT name, password, group_name, ip, enabled, created_at, updated_at, used_in, used_out, max_total, reset_period, period_start, quota_disabled FROM %s WHERE name = ?",
		userTableName), name).
		Scan(&u.Name, &u.Password, &u.Group, &u.IP, &enabled, &u.CreatedAt, &u.UpdatedAt,
			&u.UsedIn, &u.UsedOut, &u.MaxTotal, &u.ResetPeriod, &u.PeriodStart, &quotaDisabled)
	if errors.Is(err, sql.ErrNoRows) {
		return userRow{}, false, nil
	}
	if err != nil {
		return userRow{}, false, fmt.Errorf("radius: read user: %w", err)
	}
	u.Enabled = enabled != 0
	u.QuotaDisabled = quotaDisabled != 0
	return u, true, nil
}

// addUser inserts an account without a fixed address.
func (s *store) addUser(name, password, group string) error {
	return s.addUserWithIP(name, password, group, "")
}

// addUserWithIP inserts an account with an optional fixed address. Duplicate
// names are rejected so an overwrite from the bot has to be an explicit
// password change instead; a taken address is reported separately.
func (s *store) addUserWithIP(name, password, group, ip string) error {
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	_, err = s.db.Exec(fmt.Sprintf(
		"INSERT INTO %s (name, password, group_name, ip, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)",
		userTableName), name, hash, group, ip, now, now)
	if err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, userTableName+".ip") || strings.Contains(msg, "idx_"+userTableName+"_ip") {
			return errIPInUse
		}
		if strings.Contains(msg, "unique") || strings.Contains(msg, "constraint") {
			return errUserExists
		}
		return fmt.Errorf("radius: add user: %w", err)
	}
	return nil
}

func (s *store) deleteUser(name string) (bool, error) {
	res, err := s.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE name = ?", userTableName), name)
	if err != nil {
		return false, fmt.Errorf("radius: delete user: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *store) setPassword(name, password string) (bool, error) {
	hash, err := hashPassword(password)
	if err != nil {
		return false, err
	}
	res, err := s.db.Exec(fmt.Sprintf(
		"UPDATE %s SET password = ?, updated_at = ? WHERE name = ?", userTableName),
		hash, time.Now().Unix(), name)
	if err != nil {
		return false, fmt.Errorf("radius: set password: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *store) setEnabled(name string, enabled bool) (bool, error) {
	v := 0
	if enabled {
		v = 1
	}
	res, err := s.db.Exec(fmt.Sprintf(
		"UPDATE %s SET enabled = ?, quota_disabled = 0, updated_at = ? WHERE name = ?", userTableName),
		v, time.Now().Unix(), name)
	if err != nil {
		return false, fmt.Errorf("radius: set enabled: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *store) setGroup(name, group string) (bool, error) {
	res, err := s.db.Exec(fmt.Sprintf(
		"UPDATE %s SET group_name = ?, updated_at = ? WHERE name = ?", userTableName),
		group, time.Now().Unix(), name)
	if err != nil {
		return false, fmt.Errorf("radius: set group: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *store) setIP(name, ip string) (bool, error) {
	// Check the owner first so the bot gets a useful message ("used by alice")
	// instead of only the SQLite constraint text. The unique index still guards
	// the race between this SELECT and the UPDATE.
	if ip != "" {
		owner, used, err := s.ipOwner(ip)
		if err != nil {
			return false, err
		}
		if used && owner != name {
			return false, fmt.Errorf("%w: %s is used by %s", errIPInUse, ip, owner)
		}
	}
	res, err := s.db.Exec(fmt.Sprintf(
		"UPDATE %s SET ip = ?, updated_at = ? WHERE name = ?", userTableName),
		ip, time.Now().Unix(), name)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return false, fmt.Errorf("%w: %s", errIPInUse, ip)
		}
		return false, fmt.Errorf("radius: set ip: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *store) ipOwner(ip string) (string, bool, error) {
	var owner string
	err := s.db.QueryRow(fmt.Sprintf(
		"SELECT name FROM %s WHERE ip = ? LIMIT 1", userTableName), ip).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("radius: look up ip owner: %w", err)
	}
	return owner, true, nil
}

func (s *store) listUsers() ([]userRow, error) {
	rows, err := s.db.Query(fmt.Sprintf(
		"SELECT name, password, group_name, ip, enabled, created_at, updated_at, used_in, used_out, max_total, reset_period, period_start, quota_disabled FROM %s ORDER BY name", userTableName))
	if err != nil {
		return nil, fmt.Errorf("radius: list users: %w", err)
	}
	defer rows.Close()
	var out []userRow
	for rows.Next() {
		var u userRow
		var enabled, quotaDisabled int
		if err := rows.Scan(&u.Name, &u.Password, &u.Group, &u.IP, &enabled, &u.CreatedAt, &u.UpdatedAt,
			&u.UsedIn, &u.UsedOut, &u.MaxTotal, &u.ResetPeriod, &u.PeriodStart, &u.QuotaDisabled); err != nil {
			return nil, fmt.Errorf("radius: scan user: %w", err)
		}
		u.Enabled = enabled != 0
		u.QuotaDisabled = quotaDisabled != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

// applyAccounting folds one Accounting-Request into the session table.
func (s *store) applyAccounting(sessionID, name, remoteIP string, status uint32, inOctets, outOctets int64) (bool, error) {
	if sessionID == "" {
		return false, nil // nothing to key on; ocserv always sends one
	}
	now := time.Now().Unix()
	if _, err := s.maybeResetQuota(name, now); err != nil {
		return false, err
	}
	switch status {
	case acctStatusStart, acctStatusStart2:
		_, err := s.db.Exec(fmt.Sprintf(
			`INSERT INTO %s (session_id, name, remote_ip, started_at, updated_at, ended_at, input_octets, output_octets, active)
			 VALUES (?, ?, ?, ?, ?, 0, ?, ?, 1)
			 ON CONFLICT(session_id) DO UPDATE SET
			   name = excluded.name, remote_ip = excluded.remote_ip,
			   updated_at = excluded.updated_at, input_octets = excluded.input_octets,
			   output_octets = excluded.output_octets, active = 1, ended_at = 0`,
			sessionTableName), sessionID, name, remoteIP, now, now, inOctets, outOctets)
		if err != nil {
			return false, wrapAcct(err)
		}
	case acctStatusInterim, acctStatusAlive:
		_, err := s.db.Exec(fmt.Sprintf(
			`INSERT INTO %s (session_id, name, remote_ip, started_at, updated_at, input_octets, output_octets, active)
			 VALUES (?, ?, ?, ?, ?, ?, ?, 1)
			 ON CONFLICT(session_id) DO UPDATE SET
			   updated_at = excluded.updated_at, input_octets = excluded.input_octets,
			   output_octets = excluded.output_octets, active = 1`,
			sessionTableName), sessionID, name, remoteIP, now, now, inOctets, outOctets)
		if err != nil {
			return false, wrapAcct(err)
		}
	case acctStatusStop:
		_, err := s.db.Exec(fmt.Sprintf(
			`INSERT INTO %s (session_id, name, remote_ip, started_at, updated_at, ended_at, input_octets, output_octets, active)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
			 ON CONFLICT(session_id) DO UPDATE SET
			   updated_at = excluded.updated_at, ended_at = excluded.ended_at,
			   input_octets = excluded.input_octets, output_octets = excluded.output_octets, active = 0`,
			sessionTableName), sessionID, name, remoteIP, now, now, now, inOctets, outOctets)
		if err != nil {
			return false, wrapAcct(err)
		}
	default:
		return false, nil
	}
	if err := s.settleSession(sessionID, name, now); err != nil {
		return false, err
	}
	return s.enforceQuota(name, now)
}

// settleSession adds only the bytes this session has not yet contributed to
// the account counters. Interim records repeat the running total, and a Stop
// record repeats it once more, so this delta is what keeps the sum exact.
func (s *store) settleSession(sessionID, name string, now int64) error {
	var inOctets, outOctets, countedIn, countedOut int64
	err := s.db.QueryRow(fmt.Sprintf(
		"SELECT input_octets, output_octets, counted_in, counted_out FROM %s WHERE session_id = ?",
		sessionTableName), sessionID).Scan(&inOctets, &outOctets, &countedIn, &countedOut)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("radius: read session counters: %w", err)
	}
	deltaIn := inOctets - countedIn
	if deltaIn < 0 {
		deltaIn = 0
	}
	deltaOut := outOctets - countedOut
	if deltaOut < 0 {
		deltaOut = 0
	}
	if deltaIn == 0 && deltaOut == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("radius: quota transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(fmt.Sprintf(
		"UPDATE %s SET used_in = used_in + ?, used_out = used_out + ?, updated_at = ? WHERE name = ?",
		userTableName), deltaIn, deltaOut, now, name); err != nil {
		return fmt.Errorf("radius: add quota usage: %w", err)
	}
	if _, err := tx.Exec(fmt.Sprintf(
		"UPDATE %s SET counted_in = ?, counted_out = ? WHERE session_id = ?",
		sessionTableName), inOctets, outOctets, sessionID); err != nil {
		return fmt.Errorf("radius: mark session counted: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("radius: commit quota usage: %w", err)
	}
	return nil
}

// maybeResetQuota starts a new quota period once the configured interval has
// elapsed. Only an account disabled by quota is enabled again; a manual
// disable stays manual.
func (s *store) maybeResetQuota(name string, now int64) (bool, error) {
	var resetPeriod, periodStart int64
	var enabled, quotaDisabled int
	err := s.db.QueryRow(fmt.Sprintf(
		"SELECT reset_period, period_start, enabled, quota_disabled FROM %s WHERE name = ?",
		userTableName), name).Scan(&resetPeriod, &periodStart, &enabled, &quotaDisabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("radius: read quota period: %w", err)
	}
	if resetPeriod <= 0 {
		return false, nil
	}
	if periodStart <= 0 {
		if _, err := s.db.Exec(fmt.Sprintf(
			"UPDATE %s SET period_start = ?, updated_at = ? WHERE name = ?",
			userTableName), now, now, name); err != nil {
			return false, fmt.Errorf("radius: start quota period: %w", err)
		}
		return false, nil
	}
	if now < periodStart+resetPeriod {
		return false, nil
	}

	newStart := periodStart + ((now-periodStart)/resetPeriod)*resetPeriod
	reenable := quotaDisabled != 0
	enabledValue := enabled
	if reenable {
		enabledValue = 1
	}
	if _, err := s.db.Exec(fmt.Sprintf(
		"UPDATE %s SET used_in = 0, used_out = 0, period_start = ?, quota_disabled = 0, enabled = ?, updated_at = ? WHERE name = ?",
		userTableName), newStart, enabledValue, now, name); err != nil {
		return false, fmt.Errorf("radius: reset quota period: %w", err)
	}
	return true, nil
}

// enforceQuota disables an account that has reached its total byte limit. It
// returns true only when this call performed the disable, so the caller can log
// the transition once instead of on every accounting record.
func (s *store) enforceQuota(name string, now int64) (bool, error) {
	var usedIn, usedOut, maxTotal int64
	var enabled, quotaDisabled int
	err := s.db.QueryRow(fmt.Sprintf(
		"SELECT used_in, used_out, max_total, enabled, quota_disabled FROM %s WHERE name = ?",
		userTableName), name).Scan(&usedIn, &usedOut, &maxTotal, &enabled, &quotaDisabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("radius: read quota: %w", err)
	}
	if maxTotal <= 0 || usedIn+usedOut < maxTotal {
		return false, nil
	}
	if enabled == 0 || quotaDisabled != 0 {
		return false, nil // already disabled, or disabled manually
	}
	if _, err := s.db.Exec(fmt.Sprintf(
		"UPDATE %s SET enabled = 0, quota_disabled = 1, updated_at = ? WHERE name = ?",
		userTableName), now, name); err != nil {
		return false, fmt.Errorf("radius: disable over-quota user: %w", err)
	}
	return true, nil
}

// setQuota changes the byte limit and reset period. A zero limit is unlimited
// and a zero period never resets automatically. Changing the limit starts a
// fresh period but keeps the bytes already used in this one.
func (s *store) setQuota(name string, maxTotal, resetPeriod int64) (bool, error) {
	u, found, err := s.getUser(name)
	if err != nil || !found {
		return false, err
	}
	if resetPeriod < 0 {
		resetPeriod = u.ResetPeriod
	}
	now := time.Now().Unix()
	periodStart := u.PeriodStart
	if resetPeriod != u.ResetPeriod || periodStart <= 0 {
		periodStart = now
	}
	enabled := u.Enabled || u.QuotaDisabled
	if _, err := s.db.Exec(fmt.Sprintf(
		"UPDATE %s SET max_total = ?, reset_period = ?, period_start = ?, enabled = ?, quota_disabled = 0, updated_at = ? WHERE name = ?",
		userTableName), maxTotal, resetPeriod, periodStart, boolInt(enabled), now, name); err != nil {
		return false, fmt.Errorf("radius: set quota: %w", err)
	}
	if _, err := s.enforceQuota(name, now); err != nil {
		return false, err
	}
	return true, nil
}

// resetQuota clears the counters immediately and starts a new period. An
// account blocked only by quota is enabled again; a manual disable remains.
func (s *store) resetQuota(name string) (bool, error) {
	u, found, err := s.getUser(name)
	if err != nil || !found {
		return false, err
	}
	now := time.Now().Unix()
	enabled := u.Enabled || u.QuotaDisabled
	if _, err := s.db.Exec(fmt.Sprintf(
		"UPDATE %s SET used_in = 0, used_out = 0, period_start = ?, enabled = ?, quota_disabled = 0, updated_at = ? WHERE name = ?",
		userTableName), now, boolInt(enabled), now, name); err != nil {
		return false, fmt.Errorf("radius: reset quota: %w", err)
	}
	return true, nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// resetDueQuotas applies the periodic reset to every account whose period has
// elapsed. It is called by the plugin's background loop so a user stays cut off
// only until the boundary, even while offline.
func (s *store) resetDueQuotas(now int64) (int, error) {
	rows, err := s.db.Query(fmt.Sprintf(
		"SELECT name FROM %s WHERE reset_period > 0", userTableName))
	if err != nil {
		return 0, fmt.Errorf("radius: list quota periods: %w", err)
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return 0, fmt.Errorf("radius: scan quota user: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Close(); err != nil {
		return 0, fmt.Errorf("radius: close quota rows: %w", err)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	reset := 0
	for _, name := range names {
		ok, err := s.maybeResetQuota(name, now)
		if err != nil {
			return reset, err
		}
		if ok {
			reset++
		}
	}
	return reset, nil
}

func wrapAcct(err error) error {
	if err != nil {
		return fmt.Errorf("radius: accounting: %w", err)
	}
	return nil
}

// listSessions returns sessions, newest first. activeOnly limits it to current
// connections.
func (s *store) listSessions(activeOnly bool, limit int) ([]sessionRow, error) {
	if limit <= 0 {
		limit = 50
	}
	q := fmt.Sprintf("SELECT session_id, name, remote_ip, started_at, updated_at, ended_at, input_octets, output_octets, counted_in, counted_out, active FROM %s", sessionTableName)
	if activeOnly {
		q += " WHERE active = 1"
	}
	q += fmt.Sprintf(" ORDER BY updated_at DESC LIMIT %d", limit)
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("radius: list sessions: %w", err)
	}
	defer rows.Close()
	var out []sessionRow
	for rows.Next() {
		var r sessionRow
		var active int
		if err := rows.Scan(&r.SessionID, &r.Name, &r.RemoteIP, &r.StartedAt, &r.UpdatedAt,
			&r.EndedAt, &r.InOctets, &r.OutOctets, &r.CountedIn, &r.CountedOut, &active); err != nil {
			return nil, fmt.Errorf("radius: scan session: %w", err)
		}
		r.Active = active != 0
		out = append(out, r)
	}
	return out, rows.Err()
}
