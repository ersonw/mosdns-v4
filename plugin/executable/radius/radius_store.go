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

// userRow is one account, as stored and as handed to the admin surface.
type userRow struct {
	Name      string
	Password  string // the stored hash, never the plaintext
	Group     string
	Enabled   bool
	CreatedAt int64
	UpdatedAt int64
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
	Active    bool
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
			enabled INTEGER NOT NULL DEFAULT 1,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
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
	return nil
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
	var enabled int
	err := s.db.QueryRow(fmt.Sprintf(
		"SELECT name, password, group_name, enabled, created_at, updated_at FROM %s WHERE name = ?",
		userTableName), name).
		Scan(&u.Name, &u.Password, &u.Group, &enabled, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return userRow{}, false, nil
	}
	if err != nil {
		return userRow{}, false, fmt.Errorf("radius: read user: %w", err)
	}
	u.Enabled = enabled != 0
	return u, true, nil
}

// addUser inserts an account. Duplicate names are rejected so an overwrite from
// the bot has to be an explicit password change instead.
func (s *store) addUser(name, password, group string) error {
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	_, err = s.db.Exec(fmt.Sprintf(
		"INSERT INTO %s (name, password, group_name, enabled, created_at, updated_at) VALUES (?, ?, ?, 1, ?, ?)",
		userTableName), name, hash, group, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "constraint") {
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
		"UPDATE %s SET enabled = ?, updated_at = ? WHERE name = ?", userTableName),
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

func (s *store) listUsers() ([]userRow, error) {
	rows, err := s.db.Query(fmt.Sprintf(
		"SELECT name, password, group_name, enabled, created_at, updated_at FROM %s ORDER BY name", userTableName))
	if err != nil {
		return nil, fmt.Errorf("radius: list users: %w", err)
	}
	defer rows.Close()
	var out []userRow
	for rows.Next() {
		var u userRow
		var enabled int
		if err := rows.Scan(&u.Name, &u.Password, &u.Group, &enabled, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, fmt.Errorf("radius: scan user: %w", err)
		}
		u.Enabled = enabled != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

// applyAccounting folds one Accounting-Request into the session table.
func (s *store) applyAccounting(sessionID, name, remoteIP string, status uint32, inOctets, outOctets int64) error {
	if sessionID == "" {
		return nil // nothing to key on; ocserv always sends one
	}
	now := time.Now().Unix()
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
		return wrapAcct(err)
	case acctStatusInterim, acctStatusAlive:
		_, err := s.db.Exec(fmt.Sprintf(
			`INSERT INTO %s (session_id, name, remote_ip, started_at, updated_at, input_octets, output_octets, active)
			 VALUES (?, ?, ?, ?, ?, ?, ?, 1)
			 ON CONFLICT(session_id) DO UPDATE SET
			   updated_at = excluded.updated_at, input_octets = excluded.input_octets,
			   output_octets = excluded.output_octets, active = 1`,
			sessionTableName), sessionID, name, remoteIP, now, now, inOctets, outOctets)
		return wrapAcct(err)
	case acctStatusStop:
		_, err := s.db.Exec(fmt.Sprintf(
			`INSERT INTO %s (session_id, name, remote_ip, started_at, updated_at, ended_at, input_octets, output_octets, active)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
			 ON CONFLICT(session_id) DO UPDATE SET
			   updated_at = excluded.updated_at, ended_at = excluded.ended_at,
			   input_octets = excluded.input_octets, output_octets = excluded.output_octets, active = 0`,
			sessionTableName), sessionID, name, remoteIP, now, now, now, inOctets, outOctets)
		return wrapAcct(err)
	default:
		return nil
	}
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
	q := fmt.Sprintf("SELECT session_id, name, remote_ip, started_at, updated_at, ended_at, input_octets, output_octets, active FROM %s", sessionTableName)
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
			&r.EndedAt, &r.InOctets, &r.OutOctets, &active); err != nil {
			return nil, fmt.Errorf("radius: scan session: %w", err)
		}
		r.Active = active != 0
		out = append(out, r)
	}
	return out, rows.Err()
}
