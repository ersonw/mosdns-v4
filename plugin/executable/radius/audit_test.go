package radius

import (
	"fmt"
	"net"
	"testing"

	"go.uber.org/zap"
)

// buildAccessRequestWith builds a PAP Access-Request that also carries the
// context attributes ocserv sends (station, NAS identifier, user agent, etc.).
func buildAccessRequestWith(id byte, secret []byte, auth [16]byte, name, pass string, extra []attribute) []byte {
	attrs := []attribute{
		{typ: attrUserName, value: []byte(name)},
		{typ: attrUserPassword, value: encodeUserPassword([]byte(pass), secret, auth[:])},
	}
	attrs = append(attrs, extra...)
	p := &packet{code: codeAccessRequest, id: id, authenticator: auth, attrs: attrs}
	return p.encode(secret, nil)
}

func testServer(t *testing.T, secret []byte, st *store) *server {
	t.Helper()
	srv, err := newServer(zap.NewNop(), secret, st, "127.0.0.1:0", "")
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(srv.close)
	return srv
}

func responseCode(t *testing.T, raw []byte) byte {
	t.Helper()
	p, err := parsePacket(raw)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	return p.code
}

func TestAuthLogRecordsEveryOutcome(t *testing.T) {
	secret := []byte("test-secret")
	st := testStore(t)
	if err := st.addUser("alice", "secret123", "staff"); err != nil {
		t.Fatalf("addUser: %v", err)
	}
	srv := testServer(t, secret, st)
	src := &net.UDPAddr{IP: net.ParseIP("10.131.160.3"), Port: 41812}
	auth := randomAuth()

	context := []attribute{
		{typ: attrCallingStationID, value: []byte("112.201.103.89")},
		{typ: attrNASIdentifier, value: []byte("ph-vpn1.dyize.com")},
		{typ: attrConnectInfo, value: []byte("AnyConnect-compatible")},
		{typ: attrAcctSessionID, value: []byte("sess-audit-1")},
		{typ: attrNASPort, value: uint32Bytes(7)},
		{typ: attrServiceType, value: uint32Bytes(8)},
		{typ: attrNASPortType, value: uint32Bytes(5)},
	}

	// Accepted request.
	if code := responseCode(t, srv.handleAccess(src,
		buildAccessRequestWith(1, secret, auth, "alice", "secret123", context))); code != codeAccessAccept {
		t.Fatalf("accept path returned code %d", code)
	}
	// Rejected request: wrong password, same context.
	if code := responseCode(t, srv.handleAccess(src,
		buildAccessRequestWith(2, secret, auth, "alice", "wrong", context))); code != codeAccessReject {
		t.Fatalf("reject path returned code %d", code)
	}
	// Rejected request with no user name at all.
	empty := &packet{code: codeAccessRequest, id: 3, authenticator: auth, attrs: context}
	if code := responseCode(t, srv.handleAccess(src, empty.encode(secret, nil))); code != codeAccessReject {
		t.Fatalf("missing user-name returned code %d", code)
	}

	rows, err := st.listAuthLog(0)
	if err != nil {
		t.Fatalf("listAuthLog: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("auth log has %d rows, want 3: %+v", len(rows), rows)
	}
	// Newest first: missing user-name, wrong password, accept.
	if rows[0].Result != "reject" || rows[0].Reason != "missing user-name" || rows[0].Name != "" {
		t.Fatalf("row 0 = %+v", rows[0])
	}
	if rows[1].Result != "reject" || rows[1].Reason != "invalid credentials" || rows[1].Name != "alice" {
		t.Fatalf("row 1 = %+v", rows[1])
	}
	if rows[2].Result != "accept" || rows[2].Name != "alice" {
		t.Fatalf("row 2 = %+v", rows[2])
	}
	// The whole ocserv context has to survive on every row.
	for _, r := range rows {
		if r.NASID != "ph-vpn1.dyize.com" {
			t.Fatalf("nas identifier lost on %+v", r)
		}
		if r.ClientIP != "" && r.ClientIP != "112.201.103.89" {
			t.Fatalf("client ip = %q", r.ClientIP)
		}
	}
	if rows[1].NASPort != 7 || rows[1].Service != 8 || rows[1].NASPortTyp != 5 {
		t.Fatalf("port/service typing lost: %+v", rows[1])
	}
	if rows[1].SessionID != "sess-audit-1" || rows[1].UserAgent != "AnyConnect-compatible" {
		t.Fatalf("session id / user agent lost: %+v", rows[1])
	}
	if rows[1].NASIP != "10.131.160.3:41812" {
		t.Fatalf("nas ip = %q", rows[1].NASIP)
	}

	// The password is the one thing that must never be persisted.
	var cols []string
	rq, err := st.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", authLogTableName))
	if err != nil {
		t.Fatalf("pragma: %v", err)
	}
	defer rq.Close()
	for rq.Next() {
		var (
			cid     int
			name    string
			typ     string
			notnull int
			dflt    interface{}
			pk      int
		)
		if err := rq.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan pragma: %v", err)
		}
		cols = append(cols, name)
	}
	for _, c := range cols {
		if c == "password" || c == "user_password" {
			t.Fatalf("auth log must not store a password column, got %v", cols)
		}
	}
}

func TestAuthLogPrunesToLimit(t *testing.T) {
	st := testStore(t)
	st.setAuthLogMax(3)
	for i := 0; i < 5; i++ {
		if err := st.recordAuth(authLogRow{Name: fmt.Sprintf("u%d", i), Result: "accept"}); err != nil {
			t.Fatalf("recordAuth %d: %v", i, err)
		}
	}
	rows, err := st.listAuthLog(0)
	if err != nil {
		t.Fatalf("listAuthLog: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	if rows[0].Name != "u4" || rows[2].Name != "u2" {
		t.Fatalf("kept the wrong rows: %+v", rows)
	}
}

func TestRequireVhost(t *testing.T) {
	secret := []byte("test-secret")
	st := testStore(t)
	if err := st.addUser("alice", "secret123", ""); err != nil {
		t.Fatalf("addUser: %v", err)
	}
	srv := testServer(t, secret, st)
	src := &net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 1812}
	auth := randomAuth()

	withNAS := func(id byte, nas string) []byte {
		var extra []attribute
		if nas != "" {
			extra = append(extra, attribute{typ: attrNASIdentifier, value: []byte(nas)})
		}
		return buildAccessRequestWith(id, secret, auth, "alice", "secret123", extra)
	}

	// Off by default: an account with no vhost accepts from any NAS.
	if code := responseCode(t, srv.handleAccess(src, withNAS(1, "ph-vpn1.dyize.com"))); code != codeAccessAccept {
		t.Fatalf("isolation off should accept, got %d", code)
	}

	srv.requireVhost = true

	// No NAS-Identifier at all: nothing to match, request is refused.
	if code := responseCode(t, srv.handleAccess(src, withNAS(2, ""))); code != codeAccessReject {
		t.Fatalf("missing nas-identifier should reject, got %d", code)
	}
	// Identifier present but the account is not bound to it yet.
	if code := responseCode(t, srv.handleAccess(src, withNAS(3, "ph-vpn1.dyize.com"))); code != codeAccessReject {
		t.Fatalf("unbound account should reject, got %d", code)
	}
	// Bound to another vhost.
	if ok, err := st.setVhost("alice", "ph-vpn.dyize.com"); err != nil || !ok {
		t.Fatalf("setVhost = %v/%v", ok, err)
	}
	if code := responseCode(t, srv.handleAccess(src, withNAS(4, "ph-vpn1.dyize.com"))); code != codeAccessReject {
		t.Fatalf("mismatched vhost should reject, got %d", code)
	}
	// Matching vhost, case-insensitive.
	if code := responseCode(t, srv.handleAccess(src, withNAS(5, "PH-VPN.DYIZE.COM"))); code != codeAccessAccept {
		t.Fatalf("matching vhost should accept, got %d", code)
	}

	rows, err := st.listAuthLog(0)
	if err != nil {
		t.Fatalf("listAuthLog: %v", err)
	}
	var reasons []string
	for _, r := range rows {
		reasons = append(reasons, r.Result+":"+r.Reason)
	}
	if len(reasons) != 5 {
		t.Fatalf("rows = %v", reasons)
	}
}

func TestAccountingKeepsClientContext(t *testing.T) {
	secret := []byte("test-secret")
	st := testStore(t)
	if err := st.addUser("alice", "secret123", ""); err != nil {
		t.Fatalf("addUser: %v", err)
	}
	srv := testServer(t, secret, st)
	src := &net.UDPAddr{IP: net.ParseIP("10.131.160.3"), Port: 41813}

	attrs := []attribute{
		{typ: attrUserName, value: []byte("alice")},
		{typ: attrAcctSessionID, value: []byte("sess-meta")},
		{typ: attrAcctStatusType, value: uint32Bytes(acctStatusStart)},
		{typ: attrAcctInputOctets, value: uint32Bytes(10)},
		{typ: attrAcctOutputOctets, value: uint32Bytes(20)},
		{typ: attrCallingStationID, value: []byte("112.201.103.89")},
		{typ: attrNASIdentifier, value: []byte("ph-vpn1.dyize.com")},
		{typ: attrConnectInfo, value: []byte("AnyConnect-compatible")},
	}
	if code := responseCode(t, srv.handleAccounting(src, buildAcctRequest(1, secret, attrs))); code != codeAccountingResponse {
		t.Fatalf("accounting response code %d", code)
	}

	sessions, err := st.listSessions(true, 0)
	if err != nil {
		t.Fatalf("listSessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("sessions = %+v", sessions)
	}
	s := sessions[0]
	if s.ClientIP != "112.201.103.89" {
		t.Fatalf("client ip = %q, want the calling station", s.ClientIP)
	}
	if s.NASIdentifier != "ph-vpn1.dyize.com" {
		t.Fatalf("nas identifier = %q", s.NASIdentifier)
	}
	if s.UserAgent != "AnyConnect-compatible" {
		t.Fatalf("user agent = %q", s.UserAgent)
	}
	if s.RemoteIP != "10.131.160.3:41813" {
		t.Fatalf("remote ip should stay the NAS address, got %q", s.RemoteIP)
	}
}
