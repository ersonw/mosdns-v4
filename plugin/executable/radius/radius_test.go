package radius

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/ersonw/mosdns-v4/coremain"
	"go.uber.org/zap"
)

func coremainBP(t *testing.T) *coremain.BP {
	t.Helper()
	return coremain.NewBP("test_radius", PluginType, zap.NewNop(), nil)
}

func testStore(t *testing.T) *store {
	t.Helper()
	st, err := openStore(filepath.Join(t.TempDir(), "radius.db"))
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	t.Cleanup(func() { _ = st.close() })
	return st
}

func testPlugin(t *testing.T) *Plugin {
	t.Helper()
	bp := coremainBP(t)
	p, err := Init(bp, &Args{
		Listen:           "127.0.0.1:0",
		AccountingListen: "off",
		Secret:           "test-secret",
		DBPath:           filepath.Join(t.TempDir(), "radius.db"),
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p.(*Plugin)
}

func randomAuth() [16]byte {
	var a [16]byte
	for i := range a {
		a[i] = byte(i*7 + 3)
	}
	return a
}

func buildPAPRequest(id byte, secret []byte, auth [16]byte, name, pass string) []byte {
	enca := encodeUserPassword([]byte(pass), secret, auth[:])
	p := &packet{
		code:          codeAccessRequest,
		id:            id,
		authenticator: auth,
		attrs: []attribute{
			{typ: attrUserName, value: []byte(name)},
			{typ: attrUserPassword, value: enca},
		},
	}
	return p.encode(secret, nil)
}

func buildAcctRequest(id byte, secret []byte, attrs []attribute) []byte {
	p := &packet{code: codeAccountingRequest, id: id, attrs: attrs}
	raw := p.encode(secret, nil) // authenticator stays zero
	copy(raw[4:radiusHeaderLen], responseAuthenticator(raw, make([]byte, 16), secret))
	return raw
}

func TestUserPasswordRoundTrip(t *testing.T) {
	secret := []byte("shared-secret")
	auth := randomAuth()
	for _, plain := range []string{"a", "123456", "exactly-sixteen!", "a much longer password than one block"} {
		enc := encodeUserPassword([]byte(plain), secret, auth[:])
		if len(enc)%radiusAuthLen != 0 || len(enc) == 0 {
			t.Fatalf("%q: encoded length %d is not a 16 byte multiple", plain, len(enc))
		}
		got, err := decodeUserPassword(enc, secret, auth[:])
		if err != nil {
			t.Fatalf("%q: decode: %v", plain, err)
		}
		if got != plain {
			t.Fatalf("decode = %q, want %q", got, plain)
		}
	}
}

func TestParsePacketRejectsTruncatedAttribute(t *testing.T) {
	raw := make([]byte, radiusHeaderLen)
	raw[0] = codeAccessRequest
	raw[1] = 7
	binary.BigEndian.PutUint16(raw[2:4], uint16(radiusHeaderLen+1))
	raw = append(raw, attrUserName, 0x09) // length 9 but no bytes follow
	if _, err := parsePacket(raw); err == nil {
		t.Fatal("expected a truncated attribute to be rejected")
	}
}

func TestPasswordHash(t *testing.T) {
	hash, err := hashPassword("hunter2")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if !verifyPassword(hash, "hunter2") {
		t.Fatal("correct password did not verify")
	}
	if verifyPassword(hash, "hunter3") {
		t.Fatal("wrong password verified")
	}
	if verifyPassword("plain-text", "plain-text") {
		t.Fatal("a value without the pbkdf2 prefix verified")
	}
}

func TestAccessAcceptAndReject(t *testing.T) {
	secret := []byte("test-secret")
	st := testStore(t)
	if err := st.addUser("alice", "secret123", "staff"); err != nil {
		t.Fatalf("addUser: %v", err)
	}
	srv, err := newServer(zap.NewNop(), secret, st, "127.0.0.1:0", "")
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	srv.start()
	defer srv.close()
	addr := srv.auth.LocalAddr().(*net.UDPAddr)

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	roundTrip := func(req []byte) *packet {
		t.Helper()
		if _, err := conn.Write(req); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, radiusMaxPacket)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		p, err := parsePacket(buf[:n])
		if err != nil {
			t.Fatalf("parse response: %v", err)
		}
		return p
	}

	// Correct password -> Access-Accept carrying the group.
	auth := randomAuth()
	accept := roundTrip(buildPAPRequest(1, secret, auth, "alice", "secret123"))
	if accept.code != codeAccessAccept {
		t.Fatalf("code = %d, want accept (%d)", accept.code, codeAccessAccept)
	}
	if v, ok := accept.get(attrClass); !ok || string(v) != "staff" {
			t.Fatalf("class attribute = %q/%v, want staff", v, ok)
	}

	// Wrong password -> Reject.
	reject := roundTrip(buildPAPRequest(2, secret, auth, "alice", "wrong-pass"))
	if reject.code != codeAccessReject {
		t.Fatalf("code = %d, want reject (%d)", reject.code, codeAccessReject)
	}

	// Unknown user -> Reject.
	unknown := roundTrip(buildPAPRequest(3, secret, auth, "bob", "secret123"))
	if unknown.code != codeAccessReject {
		t.Fatalf("unknown user got code %d", unknown.code)
	}

	// Disabled account -> Reject.
	if _, err := st.setEnabled("alice", false); err != nil {
		t.Fatalf("setEnabled: %v", err)
	}
	disabled := roundTrip(buildPAPRequest(4, secret, auth, "alice", "secret123"))
	if disabled.code != codeAccessReject {
		t.Fatalf("disabled account got code %d", disabled.code)
	}
}

func TestAccessResponseAuthenticatorMatchesClient(t *testing.T) {
	secret := []byte("test-secret")
	st := testStore(t)
	if err := st.addUser("alice", "secret123", ""); err != nil {
		t.Fatalf("addUser: %v", err)
	}
	srv, err := newServer(zap.NewNop(), secret, st, "127.0.0.1:0", "")
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	srv.start()
	defer srv.close()

	conn, err := net.DialUDP("udp", nil, srv.auth.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	auth := randomAuth()
	req := buildPAPRequest(9, secret, auth, "alice", "secret123")
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, radiusMaxPacket)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	raw := buf[:n]
	// A client recomputes MD5(code|id|len|request authenticator|attrs|secret).
	// Copy the authenticator first: appending to raw[0:4] would reuse the read
	// buffer and overwrite it.
	got := append([]byte(nil), raw[4:radiusHeaderLen]...)
	h := md5.New()
	h.Write(raw[0:4])
	h.Write(auth[:])
	h.Write(raw[radiusHeaderLen:])
	h.Write(secret)
	want := h.Sum(nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("response authenticator mismatch: got %x want %x", got, want)
	}
}

func TestAccountingRecordsSession(t *testing.T) {
	secret := []byte("test-secret")
	st := testStore(t)
	srv, err := newServer(zap.NewNop(), secret, st, "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	srv.start()
	defer srv.close()

	conn, err := net.DialUDP("udp", nil, srv.acct.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial acct: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	send := func(status uint32, in, out uint32) {
		t.Helper()
		// Literal RFC 2866 codes on purpose: using the implementation constants
		// here would hide an off-by-one in the numbering, which is exactly how
		// Output-Octets was once read as Output-Packets.
		attrs := []attribute{
			{typ: 1, value: []byte("alice")},              // User-Name
			{typ: 44, value: []byte("sess-1")},            // Acct-Session-Id
			{typ: 40, value: uint32Bytes(status)},         // Acct-Status-Type
			{typ: 42, value: uint32Bytes(in)},             // Acct-Input-Octets
			{typ: 43, value: uint32Bytes(out)},            // Acct-Output-Octets
		}
		if _, err := conn.Write(buildAcctRequest(1, secret, attrs)); err != nil {
			t.Fatalf("write accounting: %v", err)
		}
		buf := make([]byte, radiusMaxPacket)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read accounting response: %v", err)
		}
		p, err := parsePacket(buf[:n])
		if err != nil || p.code != codeAccountingResponse {
			t.Fatalf("accounting response code %v err %v", p, err)
		}
	}

	send(1, 10, 20) // Start
	sessions, err := st.listSessions(true, 0)
	if err != nil {
		t.Fatalf("listSessions: %v", err)
	}
	if len(sessions) != 1 || sessions[0].InOctets != 10 || sessions[0].OutOctets != 20 {
		t.Fatalf("sessions after start = %+v", sessions)
	}

	send(2, 100, 200) // Stop
	sessions, err = st.listSessions(false, 0)
	if err != nil {
		t.Fatalf("listSessions: %v", err)
	}
	if len(sessions) != 1 || sessions[0].Active || sessions[0].InOctets != 100 || sessions[0].OutOctets != 200 {
		t.Fatalf("sessions after stop = %+v", sessions)
	}
}

func uint32Bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func TestAdminValidateAndCRUD(t *testing.T) {
	p := testPlugin(t)

	if err := p.AddUser("", "secret123", ""); err == nil {
		t.Fatal("empty name accepted")
	}
	if err := p.AddUser("has space", "secret123", ""); err == nil {
		t.Fatal("name with a space accepted")
	}
	if err := p.AddUser("alice", "123", ""); err == nil {
		t.Fatal("short password accepted")
	}
	if err := p.AddUser("alice", "secret123", "staff"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	if err := p.AddUser("alice", "secret123", ""); err != errUserExists {
		t.Fatalf("duplicate add = %v, want errUserExists", err)
	}

	users, err := p.Users()
	if err != nil {
		t.Fatalf("Users: %v", err)
	}
	if len(users) != 1 || users[0].Name != "alice" || users[0].Group != "staff" || !users[0].Enabled {
		t.Fatalf("Users = %+v", users)
	}

	ok, err := p.SetPassword("alice", "newsecret")
	if err != nil || !ok {
		t.Fatalf("SetPassword = %v/%v", ok, err)
	}
	ok, err = p.SetEnabled("alice", false)
	if err != nil || !ok {
		t.Fatalf("SetEnabled = %v/%v", ok, err)
	}
	ok, err = p.SetGroup("alice", "ops")
	if err != nil || !ok {
		t.Fatalf("SetGroup = %v/%v", ok, err)
	}
	ok, _ = p.SetPassword("nobody", "newsecret")
	if ok {
		t.Fatal("SetPassword on a missing user reported success")
	}

	ok, err = p.DeleteUser("alice")
	if err != nil || !ok {
		t.Fatalf("DeleteUser = %v/%v", ok, err)
	}
	if n, _ := p.Users(); len(n) != 0 {
		t.Fatalf("users left after delete: %+v", n)
	}
	ok, _ = p.DeleteUser("alice")
	if ok {
		t.Fatal("second delete reported success")
	}
}
