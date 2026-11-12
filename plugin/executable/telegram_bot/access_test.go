package telegram_bot

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ersonw/mosdns-v4/pkg/fakeip_admin"
	"github.com/ersonw/mosdns-v4/plugin/executable/radius"
)

func TestAddressesOfUser(t *testing.T) {
	sessions := []radius.Session{
		{Name: "Alice", RemoteIP: "192.0.2.10"},
		{Name: "alice", RemoteIP: "192.0.2.10"}, // duplicate address
		{Name: "alice", RemoteIP: "192.0.2.11"},
		{Name: "bob", RemoteIP: "192.0.2.99"},
		{Name: "alice", RemoteIP: ""}, // accounting row without an address
	}
	got := addressesOfUser(sessions, "alice")
	want := []string{"192.0.2.10", "192.0.2.11"}
	if len(got) != len(want) {
		t.Fatalf("addresses = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("addresses = %v, want %v", got, want)
		}
	}
}

func TestCollectAccessRowsMergesNewestFirst(t *testing.T) {
	p := newStubPlugin()
	now := time.Now().Unix()
	p.admin.(*stubAdmin).access = []fakeipadmin.AccessRecord{
		{ClientIP: "192.0.2.10", Domain: "old.example.com", FakeIP: "198.18.0.2", RealIP: "203.0.113.5", LastSeen: now - 60},
		{ClientIP: "192.0.2.10", Domain: "new.example.com", FakeIP: "198.18.0.3", RealIP: "203.0.113.6", LastSeen: now},
		{ClientIP: "192.0.2.99", Domain: "other.example.com", FakeIP: "198.18.0.4", LastSeen: now},
	}

	rows, tags, err := p.collectAccessRows(context.Background(), []string{"192.0.2.10"}, 0)
	if err != nil {
		t.Fatalf("collectAccessRows: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2 (only the requested address)", len(rows))
	}
	if rows[0].domain != "new.example.com" || rows[1].domain != "old.example.com" {
		t.Fatalf("rows not sorted newest first: %+v", rows)
	}
	if len(tags) != 1 || tags[0] != "fakeip" {
		t.Fatalf("tags = %v", tags)
	}
}

func TestWriteXLSXIsAReadableWorkbook(t *testing.T) {
	sheet := [][]interface{}{
		{"client_ip", "domain", "hits"},
		{"192.0.2.10", "example.com", 3},
		{"192.0.2.11", `quoted "name" & <tag>`, 1},
	}
	data, err := writeXLSX("access 2026/11:12", sheet)
	if err != nil {
		t.Fatalf("writeXLSX: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("open xlsx: %v", err)
	}
	required := map[string]bool{
		"[Content_Types].xml":        false,
		"_rels/.rels":                false,
		"xl/workbook.xml":            false,
		"xl/_rels/workbook.xml.rels": false,
		"xl/worksheets/sheet1.xml":   false,
	}
	for _, f := range zr.File {
		if _, ok := required[f.Name]; ok {
			required[f.Name] = true
		}
	}
	for name, found := range required {
		if !found {
			t.Fatalf("xlsx is missing %s", name)
		}
	}

	var sheetXML string
	for _, f := range zr.File {
		if f.Name != "xl/worksheets/sheet1.xml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open sheet: %v", err)
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read sheet: %v", err)
		}
		sheetXML = string(b)
	}
	for _, want := range []string{"192.0.2.10", "example.com", "&amp; &lt;tag&gt;", "&#34;"} {
		if !strings.Contains(sheetXML, want) {
			t.Errorf("sheet does not contain %q: %s", want, sheetXML)
		}
	}
	// The sheet name must be sanitised, not rejected by Excel.
	if !strings.Contains(sheetXML, "sheetData") {
		t.Fatalf("sheet has no data block")
	}
}

func TestSuperAdminHoldsEveryPermission(t *testing.T) {
	args := &Args{
		Admins: []AdminUser{{ChatID: 2002, Role: RoleSuperAdmin}},
		Roles:  map[string]Role{},
	}
	args.initDefault()
	access, err := buildAccess(args)
	if err != nil {
		t.Fatalf("buildAccess: %v", err)
	}
	for _, perm := range allPermissions {
		if !access.allowed(2002, perm) {
			t.Fatalf("superadmin lacks %q: %s", perm, access.permissionNames(2002))
		}
	}
}

func TestAccessCommandNeedsAccessPermission(t *testing.T) {
	args := &Args{
		Admins: []AdminUser{{ChatID: 3003, Role: "ops"}},
		Roles:  map[string]Role{"ops": {Allow: []string{PermStatus}}},
	}
	args.initDefault()
	access, err := buildAccess(args)
	if err != nil {
		t.Fatalf("buildAccess: %v", err)
	}
	if access.allowed(3003, PermAccess) {
		t.Fatalf("a status-only role must not export records")
	}

	args2 := &Args{ChatIDs: []int64{3003}}
	args2.initDefault()
	access2, err := buildAccess(args2)
	if err != nil {
		t.Fatalf("buildAccess: %v", err)
	}
	if !access2.allowed(3003, PermAccess) {
		t.Fatalf("the built-in admin must be able to export records")
	}
}

// fakeAccessServer serves one /access update and captures the document upload.
type fakeAccessServer struct {
	update string
	docs   chan []byte
	caps   chan string
	served bool
	mu     sync.Mutex
}

func (f *fakeAccessServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			f.mu.Lock()
			first := !f.served
			f.served = true
			f.mu.Unlock()
			if first {
				_, _ = w.Write([]byte(`{"ok":true,"result":[` + f.update + `]}`))
				return
			}
			time.Sleep(100 * time.Millisecond)
			_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
		case strings.HasSuffix(r.URL.Path, "/sendDocument"):
			if err := r.ParseMultipartForm(8 << 20); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			file, _, err := r.FormFile("document")
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			data, _ := io.ReadAll(file)
			_ = file.Close()
			select {
			case f.docs <- data:
			default:
			}
			select {
			case f.caps <- r.FormValue("caption"):
			default:
			}
			_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true,"result":{}}`))
		}
	}
}

func TestAccessExportSendsXLSXDocument(t *testing.T) {
	fake := &fakeAccessServer{
		update: `{"update_id":11,"message":{"chat":{"id":123},"text":"/access alice 30"}}`,
		docs:   make(chan []byte, 1),
		caps:   make(chan string, 1),
	}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	p := newStubPlugin()
	p.radius = &stubRadius{sessions: []radius.Session{
		{Name: "alice", RemoteIP: "192.0.2.10"},
		{Name: "bob", RemoteIP: "192.0.2.99"},
	}}
	now := time.Now().Unix()
	p.admin.(*stubAdmin).access = []fakeipadmin.AccessRecord{
		{ClientIP: "192.0.2.10", Domain: "example.com", FakeIP: "198.18.0.2", RealIP: "203.0.113.5", FirstSeen: now - 3600, LastSeen: now, Hits: 4},
		{ClientIP: "192.0.2.99", Domain: "bob.example.com", FakeIP: "198.18.0.9", LastSeen: now},
	}

	cancel, done := startBot(t, p, srv.URL)
	defer func() {
		cancel()
		<-done
	}()

	select {
	case data := <-fake.docs:
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("sent document is not a zip: %v", err)
		}
		var sheet string
		for _, f := range zr.File {
			if f.Name != "xl/worksheets/sheet1.xml" {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("open sheet: %v", err)
			}
			b, _ := io.ReadAll(rc)
			_ = rc.Close()
			sheet = string(b)
		}
		if !strings.Contains(sheet, "example.com") {
			t.Fatalf("sheet lacks the exported domain: %s", sheet)
		}
		if strings.Contains(sheet, "bob.example.com") {
			t.Fatalf("sheet contains another user's domain: %s", sheet)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("bot did not send the access document")
	}

	select {
	case caption := <-fake.caps:
		if !strings.Contains(caption, "alice") || !strings.Contains(caption, "192.0.2.10") {
			t.Fatalf("caption = %q", caption)
		}
	case <-time.After(time.Second):
		t.Fatalf("document had no caption")
	}
}
