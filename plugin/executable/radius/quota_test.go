package radius

import (
	"testing"
	"time"
)

func TestQuotaAccountingIsIdempotent(t *testing.T) {
	st := testStore(t)
	if err := st.addUser("alice", "secret123", "staff"); err != nil {
		t.Fatalf("addUser: %v", err)
	}
	if ok, err := st.setQuota("alice", 100, 0); err != nil || !ok {
		t.Fatalf("setQuota = %v/%v", ok, err)
	}

	// Start carries no bytes, interim repeats a running total, and stop repeats
	// it once more. Only the growth between records may reach the counter.
	steps := []struct {
		status uint32
		in     int64
		out    int64
	}{
		{acctStatusStart, 0, 0},
		{acctStatusInterim, 40, 40},
		{acctStatusInterim, 40, 80},
		{acctStatusStop, 100, 100},
	}
	for _, step := range steps {
		if _, err := st.applyAccounting("sess-1", "alice", "192.0.2.10", step.status, step.in, step.out); err != nil {
			t.Fatalf("accounting %+v: %v", step, err)
		}
	}
	// A duplicated stop record must not add the same bytes twice.
	if _, err := st.applyAccounting("sess-1", "alice", "192.0.2.10", acctStatusStop, 100, 100); err != nil {
		t.Fatalf("duplicate stop: %v", err)
	}

	u, found, err := st.getUser("alice")
	if err != nil || !found {
		t.Fatalf("getUser = %+v/%v/%v", u, found, err)
	}
	if u.UsedIn != 100 || u.UsedOut != 100 {
		t.Fatalf("usage = %d/%d, want 100/100", u.UsedIn, u.UsedOut)
	}
	if u.Enabled || !u.QuotaDisabled {
		t.Fatalf("over-quota user = enabled:%v quota:%v, want disabled/quota", u.Enabled, u.QuotaDisabled)
	}

	if ok, err := st.resetQuota("alice"); err != nil || !ok {
		t.Fatalf("resetQuota = %v/%v", ok, err)
	}
	u, found, err = st.getUser("alice")
	if err != nil || !found {
		t.Fatalf("getUser after reset = %+v/%v/%v", u, found, err)
	}
	if u.UsedIn != 0 || u.UsedOut != 0 || !u.Enabled || u.QuotaDisabled {
		t.Fatalf("after reset = %+v, want zero usage and enabled", u)
	}
}

func TestQuotaPeriodResetReenablesOnlyQuotaDisabled(t *testing.T) {
	st := testStore(t)
	if err := st.addUser("alice", "secret123", "staff"); err != nil {
		t.Fatalf("addUser alice: %v", err)
	}
	if err := st.addUser("bob", "secret123", "staff"); err != nil {
		t.Fatalf("addUser bob: %v", err)
	}
	if ok, err := st.setQuota("alice", 10, 60); err != nil || !ok {
		t.Fatalf("setQuota alice = %v/%v", ok, err)
	}
	if ok, err := st.setQuota("bob", 10, 60); err != nil || !ok {
		t.Fatalf("setQuota bob = %v/%v", ok, err)
	}
	if _, err := st.setEnabled("bob", false); err != nil {
		t.Fatalf("disable bob: %v", err)
	}

	// Expire the period by moving its start two intervals back and sweeping.
	now := time.Now().Unix()
	if _, err := st.db.Exec("UPDATE radius_users SET period_start = ? WHERE name IN ('alice','bob')", now-120); err != nil {
		t.Fatalf("backdate period: %v", err)
	}
	n, err := st.resetDueQuotas(now)
	if err != nil {
		t.Fatalf("resetDueQuotas: %v", err)
	}
	if n != 2 {
		t.Fatalf("reset %d users, want 2", n)
	}

	u, found, err := st.getUser("alice")
	if err != nil || !found {
		t.Fatalf("getUser alice = %+v/%v/%v", u, found, err)
	}
	if !u.Enabled || u.QuotaDisabled || u.PeriodStart != now-120+120 {
		t.Fatalf("alice after reset = %+v", u)
	}
	if u.PeriodStart <= now-120 {
		t.Fatalf("period start did not advance: %d", u.PeriodStart)
	}

	// Bob was disabled manually, so the periodic reset must not enable him.
	b, found, err := st.getUser("bob")
	if err != nil || !found {
		t.Fatalf("getUser bob = %+v/%v/%v", b, found, err)
	}
	if b.Enabled || b.QuotaDisabled {
		t.Fatalf("manual disable changed: %+v", b)
	}
}
