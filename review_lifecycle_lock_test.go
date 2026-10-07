package auth

import (
	"context"
	"database/sql"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Deterministic race tests (auth#6 section 15). A competing writer is held
// open inside a transaction the test controls; the operation under test is
// started and, once it is observed waiting on that writer, the writer commits.
// On PostgreSQL the wait is a row lock (pg_stat_activity wait_event_type
// 'Lock'); on SQLite it is the single pooled connection (db.Stats().WaitCount).

type heldWriter struct {
	tx      *sql.Tx
	waiting func(t *testing.T) // blocks until the operation under test is observed waiting
}

// holdWriter opens the competing transaction. Statements the test runs on
// h.tx are uncommitted until commit is called.
func holdWriter(t *testing.T, w *reviewWorld) *heldWriter {
	t.Helper()
	ctx := context.Background()
	if usingPG() {
		db, err := sql.Open("pgx", os.Getenv("AUTH_REVIEW_PG_URL"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback() })
		return &heldWriter{tx: tx, waiting: func(t *testing.T) {
			t.Helper()
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				var n int
				if err := db.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()`).Scan(&n); err == nil && n > 0 {
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatal("operation never blocked on the row lock")
		}}
	}
	db, _ := w.svc.k.SQL(ctx)
	before := db.Stats().WaitCount
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	return &heldWriter{tx: tx, waiting: func(t *testing.T) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if db.Stats().WaitCount > before {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("operation never waited for the connection")
	}}
}

// background runs fn and returns a function that waits for its result.
func background(fn func() int) func() int {
	ch := make(chan int, 1)
	go func() { ch <- fn() }()
	return func() int { return <-ch }
}

// A reset redemption in flight while a promotion holds the row: the redemption
// must not set the password of the account that became an administrator.
func TestLifecycleResetRedeemVsPromoteLocked(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	_, rt := adminLink(t, w, "reset-password", w.userID)
	h := holdWriter(t, w)
	if _, err := h.tx.ExecContext(ctx, "UPDATE users SET roles = 'admin' WHERE id = "+w.svc.ph(1), w.userID); err != nil {
		t.Fatal(err)
	}
	res := background(func() int { return redeemReset(t, w, rt, "hijacked-pass-1") })
	h.waiting(t)
	if err := h.tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if c := res(); c != 401 {
		t.Fatalf("redeem racing a committed promotion => %d, want 401", c)
	}
	if !isAdminNow(t, w, w.userID) {
		t.Fatal("setup: promotion did not commit")
	}
	if loginCode(t, w, "bob@example.com", "hijacked-pass-1") == 200 {
		t.Error("SECURITY: password set on the promoted account")
	}
	if len(w.eventsNamed(EventCredentialRefused)) != 1 {
		t.Errorf("credential_refused events = %v", w.eventsNamed(EventCredentialRefused))
	}
}

// Admin set-password in flight while a promotion holds the row.
func TestLifecycleSetModeVsPromoteLocked(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	h := holdWriter(t, w)
	if _, err := h.tx.ExecContext(ctx, "UPDATE users SET roles = 'admin' WHERE id = "+w.svc.ph(1), w.userID); err != nil {
		t.Fatal(err)
	}
	res := background(func() int {
		return api(t, w, "POST", "/api/auth/admin/users/"+w.userID+"/reset-password", w.adminTok, `{"password":"hijacked-pass-1"}`)
	})
	h.waiting(t)
	if err := h.tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if c := res(); c == 200 {
		t.Fatal("set-password succeeded on an account that became an administrator")
	}
	if loginCode(t, w, "bob@example.com", "hijacked-pass-1") == 200 {
		t.Error("SECURITY: password set on the promoted account")
	}
}

// The reverse order: a redemption holds the row (password and provenance not
// yet committed) when a promotion starts. The promotion waits, then reads the
// committed provenance and answers 409.
func TestLifecyclePromoteVsRedeemLockFirst(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	_, tok2 := w.secondAdmin(t)
	h := holdWriter(t, w)
	if _, err := h.tx.ExecContext(ctx, "UPDATE users SET roles = roles WHERE id = "+w.svc.ph(1), w.userID); err != nil {
		t.Fatal(err)
	}
	res := background(func() int {
		c, _ := w.promote(t, tok2, w.userID, "")
		return c
	})
	h.waiting(t)
	if _, err := h.tx.ExecContext(ctx, "INSERT INTO auth_account_state (user_id, password_set_by, password_set_at) VALUES ("+w.svc.ph(1)+", "+w.svc.ph(2)+", 'now')", w.userID, w.adminID); err != nil {
		t.Fatal(err)
	}
	if err := h.tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if c := res(); c != 409 {
		t.Fatalf("promotion that waited for a provenance write => %d, want 409", c)
	}
	if isAdminNow(t, w, w.userID) {
		t.Error("promoted despite committed foreign provenance")
	}
}

// Two instances on one database: the only guard is the database, not a mutex.
func TestLifecycleTwoInstancesRedeem(t *testing.T) {
	if !usingPG() {
		t.Skip("two app instances need a shared PostgreSQL database")
	}
	w := newReviewWorld(t)
	srv2, _ := bootSecond(t)
	_, rt := adminLink(t, w, "reset-password", w.userID)
	var wg sync.WaitGroup
	codes := make([]int, 8)
	for i := range codes {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			srv := w.srv
			if i%2 == 1 {
				srv = srv2
			}
			codes[i], _ = rawFrom(t, srv, "10.77.0."+strconv.Itoa(i+1), "POST", "/api/auth/password/reset", "", `{"token":"`+rt+`","password":"two-instance-pass-1"}`)
		}()
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == 200 {
			ok++
		}
	}
	if ok != 1 {
		t.Errorf("redemptions across two instances = %v, want exactly one 200", codes)
	}
}

// SQLite has one connection: any pool use inside an open transaction would
// deadlock. Every transactional admin path must finish.
func TestLifecycleSQLiteNoPoolInTx(t *testing.T) {
	if usingPG() {
		t.Skip("SQLite single-connection property")
	}
	w := newReviewWorld(t)
	_, tok2 := w.secondAdmin(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, rt := adminLink(t, w, "reset-password", w.userID)
		redeemReset(t, w, rt, "link-password-12")
		api(t, w, "POST", "/api/auth/admin/users/"+w.userID+"/reset-password", w.adminTok, `{"password":"set-by-admin-123"}`)
		_, rt2 := adminLink(t, w, "reset-password", w.userID)
		_ = w.svc.SetRoles(context.Background(), w.userID, []string{"admin"})
		redeemReset(t, w, rt2, "refused-pass-123") // refusal path
		_ = w.svc.SetRoles(context.Background(), w.userID, nil)
		w.promote(t, tok2, w.userID, "")
		w.promote(t, tok2, w.userID, `,"`+acceptField+`":true`)
		api(t, w, "DELETE", "/api/auth/admin/users/"+w.userID, w.adminTok, "")
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("an admin path used the pool inside an open transaction (deadlock)")
	}
}
