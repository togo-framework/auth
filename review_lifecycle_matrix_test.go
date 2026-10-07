package auth

import (
	"context"
	"os"
	"strconv"
	"sort"
	"strings"
	"testing"
)

// TestLifecycleSequenceMatrix runs every sequence of admin lifecycle
// operations up to a fixed depth against one target account and compares each
// answer, and the end state, with an oracle written from the threat model
// (sections 7 and 9.3), not derived from the code under test:
//
//   - an account that is an administrator is never reset, set, linked or
//     emailed by another administrator while AUTH_ADMIN_CROSS_CONTROL is off;
//   - a redemption of an administrator-issued link burns the token, and is
//     refused (401) if the account is an administrator by then;
//   - a field written by an administrator other than the holder is foreign
//     provenance, sticky for good; promoting the account by anyone other than
//     that writer answers 409 unless the same request carries the accept field.
//
// Actors: A is the first administrator and B the second. The holder is the
// target itself and writes nothing here.

type mxOp struct {
	name string
	run  func(t *testing.T, w *reviewWorld, m *mxModel) (code int)
	// oracle returns the expected status and applies the expected effect.
	want func(m *mxModel) int
}

type mxModel struct {
	admin   bool
	emailBy string // writer SET, accumulating: "", "A", "B" or "AB"
	pwBy    string
	link    string // issuer of the outstanding admin-issued reset token, "" when none
	pw      string // password the account should currently accept
	n       int
	token   string // the outstanding token
}

func (m *mxModel) tainted(promoter string) bool {
	return strings.Trim(m.emailBy, promoter) != "" || strings.Trim(m.pwBy, promoter) != ""
}

func mxOps() []mxOp {
	setEmail := func(who string) mxOp {
		return mxOp{
			name: "email" + who,
			run: func(t *testing.T, w *reviewWorld, m *mxModel) int {
				m.n++
				return api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, mxTok(w, who), `{"email":"mx`+strconv.Itoa(m.n)+`@example.com"}`)
			},
			want: func(m *mxModel) int {
				if m.admin {
					return 403
				}
				m.emailBy = addMx(m.emailBy, who)
				return 200
			},
		}
	}
	setPW := func(who string) mxOp {
		return mxOp{
			name: "setpw" + who,
			run: func(t *testing.T, w *reviewWorld, m *mxModel) int {
				m.n++
				return api(t, w, "POST", "/api/auth/admin/users/"+w.userID+"/reset-password", mxTok(w, who), `{"password":"mx-pass-`+strconv.Itoa(m.n)+`-xx"}`)
			},
			want: func(m *mxModel) int {
				if m.admin {
					return 403
				}
				m.pwBy = addMx(m.pwBy, who)
				m.pw = "mx-pass-" + strconv.Itoa(m.n) + "-xx"
				return 200
			},
		}
	}
	promote := func(who string, accept bool) mxOp {
		name := "promote" + who
		extra := ""
		if accept {
			name += "+accept"
			extra = `,"` + acceptField + `":true`
		}
		return mxOp{
			name: name,
			run: func(t *testing.T, w *reviewWorld, m *mxModel) int {
				c, _ := w.promote(t, mxTok(w, who), w.userID, extra)
				return c
			},
			want: func(m *mxModel) int {
				if m.admin {
					return 403 // a roles edit of another administrator is denied by default
				}
				if m.tainted(who) && !accept {
					return 409
				}
				m.admin = true
				return 200
			},
		}
	}
	return []mxOp{
		setEmail("A"), setEmail("B"), setPW("A"), setPW("B"),
		{
			name: "issueA",
			run: func(t *testing.T, w *reviewWorld, m *mxModel) int {
				c, tok := adminLink(t, w, "reset-password", w.userID)
				if c == 200 {
					m.token = tok
				}
				return c
			},
			want: func(m *mxModel) int {
				if m.admin {
					return 403
				}
				m.link = "A"
				return 200
			},
		},
		{
			name: "redeem",
			run: func(t *testing.T, w *reviewWorld, m *mxModel) int {
				m.n++
				return redeemReset(t, w, m.token, "mx-redeem-"+strconv.Itoa(m.n)+"-xx")
			},
			want: func(m *mxModel) int {
				if m.token == "" {
					return 400 // no token in the request
				}
				if m.link == "" {
					return 401 // no outstanding token (never issued, or already burned)
				}
				issuer := m.link
				m.link = "" // burned either way
				if m.admin {
					return 401 // refused
				}
				m.pwBy = addMx(m.pwBy, issuer)
				m.pw = "mx-redeem-" + strconv.Itoa(m.n) + "-xx"
				return 200
			},
		},
		promote("A", false), promote("B", false), promote("B", true),
		{
			name: "demoteA",
			run: func(t *testing.T, w *reviewWorld, m *mxModel) int {
				return api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, w.adminTok, `{"roles":[]}`)
			},
			want: func(m *mxModel) int {
				// demoting another administrator is denied by default (cross control off)
				if m.admin {
					return 403
				}
				return 200
			},
		},
	}
}

func mxTok(w *reviewWorld, who string) string {
	if who == "A" {
		return w.adminTok
	}
	return w.userExtra
}

func TestLifecycleSequenceMatrix(t *testing.T) {
	// Exhaustive to depth 2 (every bcrypt-bearing step costs about 70ms, so
	// depth 3 is 1331 more sequences and minutes); AUTH_MATRIX_DEPTH=3 runs the
	// exhaustive depth-3 sweep, and a curated list of the longer sequences that
	// carry the threat model's races always runs.
	depth := 2
	if d, err := strconv.Atoi(os.Getenv("AUTH_MATRIX_DEPTH")); err == nil && d > 0 {
		depth = d
	}
	w := newReviewWorld(t)
	_, w.userExtra = w.secondAdmin(t)
	ops := mxOps()
	ctx := context.Background()

	var seq []int
	var walk func(d int)
	runSeq := func(seq []int) {
		// fresh target for every sequence
		db, _ := w.svc.k.SQL(ctx)
		if _, err := db.Exec("DELETE FROM users WHERE id = "+w.svc.ph(1), w.userID); err != nil {
			t.Fatal(err)
		}
		_, _ = db.Exec("DELETE FROM auth_account_state WHERE user_id = "+w.svc.ph(1), w.userID)
		u, err := w.svc.CreateUser(ctx, "bob@example.com", pw, nil)
		if err != nil {
			t.Fatal(err)
		}
		w.userID = u.ID
		m := &mxModel{pw: pw}
		var names []string
		for _, i := range seq {
			names = append(names, ops[i].name)
			got := ops[i].run(t, w, m)
			want := ops[i].want(m)
			if got != want {
				t.Fatalf("sequence %s: step %s => %d, oracle says %d", strings.Join(names, ","), ops[i].name, got, want)
			}
		}
		if got := isAdminNow(t, w, w.userID); got != m.admin {
			t.Fatalf("sequence %s: admin=%v, oracle %v", strings.Join(names, ","), got, m.admin)
		}
		p := w.provenanceOf(t, w.userID)
		for field, got := range map[string]string{"email": p.EmailBy, "password": p.PasswordBy} {
			want := m.emailBy
			if field == "password" {
				want = m.pwBy
			}
			var ids []string
			for _, c := range want {
				ids = append(ids, map[rune]string{'A': w.adminID, 'B': w.admin2ID}[c])
			}
			sort.Strings(ids)
			wantID := strings.Join(ids, ",")
			if got != wantID {
				t.Fatalf("sequence %s: %s provenance %q, oracle %q", strings.Join(names, ","), field, got, wantID)
			}
		}
		// The password only ever changed through a step the oracle allowed.
		cur, _ := w.svc.userByID(ctx, w.userID)
		if loginCode(t, w, cur.Email, m.pw) != 200 {
			t.Fatalf("sequence %s: account does not accept the oracle's password", strings.Join(names, ","))
		}
	}
	walk = func(d int) {
		if d == 0 {
			runSeq(seq)
			return
		}
		for i := range ops {
			seq = append(seq, i)
			walk(d - 1)
			seq = seq[:len(seq)-1]
		}
	}
	// every sequence of exactly 1..depth operations
	for d := 1; d <= depth; d++ {
		walk(d)
	}
	index := map[string]int{}
	for i, o := range ops {
		index[o.name] = i
	}
	for _, names := range [][]string{
		{"issueA", "promoteA", "redeem"},
		{"issueA", "promoteB", "promoteB+accept", "redeem"},
		{"issueA", "redeem", "promoteB", "promoteA"},
		{"setpwB", "promoteA", "promoteA+accept"},
		{"setpwB", "promoteB", "promoteA+accept", "setpwA"},
		{"emailA", "promoteA", "demoteA"},
		{"emailA", "setpwB", "promoteB+accept", "issueA", "redeem"},
		{"issueA", "setpwA", "redeem", "promoteB", "promoteB+accept"},
	} {
		var q []int
		for _, n := range names {
			q = append(q, index[n])
		}
		runSeq(q)
	}
}

// addMx adds a writer to the oracle's accumulating writer set (sorted letters).
func addMx(set, who string) string {
	if who == "" || strings.Contains(set, who) {
		return set
	}
	b := []byte(set + who)
	sort.Slice(b, func(i, j int) bool { return b[i] < b[j] })
	return string(b)
}
