package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// Personal access tokens (Sanctum/Cloudflare-style): long-lived API tokens whose
// abilities (scopes) are set at creation. A request bearing a PAT authenticates
// with exactly those abilities, so RequirePermission gates apply per-token.
//
// Token format: "togo_pat_<40 hex>" — only the sha256 hash is stored.

const patPrefix = "togo_pat_"

// authenticate resolves the request identity from a bearer PAT (scoped) or,
// failing that, the JWT/cookie session.
func (s *Service) authenticate(r *http.Request) (*Identity, error) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		raw := strings.TrimSpace(h[7:])
		if strings.HasPrefix(raw, patPrefix) {
			return s.patIdentity(r.Context(), raw)
		}
	}
	return s.Verify(s.resolveToken(r))
}

func (s *Service) ensurePATSchema(ctx context.Context) error {
	db, err := s.k.SQL(ctx)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS personal_access_tokens (
		id text PRIMARY KEY,
		user_id text NOT NULL,
		name text NOT NULL,
		token_hash text NOT NULL UNIQUE,
		abilities text NOT NULL DEFAULT '',
		expires_at text,
		created_at text NOT NULL
	)`)
	return err
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// patIdentity resolves a PAT to an identity scoped to its abilities.
func (s *Service) patIdentity(ctx context.Context, token string) (*Identity, error) {
	db, err := s.k.SQL(ctx)
	if err != nil {
		return nil, err
	}
	var userID, abilities, exp string
	//#nosec G202 -- dialect placeholder only; value parameterized
	row := db.QueryRowContext(ctx, "SELECT user_id, abilities, COALESCE(expires_at,'') FROM personal_access_tokens WHERE token_hash = "+s.ph(1), sha256hex(token))
	if row.Scan(&userID, &abilities, &exp) != nil {
		return nil, ErrInvalidCredentials
	}
	if exp != "" {
		if t, err := time.Parse(time.RFC3339, exp); err != nil || time.Now().After(t) {
			return nil, ErrInvalidCredentials
		}
	}
	return &Identity{ID: userID, Permissions: splitCSV(abilities), Guard: "pat"}, nil
}

func (s *Service) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name      string   `json:"name"`
		Abilities []string `json:"abilities"`
		ExpiresIn int      `json:"expires_in_hours"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}
	id, _ := IdentityFrom(r.Context())
	plain := patPrefix + genID() + genID()[:8]
	ctx := r.Context()
	db, err := s.k.SQL(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unavailable"})
		return
	}
	var exp any
	if body.ExpiresIn > 0 {
		exp = time.Now().Add(time.Duration(body.ExpiresIn) * time.Hour).UTC().Format(time.RFC3339)
	}
	p := s.ph
	q := "INSERT INTO personal_access_tokens (id, user_id, name, token_hash, abilities, expires_at, created_at) VALUES (" + //#nosec G202 -- dialect placeholders only; values parameterized
		p(1) + ", " + p(2) + ", " + p(3) + ", " + p(4) + ", " + p(5) + ", " + p(6) + ", " + p(7) + ")"
	if _, err := db.ExecContext(ctx, q, genID(), id.ID, body.Name, sha256hex(plain),
		strings.Join(body.Abilities, ","), exp, time.Now().UTC().Format(time.RFC3339)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create failed"})
		return
	}
	// Plaintext token returned ONCE.
	writeJSON(w, http.StatusCreated, map[string]any{"token": plain, "name": body.Name, "abilities": body.Abilities})
}

func (s *Service) handleListTokens(w http.ResponseWriter, r *http.Request) {
	id, _ := IdentityFrom(r.Context())
	ctx := r.Context()
	db, err := s.k.SQL(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unavailable"})
		return
	}
	//#nosec G202 -- dialect placeholder only; value parameterized
	rows, err := db.QueryContext(ctx, "SELECT id, name, abilities, created_at, COALESCE(expires_at,'') FROM personal_access_tokens WHERE user_id = "+s.ph(1), id.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "list failed"})
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var tid, name, abil, created, exp string
		if rows.Scan(&tid, &name, &abil, &created, &exp) == nil {
			out = append(out, map[string]any{"id": tid, "name": name, "abilities": splitCSV(abil), "created_at": created, "expires_at": exp})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Service) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	id, _ := IdentityFrom(r.Context())
	tid := chi.URLParam(r, "id")
	ctx := r.Context()
	db, err := s.k.SQL(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unavailable"})
		return
	}
	//#nosec G202 -- dialect placeholders only; values parameterized
	_, err = db.ExecContext(ctx, "DELETE FROM personal_access_tokens WHERE id = "+s.ph(1)+" AND user_id = "+s.ph(2), tid, id.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "revoke failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}
